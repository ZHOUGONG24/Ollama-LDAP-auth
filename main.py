import os
import time
import httpx
import re
from typing import Dict
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from ldap3 import Server, Connection, SIMPLE, SAFE_SYNC
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")

LDAP_HOST = os.getenv("LDAP_HOST", "localhost")
LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=ldap,dc=goauthentik,dc=io")

CACHE_TTL = int(os.getenv("CACHE_TTL", "1800"))
token_cache: Dict[str, float] = {}

TOKEN_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$")

def clean_expired_cache():
    current_time = time.time()
    if len(token_cache) > 1000:
        keys_to_delete = [k for k, v in token_cache.items() if v < current_time]
        for k in keys_to_delete:
            del token_cache[k]

def verify_ldap_dynamic(username: str, password: str) -> bool:
    """
    LDAP 登录
    """
    try:
        user_dn = f"cn={username},ou=users,{LDAP_BASE_DN}"
        server = Server(LDAP_HOST, port=LDAP_PORT)
        conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, client_strategy=SAFE_SYNC)
        
        if conn.bind():
            conn.unbind()
            return True
        else:
            print(f"LDAP Bind Failed for user '{username}': {conn.result}")
            return False
    except Exception as e:
        print(f"LDAP Connection Error: {e}")
        return False

async def verify_token_split(request: Request):
    """
    验证
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API Key")
    raw_token = auth_header.split(" ")[1]
    
    if len(raw_token) > 256: 
         raise HTTPException(status_code=400, detail="API Key too long")

    if not TOKEN_PATTERN.match(raw_token):
        raise HTTPException(status_code=400, detail="Invalid API Key Format. Must be 'username:password' (alphanumeric only)")

    current_time = time.time()
    if raw_token in token_cache:
        expiry = token_cache[raw_token]
        if current_time < expiry:
            return True
        else:
            del token_cache[raw_token]

    username, password = raw_token.split(":", 1)

    if verify_ldap_dynamic(username, password):
        token_cache[raw_token] = current_time + CACHE_TTL
        clean_expired_cache()
        return True
    else:
        raise HTTPException(status_code=403, detail="Invalid Username or Password")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def proxy_ollama(path: str, request: Request, authorized: bool = Depends(verify_token_split)):
    client = httpx.AsyncClient(base_url=OLLAMA_URL, timeout=300.0)
    url = f"/{path}"
    body = await request.body()
    
    forward_headers = dict(request.headers)
    forward_headers.pop("host", None)
    forward_headers.pop("content-length", None)
    
    req = client.build_request(request.method, url, content=body, headers=forward_headers)

    try:
        r = await client.send(req, stream=True)
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Cannot connect to Ollama")

    async def stream_generator():
        try:
            async for chunk in r.aiter_bytes():
                yield chunk
        finally:
            await r.aclose()
            await client.aclose()

    return StreamingResponse(
        stream_generator(),
        status_code=r.status_code,
        media_type=r.headers.get("content-type", "application/json")
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)