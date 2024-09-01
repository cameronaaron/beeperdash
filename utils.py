import httpx
from fastapi import Request, Response
from typing import Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)

async def make_authenticated_request(url: str, token: str) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, timeout=10.0)
        response.raise_for_status()
        return response.json()

def save_tokens_to_cookies(response: Response, access_token: str, jwt_token: str):
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="jwt_token", value=jwt_token, httponly=True)

def retrieve_tokens_from_cookies(request: Request) -> Tuple[str, str]:
    access_token = request.cookies.get("access_token")
    jwt_token = request.cookies.get("jwt_token")
    return access_token, jwt_token

def is_authenticated(access_token: str, jwt_token: str) -> bool:
    return bool(access_token and jwt_token)

async def handle_http_error(exc: httpx.HTTPStatusError, url: str):
    logger.error(f"Error response {exc.response.status_code} while requesting {url}.")
    return {"error": f"Failed to fetch data from {url}"}