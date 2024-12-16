from fastapi import FastAPI, Request, Form, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
import httpx
import asyncio
from pydantic import BaseModel, EmailStr
import os
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# GitHub Repositories mapping
GITHUB_REPOS = {
    "discordgo": "mautrix/discord",
    "facebookgo": "mautrix/meta",
    "gmessages": "mautrix/gmessages",
    "googlechat": "mautrix/googlechat",
    "instagramgo": "mautrix/meta",
    "linkedin": "beeper/linkedin",
    "signal": "mautrix/signal",
    "slackgo": "mautrix/slack",
    "telegram": "mautrix/telegram",
    "twitter": "mautrix/twitter",
    "whatsapp": "mautrix/whatsapp",
    "hungryserv": "beeper/hungryserv",
    "asmux": "beeper/asmux",
    "gvoice": "mautrix/gvoice",
    "imessage": "mautrix/imessage",
    "imessagego": "beeper/imessagego",
    "heisenbridge": "hifi/heisenbridge",
}

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


class LoginRequest(BaseModel):
    email: EmailStr


class TokenRequest(BaseModel):
    code: str
    request: str


@app.on_event("startup")
async def startup_event():
    app.state.httpx_client = httpx.AsyncClient()
    app.state.notification_clients = []


@app.on_event("shutdown")
async def shutdown_event():
    await app.state.httpx_client.aclose()


def save_tokens_to_cookies(response: Response, access_token: str, jwt_token: str):
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="jwt_token", value=jwt_token, httponly=True)


def retrieve_tokens_from_cookies(request: Request):
    access_token = request.cookies.get("access_token")
    jwt_token = request.cookies.get("jwt_token")
    return access_token, jwt_token


def is_authenticated(access_token: str, jwt_token: str) -> bool:
    return bool(access_token and jwt_token)


async def make_authenticated_request(url: str) -> Dict[str, Any]:
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, timeout=10.0)
        response.raise_for_status()
        return response.json()


async def get_github_commit_data(repo: str, branch: str) -> Dict[str, str]:
    github_url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    try:
        commit_data = await make_authenticated_request(github_url)
        return {
            "sha": commit_data.get("sha", "Unknown"),
            "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown"),
            "message": commit_data.get("commit", {}).get("message", "No commit message")
        }
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error fetching commit data from {github_url}: {exc}")
        return {"sha": "Unknown", "date": "Unknown", "message": "Error fetching commit data"}


async def get_latest_github_commit_hash(bridge_name: str) -> Dict[str, str]:
    repo = GITHUB_REPOS.get(bridge_name, "")
    if not repo:
        return {"sha": "Unknown", "date": "Unknown", "message": "Unknown"}

    # Try main or master branch
    for branch in ["main", "master"]:
        commit_data = await get_github_commit_data(repo, branch)
        if commit_data["sha"] != "Unknown":
            return commit_data
    return {"sha": "Unknown", "date": "Unknown", "message": "Unknown"}


async def get_commit_data_by_hash(repo: str, commit_hash: str) -> Dict[str, str]:
    github_url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
    try:
        commit_data = await make_authenticated_request(github_url)
        return {
            "sha": commit_data.get("sha", "Unknown"),
            "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown"),
            "message": commit_data.get("commit", {}).get("message", "No commit message")
        }
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error fetching commit data from {github_url}: {exc}")
        return {"sha": "Unknown", "date": "Unknown", "message": "Error fetching commit data"}


async def update_bridge_info(bridge_name: str, bridge_info: Dict[str, Any]):
    if bridge_name not in GITHUB_REPOS:
        logger.error(f"Bridge name {bridge_name} not found in GITHUB_REPOS")
        bridge_info.update({
            'is_up_to_date': None,
            'latest_commit_date': "Unknown",
            'latest_version': "Unknown",
            'latest_commit_message': "Unknown",
            'current_commit_date': "Unknown",
            'current_commit_message': "Unknown"
        })
        return

    if 'version' in bridge_info and bridge_info['version']:
        current_version = bridge_info['version'].split(':')[-1].split('-')[0]
        latest_commit = await get_latest_github_commit_hash(bridge_name)
        latest_version = latest_commit["sha"]
        latest_date = latest_commit["date"]
        latest_message = latest_commit["message"]

        current_commit = await get_commit_data_by_hash(GITHUB_REPOS[bridge_name], current_version)
        current_date = current_commit["date"]
        current_message = current_commit["message"]

        bridge_info.update({
            'is_up_to_date': (current_version == latest_version),
            'latest_commit_date': latest_date,
            'latest_version': latest_version,
            'latest_commit_message': latest_message,
            'current_commit_date': current_date,
            'current_commit_message': current_message
        })

        logger.info(f"Bridge: {bridge_name}, Current: {current_version}, Latest: {latest_version}, Up-to-date: {bridge_info['is_up_to_date']}")

    else:
        bridge_info.update({
            'is_up_to_date': None,
            'latest_commit_date': "Unknown",
            'latest_version': "Unknown",
            'latest_commit_message': "Unknown",
            'current_commit_date': "Unknown",
            'current_commit_message': "Unknown"
        })

    # Process additional fields from JSON payload if present
    if 'remoteState' in bridge_info:
        for remote_id, remote_info in bridge_info['remoteState'].items():
            if 'info' in remote_info:
                remote_info.update({
                    'battery_low': remote_info['info'].get('battery_low', None),
                    'browser_active': remote_info['info'].get('browser_active', None),
                    'google_account_pairing': remote_info['info'].get('google_account_pairing', None),
                    'mobile_data': remote_info['info'].get('mobile_data', None),
                    'settings': remote_info['info'].get('settings', None),
                    'sims': remote_info['info'].get('sims', None)
                })


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    access_token, jwt_token = retrieve_tokens_from_cookies(request)
    if is_authenticated(access_token, jwt_token):
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request, email: EmailStr = Form(...)):
    client = app.state.httpx_client
    try:
        # Initiate login request
        login_response = await client.post(
            "https://api.beeper.com/user/login",
            headers={"Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE"},
            timeout=10.0
        )
        login_response.raise_for_status()
        request_data = login_response.json().get("request")

        # Send email
        await client.post(
            "https://api.beeper.com/user/login/email",
            headers={
                "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
                "Content-Type": "application/json"
            },
            json={"request": request_data, "email": email},
            timeout=10.0
        )
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error during login: {exc.response.status_code}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Login failed"})
    except httpx.RequestError as exc:
        logger.error(f"Request error: {exc}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Login failed"})

    response = templates.TemplateResponse("code.html", {"request": request, "login_request": request_data})
    save_tokens_to_cookies(response, "", "")
    return response


@app.post("/token")
async def get_token(request: Request, code: str = Form(...), login_request: str = Form(...)):
    client = app.state.httpx_client
    try:
        login_challenge_response = await client.post(
            "https://api.beeper.com/user/login/response",
            headers={
                "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
                "Content-Type": "application/json"
            },
            json={"request": login_request, "response": code},
            timeout=10.0
        )
        login_challenge_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error: {exc.response.status_code}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Invalid token"})
    except httpx.RequestError as exc:
        logger.error(f"Request error: {exc}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Invalid token"})

    token = login_challenge_response.json().get("token")
    access_token_response = await client.post(
        "https://matrix.beeper.com/_matrix/client/v3/login",
        headers={"Content-Type": "application/json"},
        json={"type": "org.matrix.login.jwt", "token": token},
        timeout=10.0
    )
    access_token = access_token_response.json().get("access_token")

    response = RedirectResponse(url="/dashboard", status_code=303)
    save_tokens_to_cookies(response, access_token, token)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    access_token, jwt_token = retrieve_tokens_from_cookies(request)
    if not is_authenticated(access_token, jwt_token):
        return RedirectResponse(url="/", status_code=302)

    client = app.state.httpx_client
    try:
        beeper_response = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0
        )
        beeper_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error fetching Beeper data: {exc.response.status_code}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to fetch data"})
    except httpx.RequestError as exc:
        logger.error(f"Request error: {exc}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to fetch data"})

    beeper_data = beeper_response.json()
    bridges = beeper_data.get("user", {}).get("bridges", {})
    asmux_data = beeper_data.get("user", {}).get("asmuxData", {})
    user_info = beeper_data.get("userInfo", {})

    await asyncio.gather(*[
        update_bridge_info(bridge_name, bridge_info)
        for bridge_name, bridge_info in bridges.items()
    ])

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "bridges": bridges,
        "beeper_data": beeper_data,
        "token": access_token,
        "asmux_data": asmux_data,
        "user_info": user_info,
        "jwt_token": jwt_token,
        "GITHUB_REPOS": GITHUB_REPOS
    })


@app.post("/reset_password", response_class=HTMLResponse)
async def reset_password(request: Request, access_token: str = Form(...), jwt_token: str = Form(...), new_password: str = Form(...)):
    client = app.state.httpx_client
    try:
        # Initiate user interactive auth
        user_interactive_auth_response = await client.post(
            "https://matrix.beeper.com/_matrix/client/v3/account/password",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={},
            timeout=10.0
        )
        user_interactive_auth_response.raise_for_status()
        session_data = user_interactive_auth_response.json()
        session = session_data["session"]

        # Complete auth with JWT
        await client.post(
            "https://matrix.beeper.com/_matrix/client/v3/account/password",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={
                "auth": {
                    "type": "org.matrix.login.jwt",
                    "token": jwt_token,
                    "session": session,
                },
                "new_password": new_password,
                "logout_devices": False,
            },
            timeout=10.0
        )
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error resetting password: {exc.response.status_code}")
        return HTMLResponse(content="Failed to reset password", status_code=500)
    except httpx.RequestError as exc:
        logger.error(f"Request error: {exc}")
        return HTMLResponse(content="Failed to reset password", status_code=500)

    return HTMLResponse(content="Password reset successfully")


@app.post("/delete_bridge", response_class=HTMLResponse)
async def delete_bridge(request: Request, beeper_token: str = Form(...), name: str = Form(...)):
    client = app.state.httpx_client
    try:
        res_delete_beeper = await client.delete(
            f"https://api.beeper.com/bridge/{name}",
            headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"},
            timeout=10.0
        )
        res_delete_beeper.raise_for_status()
    except httpx.ReadTimeout:
        logger.error("Request to delete bridge timed out.")
        try:
            res_check_bridge = await client.get(
                f"https://api.beeper.com/bridge/{name}",
                headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"},
                timeout=10.0
            )
            if res_check_bridge.status_code == 404:
                return HTMLResponse(content=f"Bridge {name} deleted successfully.")
            else:
                return HTMLResponse(content="Delete timed out, please try again.", status_code=500)
        except:
            return HTMLResponse(content="Failed to verify deletion status.", status_code=500)
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error deleting bridge: {exc.response.status_code}")
        return HTMLResponse(content="Failed to delete bridge on Beeper", status_code=500)
    except httpx.RequestError as exc:
        logger.error(f"Request error: {exc}")
        return HTMLResponse(content="Failed to delete bridge on Beeper", status_code=500)

    return HTMLResponse(content=f"Bridge {name} deleted successfully")


@app.post("/start_or_update_bridge", response_class=HTMLResponse)
async def start_or_update_bridge(request: Request, beeper_token: str = Form(...), name: str = Form(...)):
    client = app.state.httpx_client
    try:
        res_start_update_beeper = await client.post(
            f"https://api.beeper.com/bridge/{name}/start",
            headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"},
            timeout=10.0
        )
        res_start_update_beeper.raise_for_status()
    except httpx.ReadTimeout:
        logger.error("Request to start or update bridge timed out.")
        return HTMLResponse(content="Operation timed out. Please try again.", status_code=500)
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error: {exc.response.status_code}")
        return HTMLResponse(content="Failed to start or update bridge on Beeper", status_code=500)

    return HTMLResponse(content=f"Bridge {name} started or updated successfully")


@app.post("/post_bridge_state", response_class=HTMLResponse)
async def post_bridge_state(
    request: Request, 
    beeper_token: str = Form(...), 
    username: str = Form(...), 
    bridge_name: str = Form(...), 
    state_event: str = Form(...), 
    reason: str = Form(...), 
    is_self_hosted: bool = Form(...), 
    bridge_type: str = Form(...)
):
    client = app.state.httpx_client
    url = f"https://api.beeper.com/bridgebox/{username}/bridge/{bridge_name}/bridge_state"
    headers = {"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"}
    payload = {
        "stateEvent": state_event,
        "reason": reason,
        "isSelfHosted": is_self_hosted,
        "bridgeType": bridge_type
    }

    try:
        response = await client.post(url, headers=headers, json=payload, timeout=10.0)
        response.raise_for_status()
    except httpx.ReadTimeout:
        logger.error("Request timed out.")
        return HTMLResponse(content="Request timed out. Try again later.", status_code=500)
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error posting bridge state: {exc.response.status_code}, {exc.response.text}")
        return HTMLResponse(content=f"Failed to post bridge state: {exc.response.text}", status_code=500)

    return HTMLResponse(content=f"Bridge state for {bridge_name} posted successfully")
