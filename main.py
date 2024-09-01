from fastapi import FastAPI, Request, Form, HTTPException, Cookie, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import Response
import httpx
import asyncio
from pydantic import BaseModel, EmailStr
import os
import logging
import orjson
from typing import List, Dict, Any
from fastapi.staticfiles import StaticFiles

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class LoginRequest(BaseModel):
    email: EmailStr

class TokenRequest(BaseModel):
    code: str
    request: str

class ResetPasswordRequest(BaseModel):
    access_token: str
    jwt_token: str
    new_password: str

class CreateBridgeRequest(BaseModel):
    beeper_token: str
    bridge: str
    region: str
    bridgeType: str = None
    isSelfHosted: bool = None
    reason: str = None
    source: str = None
    stateEvent: str = None
    username: str = None

class DeleteBridgeRequest(BaseModel):
    beeper_token: str
    name: str

class UserProfile(BaseModel):
    full_name: str
    email: EmailStr
    analyticsId: str = None
    bridgeClusterId: str = None
    channel: str = None
    createdAt: str = None
    customerLead: Dict[str, Any] = None
    dataLocation: str = None
    deactivatedAt: str = None
    deletedAt: str = None
    hungryUrl: str = None
    hungryUrlDirect: str = None
    isAdmin: bool = None
    isFree: bool = None
    isUserBridgeChangesLocked: bool = None
    referralCode: str = None
    supportRoomId: str = None
    token: str = None
    username: str = None

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

@app.on_event("startup")
async def startup_event():
    app.state.httpx_client = httpx.AsyncClient()
    app.state.notification_clients = []

def save_tokens_to_cookies(response: Response, access_token: str, jwt_token: str):
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="jwt_token", value=jwt_token, httponly=True)
@app.on_event("shutdown")
async def shutdown_event():
    await app.state.httpx_client.aclose()
# Mount the static directory
#app.mount("/static", StaticFiles(directory="static"), name="static")
async def get_github_commit_data(repo: str, branch: str) -> Dict[str, str]:
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    github_url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    try:
        response = await app.state.httpx_client.get(github_url, headers=headers)
        response.raise_for_status()
        commit_data = response.json()
        return {
            "sha": commit_data.get("sha", "Unknown"),
            "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown"),
            "message": commit_data.get("commit", {}).get("message", "No commit message")
        }
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error fetching commit data from {github_url}: {exc.response.status_code}")
        return {"sha": "Unknown", "date": "Unknown", "message": "Error fetching commit data"}

async def get_latest_github_commit_hash(bridge_name: str) -> Dict[str, str]:
    repo = GITHUB_REPOS.get(bridge_name, "")
    if not repo:
        return {"sha": "Unknown", "date": "Unknown", "message": "Unknown"}
    
    branches = ["main", "master"]
    for branch in branches:
        commit_data = await get_github_commit_data(repo, branch)
        if commit_data["sha"] != "Unknown":
            return commit_data

    return {"sha": "Unknown", "date": "Unknown", "message": "Unknown"}

async def get_commit_data_by_hash(repo: str, commit_hash: str) -> Dict[str, str]:
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    github_url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
    try:
        response = await app.state.httpx_client.get(github_url, headers=headers)
        response.raise_for_status()
        commit_data = response.json()
        return {
            "sha": commit_data.get("sha", "Unknown"),
            "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown"),
            "message": commit_data.get("commit", {}).get("message", "No commit message")
        }
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error fetching commit data from {github_url}: {exc.response.status_code}")
        return {"sha": "Unknown", "date": "Unknown", "message": "Error fetching commit data"}

async def update_bridge_info(bridge_name, bridge_info):
    if bridge_name not in GITHUB_REPOS:
        logger.error(f"Bridge name {bridge_name} not found in GITHUB_REPOS")
        bridge_info['is_up_to_date'] = None
        bridge_info['latest_commit_date'] = "Unknown"
        bridge_info['latest_version'] = "Unknown"
        bridge_info['latest_commit_message'] = "Unknown"
        bridge_info['current_commit_date'] = "Unknown"
        bridge_info['current_commit_message'] = "Unknown"
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

        bridge_info['is_up_to_date'] = (current_version == latest_version)
        bridge_info['latest_commit_date'] = latest_date
        bridge_info['latest_version'] = latest_version
        bridge_info['latest_commit_message'] = latest_message
        bridge_info['current_commit_date'] = current_date  # Add current commit date
        bridge_info['current_commit_message'] = current_message

        logger.info(f"Bridge: {bridge_name}, Current version: {current_version}, Latest version: {latest_version}, Up-to-date: {bridge_info['is_up_to_date']}, Latest commit date: {latest_date}, Current commit date: {current_date}")
    else:
        bridge_info['is_up_to_date'] = None
        bridge_info['latest_commit_date'] = "Unknown"
        bridge_info['latest_version'] = "Unknown"
        bridge_info['latest_commit_message'] = "Unknown"
        bridge_info['current_commit_date'] = "Unknown"  # Add current commit date
        bridge_info['current_commit_message'] = "Unknown"

    # Process additional fields from the JSON payload
    if 'remoteState' in bridge_info:
        for remote_id, remote_info in bridge_info['remoteState'].items():
            if 'info' in remote_info:
                remote_info['battery_low'] = remote_info['info'].get('battery_low', None)
                remote_info['browser_active'] = remote_info['info'].get('browser_active', None)
                remote_info['google_account_pairing'] = remote_info['info'].get('google_account_pairing', None)
                remote_info['mobile_data'] = remote_info['info'].get('mobile_data', None)
                remote_info['settings'] = remote_info['info'].get('settings', None)
                remote_info['sims'] = remote_info['info'].get('sims', None)
        for remote_id, remote_info in bridge_info['remoteState'].items():
            if 'info' in remote_info:
                remote_info['battery_low'] = remote_info['info'].get('battery_low', None)
                remote_info['browser_active'] = remote_info['info'].get('browser_active', None)
                remote_info['google_account_pairing'] = remote_info['info'].get('google_account_pairing', None)
                remote_info['mobile_data'] = remote_info['info'].get('mobile_data', None)
                remote_info['settings'] = remote_info['info'].get('settings', None)
                remote_info['sims'] = remote_info['info'].get('sims', None)

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, email: EmailStr = Form(...)):
    client = app.state.httpx_client
    try:
        login_response = await client.post(
            "https://api.beeper.com/user/login",
            headers={"Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE"},
        )
        login_response.raise_for_status()
        request_data = login_response.json().get("request")
        await client.post(
            "https://api.beeper.com/user/login/email",
            headers={
                "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
                "Content-Type": "application/json"},
            json={"request": request_data, "email": email},
        )
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error during login: {exc.response.status_code}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Login failed"})
    
    return templates.TemplateResponse("code.html", {"request": request, "login_request": request_data})

@app.post("/token")
async def get_token(request: Request, code: str = Form(...), login_request: str = Form(...)):
    client = app.state.httpx_client
    try:
        login_challenge_response = await client.post(
            "https://api.beeper.com/user/login/response",
            headers={
                "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
                "Content-Type": "application/json"},
            json={"request": login_request, "response": code},
        )
        login_challenge_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Invalid token"})
    
    token = login_challenge_response.json().get("token")
    access_token_response = await client.post(
        "https://matrix.beeper.com/_matrix/client/v3/login",
        headers={"Content-Type": "application/json"},
        json={"type": "org.matrix.login.jwt", "token": token},
    )
    access_token = access_token_response.json().get("access_token")
    response = RedirectResponse(url="/dashboard", status_code=303)
    save_tokens_to_cookies(response, access_token, token)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, access_token: str = Cookie(None), jwt_token: str = Cookie(None)):
    if not access_token or not jwt_token:
        access_token, jwt_token = retrieve_tokens_from_cookies(access_token, jwt_token)
        if not access_token or not jwt_token:
            return RedirectResponse(url="/", status_code=302)

    client = app.state.httpx_client
    beeper_response = await client.get(
        "https://api.beeper.com/whoami",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if beeper_response.status_code != 200:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to fetch Beeper data"})
    beeper_data = beeper_response.json()
    bridges = beeper_data.get("user", {}).get("bridges", {})
    asmux_data = beeper_data.get("user", {}).get("asmuxData", {})
    user_info = beeper_data.get("userInfo", {})

    bridge_updates = await asyncio.gather(*[
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
        "GITHUB_REPOS": GITHUB_REPOS,  # Pass GITHUB_REPOS to the template
    })

@app.post("/reset_password", response_class=HTMLResponse)
async def reset_password(request: Request, access_token: str = Form(...), jwt_token: str = Form(...), new_password: str = Form(...)):
    client = app.state.httpx_client
    try:
        user_interactive_auth_response = await client.post(
            "https://matrix.beeper.com/_matrix/client/v3/account/password",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={}
        )
        user_interactive_auth_response.raise_for_status()
        session_data = user_interactive_auth_response.json()
        session = session_data["session"]
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
            }
        )
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error resetting password: {exc.response.status_code}")
        return HTMLResponse(content="Failed to reset password", status_code=500)
    
    return HTMLResponse(content="Password reset successfully")

@app.post("/delete_bridge", response_class=HTMLResponse)
async def delete_bridge(request: Request, beeper_token: str = Form(...), name: str = Form(...)):
    client = app.state.httpx_client
    try:
        res_delete_beeper = await client.delete(
            f"https://api.beeper.com/bridge/{name}",
            headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"},
            timeout=10.0  # Set a timeout of 10 seconds
        )
        res_delete_beeper.raise_for_status()
    except httpx.ReadTimeout:
        logger.error("Request to delete bridge timed out.")
        # Check if the bridge still exists
        try:
            res_check_bridge = await client.get(
                f"https://api.beeper.com/bridge/{name}",
                headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"},
                timeout=10.0  # Set a timeout of 10 seconds
            )
            if res_check_bridge.status_code == 404:
                return HTMLResponse(content=f"Bridge {name} deleted successfully (timeout occurred but bridge no longer exists).")
            else:
                return HTMLResponse(content="Request to delete bridge timed out. Please try again later.", status_code=500)
        except httpx.HTTPStatusError as exc:
            logger.error(f"Error checking bridge existence: {exc.response.status_code}")
            return HTMLResponse(content="Failed to verify bridge deletion status.", status_code=500)
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error deleting bridge: {exc.response.status_code}")
        return HTMLResponse(content="Failed to delete bridge on Beeper", status_code=500)
    
    return HTMLResponse(content=f"Bridge {name} deleted successfully")

@app.post("/start_or_update_bridge", response_class=HTMLResponse)
async def start_or_update_bridge(request: Request, beeper_token: str = Form(...), name: str = Form(...)):
    client = app.state.httpx_client
    try:
        res_start_update_beeper = await client.post(
            f"https://api.beeper.com/bridge/{name}/start",
            headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"},
            timeout=10.0  # Set a timeout of 10 seconds
        )
        res_start_update_beeper.raise_for_status()
    except httpx.ReadTimeout:
        logger.error("Request to start or update bridge timed out.")
        return HTMLResponse(content="Request to start or update bridge timed out. Please try again later.", status_code=500)
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error starting or updating bridge: {exc.response.status_code}")
        return HTMLResponse(content="Failed to start or update bridge on Beeper", status_code=500)
    
    return HTMLResponse(content=f"Bridge {name} started or updated successfully")

@app.get("/profile", response_class=HTMLResponse)
async def get_profile(request: Request, access_token: str = Cookie(None)):
    if not access_token:
        access_token, _ = retrieve_tokens_from_cookies(access_token, None)
        if not access_token:
            return RedirectResponse(url="/", status_code=302)

    client = app.state.httpx_client
    profile_response = await client.get(
        "https://api.beeper.com/user/profile",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if profile_response.status_code != 200:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to fetch profile data"})
    profile_data = profile_response.json()
    return templates.TemplateResponse("profile.html", {"request": request, "profile": profile_data})

@app.post("/profile", response_class=HTMLResponse)
async def update_profile(request: Request, access_token: str = Cookie(None), full_name: str = Form(...), email: EmailStr = Form(...)):
    if not access_token:
        access_token, _ = retrieve_tokens_from_cookies(access_token, None)
        if not access_token:
            return RedirectResponse(url="/", status_code=302)

    client = app.state.httpx_client
    try:
        update_response = await client.put(
            "https://api.beeper.com/user/profile",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={"full_name": full_name, "email": email},
        )
        if update_response.status_code != 200:
            return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to update profile data"})
        return RedirectResponse(url="/profile", status_code=303)
    except Exception as e:
        logger.error(f"An error occurred while updating profile data: {e}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "An unexpected error occurred"})
