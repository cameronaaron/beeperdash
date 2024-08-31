from fastapi import FastAPI, Request, Form, HTTPException, Cookie, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
import asyncio
from pydantic import BaseModel, EmailStr
import os
import logging
import orjson
from typing import List, Dict, Any

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

class NotifyUpdateRequest(BaseModel):
    environment: str
    channel: str
    bridge: str
    image: str
    password: str
    deploy_next: bool = False
    issue_type: str = None
    issue_description: str = None

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
}

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

@app.on_event("startup")
async def startup_event():
    app.state.httpx_client = httpx.AsyncClient()
    app.state.notification_clients = []

@app.on_event("shutdown")
async def shutdown_event():
    await app.state.httpx_client.aclose()

async def get_latest_github_commit_hash(bridge_name: str) -> Dict[str, str]:
    repo = GITHUB_REPOS.get(bridge_name, "")
    if not repo:
        return {"sha": "Unknown", "date": "Unknown"}
    
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    branches = ["main", "master"]

    for branch in branches:
        github_url = f"https://api.github.com/repos/{repo}/commits/{branch}"
        response = await app.state.httpx_client.get(github_url, headers=headers)
        if response.status_code == 200:
            commit_data = response.json()
            return {"sha": commit_data.get("sha", "Unknown"), "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown")}
        elif response.status_code == 422:
            logger.error(f"Invalid repository URL for bridge {bridge_name}: {github_url}")
        else:
            logger.error(f"Failed to fetch latest commit for {bridge_name} from {branch} branch: {response.status_code}")

    return {"sha": "Unknown", "date": "Unknown"}

def save_tokens_to_cookies(response: RedirectResponse, access_token: str, jwt_token: str):
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key="jwt_token", value=jwt_token, httponly=True, secure=True, samesite="strict")

def retrieve_tokens_from_cookies(access_token: str, jwt_token: str):
    return access_token, jwt_token

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, email: EmailStr = Form(...)):
    client = app.state.httpx_client
    login_response = await client.post(
        "https://api.beeper.com/user/login",
        headers={"Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE"},
    )
    request_data = login_response.json().get("request")
    await client.post(
        "https://api.beeper.com/user/login/email",
        headers={
            "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
            "Content-Type": "application/json"},
        json={"request": request_data, "email": email},
    )
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
        "ws_notifications_url": "ws://localhost:8000/ws/notifications"  # WebSocket URL for notifications
    })

async def update_bridge_info(bridge_name, bridge_info):
    if 'version' in bridge_info and bridge_info['version']:
        current_version = bridge_info['version'].split(':')[-1].split('-')[0]
        latest_commit = await get_latest_github_commit_hash(bridge_name)
        latest_version = latest_commit["sha"]
        latest_date = latest_commit["date"]
        bridge_info['is_up_to_date'] = (current_version == latest_version)
        bridge_info['latest_commit_date'] = latest_date
        logger.info(f"Bridge: {bridge_name}, Current version: {current_version}, Latest version: {latest_version}, Up-to-date: {bridge_info['is_up_to_date']}, Latest commit date: {latest_date}")
    else:
        bridge_info['is_up_to_date'] = None
        bridge_info['latest_commit_date'] = "Unknown"

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

@app.post("/reset_password", response_class=HTMLResponse)
async def reset_password(request: Request, access_token: str = Form(...), jwt_token: str = Form(...), new_password: str = Form(...)):
    client = app.state.httpx_client
    user_interactive_auth_response = await client.post(
        "https://matrix.beeper.com/_matrix/client/v3/account/password",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={}
    )
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
    return HTMLResponse(content="Password reset successfully")

@app.post("/delete_bridge", response_class=HTMLResponse)
async def delete_bridge(request: Request, beeper_token: str = Form(...), name: str = Form(...)):
    client = app.state.httpx_client
    res_delete_beeper = await client.delete(
        f"https://api.beeper.com/bridge/{name}",
        headers={"Authorization": f"Bearer {beeper_token}", "Content-Type": "application/json"}
    )
    if res_delete_beeper.status_code != 204:
        return HTMLResponse(content="Failed to delete bridge on Beeper", status_code=500)
    return HTMLResponse(content=f"Bridge {name} deleted successfully")

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
    update_response = await client.put(
        "https://api.beeper.com/user/profile",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"full_name": full_name, "email": email},
    )
    if update_response.status_code != 200:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to update profile data"})
    return RedirectResponse(url="/profile", status_code=303)

@app.websocket("/ws/bridge_status")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            bridge_status = await get_bridge_status(data)
            await websocket.send_json(bridge_status)
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    await websocket.accept()
    app.state.notification_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        app.state.notification_clients.remove(websocket)
        logger.info("WebSocket disconnected")

async def get_bridge_status(bridge_name: str) -> Dict[str, Any]:
    # Simulate fetching bridge status
    await asyncio.sleep(1)
    return {"bridge_name": bridge_name, "status": "active"}
