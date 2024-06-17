from fastapi import FastAPI, Request, Form, HTTPException, Cookie, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
import asyncio
from pydantic import BaseModel, EmailStr
import os
import logging
import orjson

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

@app.on_event("shutdown")
async def shutdown_event():
    await app.state.httpx_client.aclose()

async def get_latest_github_commit_hash(bridge_name: str) -> str:
    repo = GITHUB_REPOS.get(bridge_name, "")
    if not repo:
        return "Unknown"
    
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    branches = ["main", "master"]

    for branch in branches:
        github_url = f"https://api.github.com/repos/{repo}/commits/{branch}"
        response = await app.state.httpx_client.get(github_url, headers=headers)
        if response.status_code == 200:
            return response.json().get("sha", "Unknown")
        elif response.status_code == 422:
            logger.error(f"Invalid repository URL for bridge {bridge_name}: {github_url}")
        else:
            logger.error(f"Failed to fetch latest commit for {bridge_name} from {branch} branch: {response.status_code}")

    return "Unknown"

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
    login_challenge_response = await client.post(
        "https://api.beeper.com/user/login/response",
        headers={
            "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
            "Content-Type": "application/json"},
        json={"request": login_request, "response": code},
    )
    token = login_challenge_response.json().get("token")
    access_token_response = await client.post(
        "https://matrix.beeper.com/_matrix/client/v3/login",
        headers={"Content-Type": "application/json"},
        json={"type": "org.matrix.login.jwt", "token": token},
    )
    access_token = access_token_response.json().get("access_token")
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="Lax")
    response.set_cookie(key="jwt_token", value=token, httponly=True, secure=True, samesite="Lax")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, access_token: str = Cookie(None), jwt_token: str = Cookie(None)):
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
        "GITHUB_REPOS": GITHUB_REPOS  # Pass GITHUB_REPOS to the template
    })

async def update_bridge_info(bridge_name, bridge_info):
    if 'version' in bridge_info and bridge_info['version']:
        current_version = bridge_info['version'].split(':')[-1].split('-')[0]
        latest_version = await get_latest_github_commit_hash(bridge_name)
        bridge_info['is_up_to_date'] = (current_version == latest_version)
        logger.info(f"Bridge: {bridge_name}, Current version: {current_version}, Latest version: {latest_version}, Up-to-date: {bridge_info['is_up_to_date']}")
    else:
        bridge_info['is_up_to_date'] = None

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

@app.post("/notify_update", response_class=HTMLResponse)
async def notify_update(request: Request, environment: str = Form(...), channel: str = Form(...), bridge: str = Form(...), image: str = Form(...), password: str = Form(...), deploy_next: bool = Form(...)):
    try:
        url = os.getenv(f"BEEPER_{environment}_ADMIN_API_URL")
        if not url:
            raise ValueError(f"Environment variable for {environment} admin API URL not set")
        
        headers = {"Content-Type": "application/json"}
        data = {
            "channel": channel,
            "bridge": bridge,
            "image": image,
            "password": password,
            "deployNext": deploy_next
        }
        
        client = app.state.httpx_client
        response = await client.post(url, headers=headers, json=data)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Failed to notify update: {response.text}")
        
        return HTMLResponse(content="Update notification sent successfully")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
