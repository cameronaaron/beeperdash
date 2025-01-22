"""
Beeper Dashboard
Created by Cameron Aaron

DISCLAIMER:
This is an unofficial dashboard that interacts with Beeper's APIs.
Not affiliated with, endorsed by, or supported by Beeper or Automatic.
Use at your own risk.

Author: Cameron Aaron
"""

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
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Unofficial Beeper Dashboard",
    description="Created by Cameron Aaron. Not affiliated with Beeper/Automatic. Use at your own risk.",
    version="1.0",
    contact={
        "name": "Cameron Aaron",
        "url": "https://github.com/cameronaaron",  
    },
)
templates = Jinja2Templates(directory="templates")

# Create static directory if it doesn't exist
static_dir = Path("static")
static_dir.mkdir(exist_ok=True)
css_dir = static_dir / "css"
css_dir.mkdir(exist_ok=True)

# Update the static files mounting
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
else:
    logger.warning("Static directory does not exist, static files will not be served")

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

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')


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
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=5.0)  # reduced timeout
            response.raise_for_status()
            return response.json()
    except (httpx.ConnectTimeout, httpx.ReadTimeout):
        logger.error(f"Timeout while fetching data from {url}")
        raise httpx.RequestError(f"Timeout while fetching data from {url}")
    except Exception as e:
        logger.error(f"Error fetching data from {url}: {str(e)}")
        raise


async def get_github_commit_data(repo: str, branch: str) -> Dict[str, str]:
    github_url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    try:
        commit_data = await make_authenticated_request(github_url)
        return {
            "sha": commit_data.get("sha", "Unknown"),
            "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown"),
            "message": commit_data.get("commit", {}).get("message", "No commit message"),
            "branch": branch
        }
    except httpx.HTTPStatusError:
        # Don't log 422 errors as they're expected when a branch doesn't exist
        return {"sha": "Unknown", "date": "Unknown", "message": "Branch not found", "branch": branch}
    except Exception as exc:
        logger.error(f"Unexpected error fetching commit data from {github_url}: {exc}")
        return {"sha": "Unknown", "date": "Unknown", "message": "Error fetching commit data", "branch": branch}

async def get_latest_github_commit_hash(bridge_name: str) -> Dict[str, str]:
    repo = GITHUB_REPOS.get(bridge_name, "")
    if not repo:
        return {"sha": "Unknown", "date": "Unknown", "message": "Unknown", "branch": "Unknown"}

    # Try branches in order of preference
    for branch in ["main", "master", "dev", "develop"]:
        commit_data = await get_github_commit_data(repo, branch)
        if commit_data["sha"] != "Unknown":
            return commit_data

    # If no branches worked, try to get default branch
    try:
        repo_url = f"https://api.github.com/repos/{repo}"
        repo_data = await make_authenticated_request(repo_url)
        default_branch = repo_data.get("default_branch")
        if default_branch:
            commit_data = await get_github_commit_data(repo, default_branch)
            if commit_data["sha"] != "Unknown":
                return commit_data
    except:
        pass

    return {"sha": "Unknown", "date": "Unknown", "message": "No valid branch found", "branch": "Unknown"}

async def get_commit_data_by_hash(repo: str, commit_hash: str) -> Dict[str, str]:
    # Clean up commit hash - remove any docker prefix and get only the hash part
    if 'docker.beeper-tools.com' in commit_hash:
        parts = commit_hash.split(':')[-1].split('-')
        for part in parts:
            if len(part) > 8 and all(c.isalnum() for c in part):
                commit_hash = part
                break
    
    # Ensure we're only using the hash part
    commit_hash = ''.join(c for c in commit_hash if c.isalnum())
    
    # Trim to standard git hash length if needed
    if len(commit_hash) > 40:
        commit_hash = commit_hash[:40]
    
    # Try full hash first, then abbreviated
    for hash_version in [commit_hash, commit_hash[:8]]:
        try:
            github_url = f"https://api.github.com/repos/{repo}/commits/{hash_version}"
            commit_data = await make_authenticated_request(github_url)
            return {
                "sha": commit_data.get("sha", "Unknown"),
                "date": commit_data.get("commit", {}).get("committer", {}).get("date", "Unknown"),
                "message": commit_data.get("commit", {}).get("message", "No commit message")
            }
        except httpx.HTTPStatusError:
            continue
        except Exception as exc:
            logger.error(f"Error fetching commit {hash_version}: {exc}")
            continue

    return {"sha": commit_hash, "date": "Unknown", "message": "Could not fetch commit data"}

async def update_bridge_info(bridge_name: str, bridge_info: Dict[str, Any]):
    if bridge_name not in GITHUB_REPOS:
        bridge_info.update({
            'is_up_to_date': None,
            'latest_commit_date': "Unknown",
            'latest_version': "Unknown",
            'latest_commit_message': "Unknown",
            'current_commit_date': "Unknown",
            'current_commit_message': "Unknown"
        })
        return

    try:
        if 'version' not in bridge_info or not bridge_info['version']:
            raise ValueError("No version information available")

        version_string = bridge_info['version']
        current_version = None
        
        # Extract commit hash from version string
        if 'docker.beeper-tools.com' in version_string:
            parts = version_string.split(':')[-1].split('-')
            for part in parts:
                if len(part) > 8 and all(c.isalnum() for c in part):
                    current_version = part
                    break
            if not current_version and len(parts) > 1:
                current_version = parts[1]
        else:
            # Handle direct commit hash
            clean_version = ''.join(c for c in version_string if c.isalnum())
            if len(clean_version) >= 8:
                current_version = clean_version
            else:
                current_version = version_string

        if not current_version:
            raise ValueError(f"Could not parse version from: {version_string}")

        # Store the full version string for display
        bridge_info['full_version'] = version_string
        
        # Get latest commit first - now includes branch info
        latest_commit = await get_latest_github_commit_hash(bridge_name)
        
        # Get current commit info with cleaned hash
        current_commit = await get_commit_data_by_hash(GITHUB_REPOS[bridge_name], current_version)

        bridge_info.update({
            'is_up_to_date': (
                current_commit["sha"] != "Unknown" and 
                latest_commit["sha"] != "Unknown" and
                (current_commit["sha"].startswith(latest_commit["sha"]) or 
                latest_commit["sha"].startswith(current_commit["sha"]) or
                current_commit["sha"] == latest_commit["sha"])
            ),
            'latest_commit_date': latest_commit["date"],
            'latest_version': latest_commit["sha"],
            'latest_commit_message': latest_commit["message"],
            'latest_branch': latest_commit.get("branch", "Unknown"),
            'current_commit_date': current_commit["date"],
            'current_commit_message': current_commit["message"],
            'current_version': current_version[:12] if current_version else "Unknown",
            'repository': GITHUB_REPOS.get(bridge_name, "Unknown"),
            'github_url': f"https://github.com/{GITHUB_REPOS.get(bridge_name, '')}",
            'version_details': {
                'full_hash': current_version,
                'short_hash': current_version[:8] if current_version else "Unknown",
                'docker_tag': version_string if 'docker.beeper-tools.com' in version_string else None,
                'version_tag': parts[0] if 'docker.beeper-tools.com' in version_string and parts else None
            }
        })

        # Only add compare URL if we have valid versions and they're different
        if (current_commit["sha"] != "Unknown" and latest_commit["sha"] != "Unknown" and 
            current_commit["sha"] != latest_commit["sha"]):
            bridge_info['compare_url'] = (
                f"https://github.com/{GITHUB_REPOS.get(bridge_name, '')}/compare/"
                f"{current_version}...{latest_commit['sha']}"
            )

    except Exception as e:
        logger.error(f"Error updating bridge info for {bridge_name}: {str(e)}")
        bridge_info.update({
            'is_up_to_date': None,
            'latest_commit_date': "Unknown",
            'latest_version': "Unknown",
            'latest_commit_message': "Unknown",
            'current_commit_date': "Unknown",
            'current_commit_message': "Unknown",
            'current_version': version_string if 'version_string' in locals() else "Unknown"
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
    """
    Login page with disclaimer about unofficial status.
    Created by Cameron Aaron - Not affiliated with Beeper.
    """
    access_token, jwt_token = retrieve_tokens_from_cookies(request)
    if is_authenticated(access_token, jwt_token):
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "disclaimer": "This is an unofficial dashboard created by Cameron Aaron. Not affiliated with Beeper."
    })


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
    """
    Main dashboard view.
    DISCLAIMER: Unofficial tool created by Cameron Aaron.
    Not affiliated with or endorsed by Beeper/Automatic.
    """
    access_token, jwt_token = retrieve_tokens_from_cookies(request)
    if not is_authenticated(access_token, jwt_token):
        return RedirectResponse(url="/", status_code=302)

    try:
        client = app.state.httpx_client
        beeper_response = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5.0  # reduced timeout
        )
        beeper_response.raise_for_status()
        beeper_data = beeper_response.json()
        
        bridges = beeper_data.get("user", {}).get("bridges", {})
        update_tasks = [
            update_bridge_info(bridge_name, bridge_info)
            for bridge_name, bridge_info in bridges.items()
        ]
        
        # Use asyncio.gather with return_exceptions=True to prevent one failure from affecting others
        await asyncio.gather(*update_tasks, return_exceptions=True)
        
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "bridges": bridges,
            "beeper_data": beeper_data,
            "token": access_token,
            "asmux_data": beeper_data.get("user", {}).get("asmuxData", {}),
            "user_info": beeper_data.get("userInfo", {}),
            "jwt_token": jwt_token,
            "GITHUB_REPOS": GITHUB_REPOS
        })
        
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error fetching Beeper data: {exc.response.status_code}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "Failed to fetch data"})
    except Exception as exc:
        logger.error(f"Unexpected error in dashboard: {str(exc)}")
        return templates.TemplateResponse("error.html", {"request": request, "error": "An unexpected error occurred"})


@app.post("/reset_password", response_class=HTMLResponse)
async def reset_password(request: Request, access_token: str = Form(...), jwt_token: str = Form(...), new_password: str = Form(...)):
    client = app.state.httpx_client
    try:
        # Verify access token is valid
        whoami_response = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0
        )
        whoami_response.raise_for_status()

        # Start interactive auth session by attempting password change
        initial_response = await client.post(
            "https://matrix.beeper.com/_matrix/client/v3/account/password",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            },
            json={
                "new_password": new_password,
                "logout_devices": False
            },
            timeout=10.0
        )

        if initial_response.status_code == 401:  # Expected status for auth required
            auth_data = initial_response.json()
            session = auth_data.get("session")

            if not session:
                return HTMLResponse(content="Failed to start authentication session", status_code=400)

            # Complete password change with JWT auth
            password_response = await client.post(
                "https://matrix.beeper.com/_matrix/client/v3/account/password",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                json={
                    "auth": {
                        "type": "org.matrix.login.jwt",
                        "token": jwt_token,
                        "session": session
                    },
                    "new_password": new_password,
                    "logout_devices": False
                },
                timeout=10.0
            )
            password_response.raise_for_status()
            return HTMLResponse(content="Password reset successfully")
        else:
            return HTMLResponse(content="Unexpected response from server", status_code=500)

    except httpx.HTTPStatusError as exc:
        error_msg = f"Failed to reset password: {exc.response.text}"
        logger.error(f"Error resetting password: {exc.response.status_code} - {error_msg}")
        return HTMLResponse(content=error_msg, status_code=exc.response.status_code)
    except httpx.RequestError as exc:
        error_msg = f"Request error: {str(exc)}"
        logger.error(error_msg)
        return HTMLResponse(content=error_msg, status_code=500)
    except Exception as exc:
        error_msg = f"Unexpected error: {str(exc)}"
        logger.error(error_msg)
        return HTMLResponse(content=error_msg, status_code=500)


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
