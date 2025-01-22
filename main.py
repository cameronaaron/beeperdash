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
import json  # Add this import
from pydantic import BaseModel, EmailStr
import os
import logging
import time
from typing import Dict, Any, Tuple, Optional, List, TypeVar, Generic
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pydantic import Field
import contextlib

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


class BeeperError(Exception):
    """Custom exception for Beeper API errors"""
    def __init__(self, message: str, status_code: int):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


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
        if (default_branch):
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


def extract_domain_and_username(user_data: dict) -> tuple[str, str]:
    """Extract domain and username from Beeper user data"""
    try:
        # Debug log the structure
        logger.debug(f"User data structure: {str(user_data)}")
        
        # Get username - seems to be consistent in userInfo
        if "userInfo" in user_data:
            username = user_data["userInfo"].get("username")
            if not username:
                raise ValueError("Username not found in userInfo")
            
            # Try to get domain from hungryUrl
            hungry_url = user_data["userInfo"].get("hungryUrl", "")
            if hungry_url and "matrix." in hungry_url:
                domain = hungry_url.split("matrix.")[-1].split("/")[0]
                logger.debug(f"Extracted domain {domain} and username {username} from hungryUrl")
                return domain, username

        # Fallback to user object if present
        if "user" in user_data:
            user = user_data["user"]
            if user.get("username") and user.get("domain"):
                logger.debug(f"Found username/domain in user object")
                return user["domain"], user["username"]

        # As a last resort, try to extract from bridgeState
        if "user" in user_data and "bridges" in user_data["user"]:
            # Look for hungryserv bridge first as it's most likely to have the correct info
            bridges = user_data["user"]["bridges"]
            if "hungryserv" in bridges:
                remote_state = bridges["hungryserv"].get("remoteState", {})
                for remote_id in remote_state:
                    if "@" in remote_id and ":" in remote_id:
                        # Format: @username:domain
                        domain = remote_id.split(":")[-1]
                        logger.debug(f"Extracted domain {domain} from hungryserv remote state")
                        return domain, username

        raise ValueError("Could not extract domain and username from user data")
    except Exception as e:
        logger.error(f"Error extracting domain and username: {str(e)}")
        logger.error(f"Available fields in userInfo: {str(user_data.get('userInfo', {}))}")
        raise ValueError(f"Failed to parse user data: {str(e)}")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard view with enhanced app service management"""
    access_token, jwt_token = retrieve_tokens_from_cookies(request)
    if not is_authenticated(access_token, jwt_token):
        return RedirectResponse(url="/", status_code=302)

    try:
        client = app.state.httpx_client
        beeper_response = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5.0
        )
        beeper_response.raise_for_status()
        beeper_data = beeper_response.json()
        
        # Ensure user_info exists and has necessary fields
        user_info = beeper_data.get("userInfo", {})
        if isinstance(user_info, dict):
            # Convert any None values to empty dicts to prevent attribute access errors
            user_info["customerLead"] = user_info.get("customerLead", {}) or {}
            if "reservedName" not in user_info["customerLead"]:
                user_info["customerLead"]["reservedName"] = {}
        
        # Initialize variables
        bridges = beeper_data.get("user", {}).get("bridges", {})
        app_services = {}
        server_time = datetime.now()
        precision = timedelta(0)
        domain = None

        try:
            domain, username = extract_domain_and_username(beeper_data)
            hungry_client = HungryAPIClient(
                base_domain=domain,
                username=username,
                access_token=access_token
            )
            
            server_time, precision = await hungry_client.get_server_time()
            
            for bridge_name in bridges.keys():
                try:
                    app_service = await hungry_client.get_app_service(bridge_name)
                    app_services[bridge_name] = app_service
                except Exception as e:
                    logger.debug(f"No app service for bridge {bridge_name}: {str(e)}")
                    app_services[bridge_name] = None
                    
        except ValueError as e:
            logger.warning(f"Domain extraction failed: {str(e)}")

        # Process bridge information
        update_tasks = [
            update_bridge_info(bridge_name, bridge_info)
            for bridge_name, bridge_info in bridges.items()
        ]
        await asyncio.gather(*update_tasks, return_exceptions=True)

        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "bridges": bridges,
            "beeper_data": beeper_data,
            "token": access_token,
            "asmux_data": beeper_data.get("user", {}).get("asmuxData", {}),
            "user_info": user_info,
            "jwt_token": jwt_token,
            "GITHUB_REPOS": GITHUB_REPOS,
            "app_services": app_services,
            "server_time": server_time,
            "time_precision": precision,
            "domain": domain
        })
        
    except Exception as exc:
        logger.error(f"Unexpected error in dashboard: {str(exc)}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Failed to load dashboard"
        })


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

T = TypeVar('T')

class FullRequest(Generic[T]):
    method: str
    url: str
    response_json: T
    max_attempts: int = 1

class Registration(BaseModel):
    """Matrix appservice registration data"""
    id: str
    url: str
    as_token: str
    hs_token: str
    sender_localpart: str
    namespaces: Dict[str, List[Dict[str, Any]]]
    rate_limited: bool = False
    protocols: List[str] = Field(default_factory=list)

@dataclass
class HungryAPIClient:
    base_domain: str
    username: str
    access_token: str
    _client: Optional[httpx.AsyncClient] = field(default=None, init=False)
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    def get_base_url(self) -> str:
        return f"https://matrix.{self.base_domain}/_hungryserv/{self.username}"
    
    def get_user_id(self) -> str:
        return f"@{self.username}:{self.base_domain}"
    
    def build_url(self, path_parts: List[str]) -> str:
        """Build URL similar to mautrix.Client.BuildURL"""
        base = self.get_base_url()
        path = "/".join(str(p) for p in path_parts if p)
        return f"{base}/{path}"
    
    async def make_request(self, 
        method: str, 
        url: str, 
        content: Optional[Dict] = None, 
        response_model: Optional[Any] = None
    ) -> Any:
        """Make request with similar interface to mautrix.Client.MakeRequest"""
        client = self._client or httpx.AsyncClient()
        try:
            response = await client.request(
                method,
                url,
                headers={"Authorization": f"Bearer {self.access_token}"},
                json=content
            )
            response.raise_for_status()
            if response_model and response.content:
                return response_model.parse_raw(response.content)
            return response.json() if response.content else None
        finally:
            if not self._client:
                await client.aclose()
    
    async def make_full_request(self, request: FullRequest) -> Any:
        """Similar to mautrix.Client.MakeFullRequest"""
        attempts = 0
        while attempts < request.max_attempts:
            try:
                return await self.make_request(
                    request.method,
                    request.url,
                    response_model=request.response_json
                )
            except Exception as e:
                attempts += 1
                if attempts >= request.max_attempts:
                    raise
                await asyncio.sleep(1)
    
    # Update existing methods to use new request helpers
    async def register_app_service(
        self, 
        bridge: str, 
        address: str, 
        push: bool = False, 
        self_hosted: bool = False
    ) -> Registration:
        url = self.build_url(["_matrix", "asmux", "mxauth", "appservice", self.username, bridge])
        return await self.make_request(
            "PUT",
            url,
            content={"address": address, "push": push, "self_hosted": self_hosted},
            response_model=Registration
        )
    
    async def get_app_service(self, bridge: str) -> Registration:
        url = self.build_url(["_matrix", "asmux", "mxauth", "appservice", self.username, bridge])
        return await self.make_request("GET", url, response_model=Registration)
    
    async def delete_app_service(self, bridge: str) -> None:
        url = self.build_url(["_matrix", "asmux", "mxauth", "appservice", self.username, bridge])
        await self.make_request("DELETE", url)
    
    async def get_server_time(self) -> Tuple[datetime, timedelta]:
        start = time.time()
        url = self.build_url(["_matrix", "client", "unstable", "com.beeper.timesync"])
        resp = await self.make_request("GET", url)
        precision = timedelta(seconds=time.time() - start)
        return datetime.fromtimestamp(resp["time_ms"] / 1000), precision

@app.post("/api/appservice/{bridge}", response_model=Registration)
async def register_app_service(
    request: Request,
    bridge: str,
    address: str = Form(...),
    push: bool = Form(False),
    self_hosted: bool = Form(False)
):
    """Register a new app service for a bridge"""
    access_token, _ = retrieve_tokens_from_cookies(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        client = app.state.httpx_client
        whoami = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        whoami.raise_for_status()
        user_data = whoami.json()
        
        domain, username = extract_domain_and_username(user_data)
        async with HungryAPIClient(
            base_domain=domain,
            username=username,
            access_token=access_token
        ) as client:
            try:
                result = await client.register_app_service(bridge, address, push, self_hosted)
                return result
            except BeeperError as e:
                logger.warning(f"App service registration failed: {e.message}")
                return HTMLResponse(
                    content=e.message,
                    status_code=e.status_code
                )
        
    except ValueError as e:
        logger.error(f"Domain extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error registering app service: {str(e)}")
        if isinstance(e, httpx.HTTPStatusError):
            return HTMLResponse(
                content=f"Failed to register app service: {e.response.text}",
                status_code=e.response.status_code
            )
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/appservice/{bridge}")
async def get_app_service(request: Request, bridge: str):
    """Get app service details for a bridge"""
    access_token, _ = retrieve_tokens_from_cookies(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        client = app.state.httpx_client
        whoami = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        whoami.raise_for_status()
        user_data = whoami.json()
        
        domain, username = extract_domain_and_username(user_data)
        logger.debug(f"Using domain: {domain}, username: {username}")
        
        async with HungryAPIClient(
            base_domain=domain,
            username=username,
            access_token=access_token
        ) as client:
            result = await client.get_app_service(bridge)
            return result
        
    except ValueError as e:
        logger.error(f"Domain extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting app service: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/appservice/{bridge}")
async def delete_app_service(request: Request, bridge: str):
    """Delete an app service for a bridge"""
    access_token, _ = retrieve_tokens_from_cookies(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        client = app.state.httpx_client
        whoami = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        whoami.raise_for_status()
        user_data = whoami.json()
        
        domain, username = extract_domain_and_username(user_data)
        async with HungryAPIClient(
            base_domain=domain,
            username=username,
            access_token=access_token
        ) as client:
            await client.delete_app_service(bridge)
            return {"status": "success", "message": f"App service for bridge {bridge} deleted"}
        
    except ValueError as e:
        logger.error(f"Domain extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting app service: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/time/sync")
async def get_server_time_sync(request: Request):
    """Get server time and sync information"""
    access_token, _ = retrieve_tokens_from_cookies(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        client = app.state.httpx_client
        whoami = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        whoami.raise_for_status()
        user_data = whoami.json()
        
        try:
            domain, username = extract_domain_and_username(user_data)
        except ValueError as e:
            logger.error(f"Domain extraction failed: {str(e)}")
            return {
                "server_time": datetime.now().isoformat(),
                "precision_ms": 0,
                "local_time": datetime.now().isoformat(),
                "error": "Could not determine server domain"
            }
        
        async with HungryAPIClient(
            base_domain=domain,
            username=username,
            access_token=access_token
        ) as client:
            server_time, precision = await client.get_server_time()
            return {
                "server_time": server_time.isoformat(),
                "precision_ms": precision.total_seconds() * 1000,
                "local_time": datetime.now().isoformat()
            }
    except Exception as e:
        logger.error(f"Error getting server time: {str(e)}")
        return {
            "server_time": datetime.now().isoformat(),
            "precision_ms": 0,
            "local_time": datetime.now().isoformat(),
            "error": str(e)
        }

class BridgeStateEvent(str, Enum):
    RUNNING = "RUNNING"
    STARTING = "STARTING"
    BACKOFF = "BACKOFF"
    UNAVAILABLE = "UNAVAILABLE"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    BRIDGE_NOT_RUNNING = "BRIDGE_NOT_RUNNING"
    # ...add other states as needed...

class BridgeState(BaseModel):
    username: str
    bridge: str
    stateEvent: BridgeStateEvent
    source: str
    createdAt: datetime
    reason: Optional[str]
    info: Dict[str, Any] = Field(default_factory=dict)
    isSelfHosted: bool
    bridgeType: str

class OtherVersion(BaseModel):
    name: str
    version: str

class WhoamiBridge(BaseModel):
    version: str
    configHash: str
    otherVersions: List[OtherVersion] = Field(default_factory=list)
    bridgeState: BridgeState
    remoteState: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

class WhoamiAsmuxData(BaseModel):
    login_token: str
    api_token: str = ""
    id: str = ""

class WhoamiUser(BaseModel):
    bridges: Dict[str, WhoamiBridge] = Field(default_factory=dict)
    hungryserv: Optional[WhoamiBridge]
    asmuxData: WhoamiAsmuxData

class WhoamiUserInfo(BaseModel):
    createdAt: datetime
    username: str
    email: str
    fullName: str
    channel: str
    isAdmin: bool = Field(alias="admin")
    isUserBridgeChangesLocked: bool = Field(alias="bridgeChangesLocked")
    isFree: bool = Field(alias="free")
    deletedAt: Optional[datetime]
    supportRoomId: str
    useHungryserv: bool
    bridgeClusterId: str
    analyticsId: str
    hungryUrl: str = Field(alias="fakeHungryURL")
    hungryUrlDirect: str = Field(alias="hungryURL")

class RespWhoami(BaseModel):
    user: WhoamiUser
    userInfo: WhoamiUserInfo

@app.post("/api/bridge/{bridge_name}/state")
async def post_bridge_state(
    request: Request,
    bridge_name: str,
    state: BridgeState,
):
    """Post bridge state update"""
    access_token, _ = retrieve_tokens_from_cookies(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        client = app.state.httpx_client
        whoami = await client.get(
            "https://api.beeper.com/whoami",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        whoami.raise_for_status()
        user_data = whoami.json()
        
        domain, username = extract_domain_and_username(user_data)
        
        url = f"https://api.{domain}/bridgebox/{username}/bridge/{bridge_name}/bridge_state"
        response = await client.post(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            json=state.dict()
        )
        response.raise_for_status()
        return {"status": "success"}
        
    except Exception as e:
        logger.error(f"Error posting bridge state: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/whoami", response_model=RespWhoami)
async def get_whoami(request: Request):
    """Get whoami information"""
    access_token, _ = retrieve_tokens_from_cookies(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        client = app.state.httpx_client
        domain, _ = extract_domain_and_username({"userInfo": {"hungryUrl": "https://matrix.beeper.com"}})
        response = await client.get(
            f"https://api.{domain}/whoami",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        return RespWhoami.parse_obj(response.json())
    except Exception as e:
        logger.error(f"Error getting whoami: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
