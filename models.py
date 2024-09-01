from pydantic import BaseModel, EmailStr
from typing import Dict, Any

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