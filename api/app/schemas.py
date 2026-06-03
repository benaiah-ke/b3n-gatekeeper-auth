from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class UserRead(BaseModel):
    id: str
    email: EmailStr
    display_name: str | None
    email_verified: bool


class OrgRead(BaseModel):
    id: str
    name: str
    slug: str
    role: str | None = None
    permissions: list[str] = []


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    scope: str = ""
    user: UserRead | None = None
    orgs: list[OrgRead] = []


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12)
    display_name: str | None = Field(default=None, max_length=160)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    client_id: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class EmailCodeRequest(BaseModel):
    email: EmailStr
    purpose: Literal["login", "verify_email", "reset_password"] = "login"


class EmailCodeVerify(BaseModel):
    email: EmailStr
    code: str
    purpose: Literal["login", "verify_email", "reset_password"] = "login"


class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str
    new_password: str = Field(..., min_length=12)


class SessionRead(BaseModel):
    id: str
    user_id: str
    org_id: str | None
    ip_address: str | None
    user_agent: str | None
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime


class ClientCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    org_id: str | None = None
    public: bool = True
    redirect_uris: list[str] = []
    allowed_origins: list[str] = []
    audiences: list[str] = []
    scopes: list[str] = []
    require_org_membership: bool = True
    mcp_resource_uri: str | None = None


class ClientRead(BaseModel):
    id: str
    name: str
    client_id: str
    public: bool
    enabled: bool
    redirect_uris: list[str]
    allowed_origins: list[str]
    audiences: list[str]
    scopes: list[str]
    require_org_membership: bool
    mcp_resource_uri: str | None


class TokenCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    token_type: Literal["personal", "service", "project", "admin", "machine"] = "personal"
    org_id: str | None = None
    project_id: str | None = None
    client_id: str | None = None
    scopes: list[str] = []
    audiences: list[str] = []
    expires_at: datetime | None = None


class TokenRead(BaseModel):
    id: str
    name: str
    token_type: str
    token_hint: str
    scopes: list[str]
    audiences: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    token: str | None = None


class OrgCreate(BaseModel):
    name: str
    slug: str


class WorkspaceCreate(BaseModel):
    org_id: str
    name: str
    slug: str


class ProjectCreate(BaseModel):
    org_id: str
    workspace_id: str | None = None
    name: str
    slug: str
    audience: str


class RoleCreate(BaseModel):
    org_id: str | None = None
    name: str
    permissions: list[str] = []


class McpResourceCreate(BaseModel):
    name: str
    org_id: str | None = None
    resource_uri: str
    scopes: list[str] = []


class DeviceAuthorizationRequest(BaseModel):
    client_id: str
    scope: str = ""
    audience: str | None = None


class DeviceAuthorizeApprove(BaseModel):
    user_code: str
    approve: bool = True
    org_id: str | None = None


class OAuthAuthorizeRequest(BaseModel):
    response_type: str = "code"
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str = "S256"
    scope: str = ""
    state: str | None = None
    audience: str | None = None
    org_id: str | None = None


class AuditRead(BaseModel):
    id: str
    org_id: str | None
    actor_user_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    created_at: datetime
