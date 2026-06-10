from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class UserRead(BaseModel):
    id: str
    email: EmailStr
    display_name: str | None
    email_verified: bool
    mfa_totp_enabled: bool = False


class MembershipRead(BaseModel):
    id: str
    org_id: str
    org_name: str
    role_id: str
    role: str
    permissions: list[str] = []
    status: str
    created_at: datetime
    updated_at: datetime


class UserAdminRead(UserRead):
    disabled: bool
    created_at: datetime
    updated_at: datetime
    mfa_totp_enabled_at: datetime | None = None
    memberships: list[MembershipRead] = []


class UserAdminUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=160)
    email_verified: bool | None = None
    disabled: bool | None = None


class IdentityRead(BaseModel):
    id: str
    provider: str
    email: EmailStr | None = None
    created_at: datetime
    updated_at: datetime


class OAuthProviderRead(BaseModel):
    id: str
    name: str
    configured: bool
    scopes: list[str] = []
    start_url: str
    authorization_url: str
    require_verified_email: bool
    allow_email_linking: bool


class OAuthProviderAdminCreate(BaseModel):
    provider_id: str = Field(..., min_length=2, max_length=40, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(..., min_length=2, max_length=160)
    enabled: bool = True
    client_id: str = Field(default="", max_length=240)
    client_secret: str | None = Field(default=None, max_length=1000)
    authorization_url: str = Field(..., max_length=500)
    token_url: str = Field(..., max_length=500)
    userinfo_url: str = Field(..., max_length=500)
    redirect_uri: str = Field(default="", max_length=500)
    scopes: list[str] = ["openid", "email", "profile"]
    subject_claim: str = Field(default="sub", max_length=120)
    email_claim: str = Field(default="email", max_length=120)
    name_claim: str = Field(default="name", max_length=120)
    email_verified_claim: str = Field(default="email_verified", max_length=120)
    allow_email_linking: bool = True
    require_verified_email: bool = True


class OAuthProviderAdminUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    enabled: bool | None = None
    client_id: str | None = Field(default=None, max_length=240)
    client_secret: str | None = Field(default=None, max_length=1000)
    authorization_url: str | None = Field(default=None, max_length=500)
    token_url: str | None = Field(default=None, max_length=500)
    userinfo_url: str | None = Field(default=None, max_length=500)
    redirect_uri: str | None = Field(default=None, max_length=500)
    scopes: list[str] | None = None
    subject_claim: str | None = Field(default=None, max_length=120)
    email_claim: str | None = Field(default=None, max_length=120)
    name_claim: str | None = Field(default=None, max_length=120)
    email_verified_claim: str | None = Field(default=None, max_length=120)
    allow_email_linking: bool | None = None
    require_verified_email: bool | None = None


class OAuthProviderAdminRead(BaseModel):
    id: str
    provider_id: str
    source: Literal["database", "env"]
    read_only: bool
    name: str
    enabled: bool
    configured: bool
    client_id: str
    client_secret_configured: bool
    authorization_url: str
    token_url: str
    userinfo_url: str
    redirect_uri: str
    scopes: list[str]
    subject_claim: str
    email_claim: str
    name_claim: str
    email_verified_claim: str
    allow_email_linking: bool
    require_verified_email: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CurrentUserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=160)


class EmailChangeRequest(BaseModel):
    new_email: EmailStr
    current_password: str | None = None


class EmailChangeConfirm(BaseModel):
    new_email: EmailStr
    code: str
    revoke_other_sessions: bool = True


class EmailChangeResponse(BaseModel):
    status: str
    email: EmailStr
    revoked_count: int = 0
    current_session_kept: bool = True


class AccountDeactivateRequest(BaseModel):
    current_password: str | None = None
    totp_code: str | None = None
    recovery_code: str | None = None


class AccountDeactivateResponse(BaseModel):
    status: str
    revoked_sessions: int
    revoked_tokens: int
    revoked_grants: int


class UserDeleteRequest(BaseModel):
    dry_run: bool = True
    confirm_email: EmailStr | None = None


class UserDeleteResponse(BaseModel):
    status: str
    dry_run: bool
    user_id: str
    email: EmailStr
    counts: dict[str, int]
    policy_org_ids: list[str] = []


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12)
    revoke_other_sessions: bool = True


class PasswordChangeResponse(BaseModel):
    status: str
    revoked_count: int
    current_session_kept: bool


class UserMembershipUpdate(BaseModel):
    org_id: str
    role_id: str | None = None
    role: str | None = None
    status: Literal["active", "suspended", "revoked"] = "active"


class UserProvisionRequest(BaseModel):
    org_id: str
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=160)
    email_verified: bool | None = None
    disabled: bool | None = None
    role_id: str | None = None
    role: str | None = None
    status: Literal["active", "suspended", "revoked"] = "active"


class UserProvisionResponse(BaseModel):
    status: Literal["created", "updated"]
    created_user: bool
    created_membership: bool
    revoked_sessions: int
    user: UserAdminRead


class UserSessionsRevokeResponse(BaseModel):
    status: str
    revoked_count: int


class UserMfaResetResponse(BaseModel):
    status: str
    revoked_count: int
    user: UserAdminRead


class InvitationCreate(BaseModel):
    email: EmailStr
    org_id: str
    role_id: str | None = None
    role: str | None = None
    expires_in_days: int = Field(default=7, ge=1, le=90)


class InvitationRead(BaseModel):
    id: str
    org_id: str
    org_name: str
    email: EmailStr
    role_id: str
    role: str
    permissions: list[str] = []
    invited_by_user_id: str | None = None
    accepted_user_id: str | None = None
    token_hint: str
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class InvitationCreateResponse(InvitationRead):
    token: str


class InvitationAcceptRequest(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(..., min_length=12)
    display_name: str | None = Field(default=None, max_length=160)
    totp_code: str | None = None
    recovery_code: str | None = None


class OrgRead(BaseModel):
    id: str
    name: str
    slug: str
    require_mfa: bool = False
    trusted_device_mfa_bypass: bool = False
    admin_step_up_mfa_required: bool = False
    session_idle_timeout_minutes: int | None = None
    audit_retention_days: int | None = None
    allow_user_hard_delete: bool = False
    role: str | None = None
    permissions: list[str] = []


class WorkspaceRead(BaseModel):
    id: str
    org_id: str
    name: str
    slug: str


class ProjectRead(BaseModel):
    id: str
    org_id: str
    workspace_id: str | None = None
    name: str
    slug: str
    audience: str


class RoleRead(BaseModel):
    id: str
    org_id: str | None = None
    name: str
    permissions: list[str] = []


class SetupStatusRead(BaseModel):
    issuer: str
    jwks_uri: str
    user: UserRead | None = None
    org: OrgRead | None = None
    orgs: list[OrgRead] = []
    auth_type: str
    scopes: list[str] = []
    owner_exists: bool
    can_manage_clients: bool
    can_issue_tokens: bool
    can_manage_projects: bool
    can_manage_roles: bool
    access_expires_at: datetime | None = None
    smtp_configured: bool
    email_dev_mode: bool
    dynamic_client_registration_enabled: bool


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
    scope: str | None = None
    audience: str | None = None
    totp_code: str | None = None
    recovery_code: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class OrgSwitchRequest(BaseModel):
    org_id: str
    client_id: str | None = None
    scope: str | None = None
    audience: str | None = None
    revoke_current_session: bool = False


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


class MfaStatusRead(BaseModel):
    totp_enabled: bool
    totp_enabled_at: datetime | None = None
    totp_pending: bool = False
    recovery_codes_remaining: int = 0


class TotpSetupRead(BaseModel):
    secret: str
    otpauth_uri: str
    issuer: str
    account: str


class TotpVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=16)


class TotpEnableRead(MfaStatusRead):
    recovery_codes: list[str] = []


class MfaRecoveryCodesRead(BaseModel):
    recovery_codes: list[str]
    recovery_codes_remaining: int


class SessionRead(BaseModel):
    id: str
    user_id: str
    org_id: str | None
    auth_client_id: str | None = None
    client_id: str | None = None
    client_name: str | None = None
    client_public: bool | None = None
    current: bool = False
    ip_address: str | None
    user_agent: str | None
    device_label: str | None = None
    amr: list[str] = []
    trusted: bool = False
    trusted_at: datetime | None = None
    trusted_until: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime


class SessionDeviceUpdate(BaseModel):
    device_label: str | None = Field(default=None, max_length=120)
    trusted: bool | None = None
    trusted_until: datetime | None = None


class SessionRevokeAllRequest(BaseModel):
    include_current: bool = True


class SessionRevokeAllResponse(BaseModel):
    status: str
    revoked_count: int
    include_current: bool


class ClientCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    client_id: str | None = Field(default=None, min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    logo_url: str | None = Field(default=None, max_length=500)
    homepage_url: str | None = Field(default=None, max_length=500)
    privacy_policy_url: str | None = Field(default=None, max_length=500)
    terms_url: str | None = Field(default=None, max_length=500)
    publisher_name: str | None = Field(default=None, max_length=160)
    verified: bool = False
    org_id: str | None = None
    public: bool = True
    redirect_uris: list[str] = []
    allowed_origins: list[str] = []
    audiences: list[str] = []
    scopes: list[str] = []
    require_org_membership: bool = True
    require_mfa: bool = False
    trusted_device_mfa_bypass: bool = False
    session_idle_timeout_minutes: int | None = Field(default=None, ge=5, le=10080)
    mcp_resource_uri: str | None = None


class ClientUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    logo_url: str | None = Field(default=None, max_length=500)
    homepage_url: str | None = Field(default=None, max_length=500)
    privacy_policy_url: str | None = Field(default=None, max_length=500)
    terms_url: str | None = Field(default=None, max_length=500)
    publisher_name: str | None = Field(default=None, max_length=160)
    verified: bool | None = None
    enabled: bool | None = None
    redirect_uris: list[str] | None = None
    allowed_origins: list[str] | None = None
    audiences: list[str] | None = None
    scopes: list[str] | None = None
    require_org_membership: bool | None = None
    require_mfa: bool | None = None
    trusted_device_mfa_bypass: bool | None = None
    session_idle_timeout_minutes: int | None = Field(default=None, ge=5, le=10080)
    mcp_resource_uri: str | None = None


class ClientRead(BaseModel):
    id: str
    org_id: str | None
    name: str
    description: str | None = None
    logo_url: str | None = None
    homepage_url: str | None = None
    privacy_policy_url: str | None = None
    terms_url: str | None = None
    publisher_name: str | None = None
    verified: bool = False
    verified_at: datetime | None = None
    client_id: str
    public: bool
    enabled: bool
    redirect_uris: list[str]
    allowed_origins: list[str]
    audiences: list[str]
    scopes: list[str]
    require_org_membership: bool
    require_mfa: bool
    trusted_device_mfa_bypass: bool
    session_idle_timeout_minutes: int | None = None
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
    org_id: str | None
    user_id: str | None
    project_id: str | None
    client_id: str | None
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


class TokenValidateRequest(BaseModel):
    token: str
    audience: str | None = None
    required_scopes: list[str] = []
    org_id: str | None = None
    project_id: str | None = None


class TokenValidateResponse(BaseModel):
    active: bool
    reason: str | None = None
    token_id: str | None = None
    token_type: str | None = None
    token_hint: str | None = None
    org_id: str | None = None
    org_name: str | None = None
    org_slug: str | None = None
    user_id: str | None = None
    user_email: EmailStr | None = None
    user_display_name: str | None = None
    project_id: str | None = None
    project_name: str | None = None
    project_audience: str | None = None
    auth_client_id: str | None = None
    scopes: list[str] = []
    audiences: list[str] = []
    missing_scopes: list[str] = []
    audience_ok: bool = True
    scope_ok: bool = True
    expires_at: datetime | None = None
    last_used_at: datetime | None = None


class OrgCreate(BaseModel):
    name: str
    slug: str
    require_mfa: bool = False
    trusted_device_mfa_bypass: bool = False
    admin_step_up_mfa_required: bool = False
    session_idle_timeout_minutes: int | None = Field(default=None, ge=5, le=10080)
    audit_retention_days: int | None = Field(default=None, ge=1, le=3650)
    allow_user_hard_delete: bool = False


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    require_mfa: bool | None = None
    trusted_device_mfa_bypass: bool | None = None
    admin_step_up_mfa_required: bool | None = None
    session_idle_timeout_minutes: int | None = Field(default=None, ge=5, le=10080)
    audit_retention_days: int | None = Field(default=None, ge=1, le=3650)
    allow_user_hard_delete: bool | None = None


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
    totp_code: str | None = None
    recovery_code: str | None = None


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
    approve: bool = False


class OAuthGrantRead(BaseModel):
    id: str
    auth_client_id: str
    client_id: str
    client_name: str
    user_id: str | None = None
    user_email: EmailStr | None = None
    org_id: str | None
    audience: str | None
    scopes: list[str]
    last_authorized_at: datetime
    revoked_at: datetime | None
    created_at: datetime


class AuditRead(BaseModel):
    id: str
    org_id: str | None
    actor_user_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    created_at: datetime


class AuditPruneRequest(BaseModel):
    org_id: str | None = None
    dry_run: bool = True


class AuditPruneResponse(BaseModel):
    org_id: str
    retention_days: int
    cutoff_at: datetime
    pruned_count: int
    dry_run: bool
