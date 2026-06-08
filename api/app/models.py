from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base


def json_type():
    return JSON().with_variant(JSONB, "postgresql")


def uuid_str() -> str:
    return str(uuid.uuid4())


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Identity(Base, TimestampMixin):
    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("provider", "provider_subject"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    provider_subject: Mapped[str] = mapped_column(String(240), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)


class OAuthProvider(Base, TimestampMixin):
    __tablename__ = "oauth_providers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    provider_id: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    client_id: Mapped[str] = mapped_column(String(240), default="", nullable=False)
    client_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    authorization_url: Mapped[str] = mapped_column(String(500), nullable=False)
    token_url: Mapped[str] = mapped_column(String(500), nullable=False)
    userinfo_url: Mapped[str] = mapped_column(String(500), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    scopes: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    subject_claim: Mapped[str] = mapped_column(String(120), default="sub", nullable=False)
    email_claim: Mapped[str] = mapped_column(String(120), default="email", nullable=False)
    name_claim: Mapped[str] = mapped_column(String(120), default="name", nullable=False)
    email_verified_claim: Mapped[str] = mapped_column(String(120), default="email_verified", nullable=False)
    allow_email_linking: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_verified_email: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trusted_device_mfa_bypass: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    admin_step_up_mfa_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    session_idle_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    audit_retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    allow_user_hard_delete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"
    __table_args__ = (UniqueConstraint("org_id", "slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str | None] = mapped_column(ForeignKey("workspaces.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    audience: Mapped[str] = mapped_column(String(200), index=True, nullable=False)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("org_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    permissions: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)


class Membership(Base, TimestampMixin):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), index=True)
    status: Mapped[str] = mapped_column(String(40), default="active", nullable=False)
    scim_external_id: Mapped[str | None] = mapped_column(String(240), nullable=True)
    scim_enterprise_profile: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(json_type()), default=dict
    )

    user: Mapped[User] = relationship(back_populates="memberships")
    role: Mapped[Role] = relationship()


class AuthClient(Base, TimestampMixin):
    __tablename__ = "auth_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    logo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    homepage_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    privacy_policy_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    terms_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    publisher_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    client_id: Mapped[str] = mapped_column(String(160), unique=True, index=True, nullable=False)
    client_secret_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    public: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    allowed_origins: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    audiences: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    scopes: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    require_org_membership: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trusted_device_mfa_bypass: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    session_idle_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mcp_resource_uri: Mapped[str | None] = mapped_column(String(300), nullable=True)


class Session(Base, TimestampMixin):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("auth_clients.id"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    device_id_hash: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(80), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    trusted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    trusted_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    amr: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RefreshToken(Base, TimestampMixin):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("auth_clients.id"), nullable=True)
    family_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class OAuthAuthorizationCode(Base, TimestampMixin):
    __tablename__ = "oauth_authorization_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    code_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    client_id: Mapped[str] = mapped_column(ForeignKey("auth_clients.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    redirect_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    scope: Mapped[str] = mapped_column(Text, default="", nullable=False)
    audience: Mapped[str | None] = mapped_column(String(300), nullable=True)
    code_challenge: Mapped[str] = mapped_column(String(200), nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(String(20), default="S256", nullable=False)
    amr: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class OAuthGrant(Base, TimestampMixin):
    __tablename__ = "oauth_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    client_id: Mapped[str] = mapped_column(ForeignKey("auth_clients.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    audience: Mapped[str | None] = mapped_column(String(300), nullable=True)
    scopes: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    last_authorized_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MfaRecoveryCode(Base, TimestampMixin):
    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (Index("ix_mfa_recovery_codes_user_used", "user_id", "used_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    code_hint: Mapped[str] = mapped_column(String(20), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Invitation(Base, TimestampMixin):
    __tablename__ = "invitations"
    __table_args__ = (
        Index("ix_invitations_org_email", "org_id", "email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), index=True)
    invited_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    accepted_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    token_hint: Mapped[str] = mapped_column(String(20), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceGrant(Base, TimestampMixin):
    __tablename__ = "device_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    device_code_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    user_code_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    user_code_hint: Mapped[str] = mapped_column(String(20), nullable=False)
    client_id: Mapped[str] = mapped_column(ForeignKey("auth_clients.id"), index=True)
    scope: Mapped[str] = mapped_column(Text, default="", nullable=False)
    audience: Mapped[str | None] = mapped_column(String(300), nullable=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    amr: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    denied_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ApiToken(Base, TimestampMixin):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("auth_clients.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    token_type: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    token_hint: Mapped[str] = mapped_column(String(20), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    audiences: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class McpResource(Base, TimestampMixin):
    __tablename__ = "mcp_resources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    resource_uri: Mapped[str] = mapped_column(String(300), unique=True, index=True, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)


class WebAuthnCredential(Base, TimestampMixin):
    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    transports: Mapped[list[str]] = mapped_column(MutableList.as_mutable(json_type()), default=list)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class OneTimeCode(Base, TimestampMixin):
    __tablename__ = "one_time_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    code_hash: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(80), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(MutableDict.as_mutable(json_type()), default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(220), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)


Index("ix_api_tokens_org_type", ApiToken.org_id, ApiToken.token_type)
Index("ix_oauth_grants_user_client", OAuthGrant.user_id, OAuthGrant.client_id)
Index("ix_audit_events_org_action", AuditEvent.org_id, AuditEvent.action)
Index("ix_sessions_client_id", Session.client_id)
