from __future__ import annotations

import secrets
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import (
    ApiToken,
    AuditEvent,
    AuthClient,
    Membership,
    OneTimeCode,
    Organization,
    RateLimitBucket,
    RefreshToken,
    Role,
    Session,
    User,
)
from app.schemas import OrgRead, UserRead
from app.security import (
    create_access_token,
    hash_password,
    new_code,
    new_opaque_token,
    now_utc,
    token_hash,
    token_hint,
    utc_after,
    verify_password,
)


async def audit(
    db: AsyncSession,
    action: str,
    *,
    org_id: str | None = None,
    actor_user_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    db.add(
        AuditEvent(
            org_id=org_id,
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip_address=request.client.host if request and request.client else None,
            details=details or {},
        )
    )


async def enforce_rate_limit(
    db: AsyncSession,
    *,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    now = now_utc()
    result = await db.execute(select(RateLimitBucket).where(RateLimitBucket.key == key))
    bucket = result.scalar_one_or_none()
    if not bucket:
        db.add(RateLimitBucket(key=key, count=1, window_start=now))
        return
    age = (now - bucket.window_start).total_seconds()
    if age > window_seconds:
        bucket.count = 1
        bucket.window_start = now
        return
    bucket.count += 1
    if bucket.count > limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def send_one_time_code(*, email: str, code: str, purpose: str) -> None:
    if not settings.smtp_host:
        if settings.email_dev_mode:
            return
        raise HTTPException(status_code=503, detail="SMTP is not configured")

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = email
    message["Subject"] = f"GateKeeper {purpose.replace('_', ' ')}"
    message.set_content(
        "Use this GateKeeper code to continue. "
        "The code expires soon and should not be shared.\n\n"
        f"{code}\n"
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls(context=context)
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


async def ensure_bootstrap(db: AsyncSession) -> Organization:
    result = await db.execute(
        select(Organization).where(Organization.slug == settings.bootstrap_org_slug)
    )
    org = result.scalar_one_or_none()
    if org:
        await ensure_default_clients(db, org)
        await ensure_bootstrap_owner(db, org)
        await db.commit()
        return org

    org = Organization(name=settings.bootstrap_org_name, slug=settings.bootstrap_org_slug)
    db.add(org)
    await db.flush()
    roles = [
        Role(org_id=org.id, name="owner", permissions=["*"]),
        Role(org_id=org.id, name="admin", permissions=["admin:*", "auth:*", "mcp:*"]),
        Role(org_id=org.id, name="operator", permissions=["auth:read", "token:*", "mcp:*"]),
        Role(org_id=org.id, name="viewer", permissions=["auth:read"]),
    ]
    db.add_all(roles)
    await audit(db, "org.bootstrap", org_id=org.id, target_type="organization", target_id=org.id)
    await ensure_default_clients(db, org)
    await ensure_bootstrap_owner(db, org)
    await db.commit()
    return org


async def org_has_owner(db: AsyncSession, org_id: str) -> bool:
    result = await db.execute(
        select(Membership.id)
        .join(Role, Role.id == Membership.role_id)
        .where(
            Membership.org_id == org_id,
            Membership.status == "active",
            Role.name == "owner",
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def ensure_bootstrap_owner(db: AsyncSession, org: Organization) -> bool:
    if await org_has_owner(db, org.id):
        return False

    role_result = await db.execute(select(Role).where(Role.org_id == org.id, Role.name == "owner"))
    owner_role = role_result.scalar_one_or_none()
    if not owner_role:
        return False

    bootstrap_email = str(settings.bootstrap_admin_email).lower()
    candidate_result = await db.execute(
        select(Membership)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.org_id == org.id,
            Membership.status == "active",
            User.email == bootstrap_email,
        )
        .order_by(Membership.created_at.asc())
        .limit(1)
    )
    candidate = candidate_result.scalar_one_or_none()
    if not candidate:
        candidate_result = await db.execute(
            select(Membership)
            .where(Membership.org_id == org.id, Membership.status == "active")
            .order_by(Membership.created_at.asc())
            .limit(1)
        )
        candidate = candidate_result.scalar_one_or_none()

    if not candidate:
        return False

    candidate.role_id = owner_role.id
    await audit(
        db,
        "org.owner.bootstrap",
        org_id=org.id,
        actor_user_id=candidate.user_id,
        target_type="membership",
        target_id=candidate.id,
        details={"reason": "no_active_owner"},
    )
    return True


async def ensure_default_clients(db: AsyncSession, org: Organization) -> None:
    result = await db.execute(select(AuthClient).where(AuthClient.client_id == "gatekeeper-cli"))
    if result.scalar_one_or_none():
        return
    db.add(
        AuthClient(
            org_id=org.id,
            name="GateKeeper CLI",
            client_id="gatekeeper-cli",
            public=True,
            redirect_uris=[],
            allowed_origins=[],
            audiences=["gatekeeper-api"],
            scopes=["auth:read", "token:*", "mcp:*"],
            require_org_membership=True,
        )
    )


async def org_roles(db: AsyncSession, user_id: str) -> list[OrgRead]:
    result = await db.execute(
        select(Organization, Role)
        .join(Membership, Membership.org_id == Organization.id)
        .join(Role, Role.id == Membership.role_id)
        .where(Membership.user_id == user_id, Membership.status == "active")
    )
    return [
        OrgRead(
            id=org.id,
            name=org.name,
            slug=org.slug,
            role=role.name,
            permissions=role.permissions or [],
        )
        for org, role in result.all()
    ]


async def create_user(
    db: AsyncSession,
    *,
    email: str,
    password: str | None,
    display_name: str | None = None,
    verified: bool = False,
) -> User:
    normalized = email.strip().lower()
    existing = await db.execute(select(User).where(User.email == normalized))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(
        email=normalized,
        display_name=display_name,
        password_hash=hash_password(password) if password else None,
        email_verified=verified,
    )
    db.add(user)
    await db.flush()

    bootstrap_org = await ensure_bootstrap(db)
    needs_first_owner = not await org_has_owner(db, bootstrap_org.id)
    if normalized == str(settings.bootstrap_admin_email).lower() or needs_first_owner:
        role_name = "owner"
    else:
        role_name = "viewer"
    result = await db.execute(
        select(Role).where(Role.org_id == bootstrap_org.id, Role.name == role_name)
    )
    role = result.scalar_one()
    db.add(Membership(org_id=bootstrap_org.id, user_id=user.id, role_id=role.id, status="active"))
    await audit(
        db,
        "user.create",
        org_id=bootstrap_org.id,
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"role": role_name, "first_owner": needs_first_owner},
    )
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_password(db: AsyncSession, email: str, password: str) -> User:
    result = await db.execute(select(User).where(User.email == email.strip().lower()))
    user = result.scalar_one_or_none()
    if not user or user.disabled or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return user


async def create_session_tokens(
    db: AsyncSession,
    user: User,
    *,
    request: Request | None = None,
    client: AuthClient | None = None,
    org_id: str | None = None,
    scopes: list[str] | None = None,
    audience: str | list[str] | None = None,
) -> tuple[str, str, Session, RefreshToken]:
    if scopes is None:
        memberships = await org_roles(db, user.id)
        derived_scopes = {permission for org in memberships for permission in org.permissions}
        scopes = sorted(derived_scopes or {"auth:read"})
    if org_id is None:
        memberships = await org_roles(db, user.id)
        org_id = memberships[0].id if memberships else None
    session_secret = new_opaque_token("gks")
    refresh_secret = new_opaque_token("gkr")
    session = Session(
        user_id=user.id,
        org_id=org_id,
        token_hash=token_hash(session_secret),
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
        expires_at=utc_after(days=settings.refresh_token_ttl_days),
    )
    db.add(session)
    await db.flush()
    refresh = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        client_id=client.id if client else None,
        family_id=secrets.token_hex(16),
        token_hash=token_hash(refresh_secret),
        expires_at=utc_after(days=settings.refresh_token_ttl_days),
    )
    db.add(refresh)
    await db.flush()
    access = create_access_token(
        subject=user.id,
        audience=audience or settings.issuer,
        scopes=scopes or ["auth:read"],
        token_type="user",
        client_id=client.client_id if client else None,
        org_id=org_id,
        extra={"email": user.email},
    )
    return access, refresh_secret, session, refresh


async def rotate_refresh_token(db: AsyncSession, refresh_token: str) -> tuple[str, str, User, list[str]]:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash(refresh_token))
    )
    refresh = result.scalar_one_or_none()
    if not refresh or refresh.revoked_at or refresh.expires_at <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if refresh.used_at:
        await db.execute(
            select(RefreshToken).where(RefreshToken.family_id == refresh.family_id)
        )
        family_result = await db.execute(
            select(RefreshToken).where(RefreshToken.family_id == refresh.family_id)
        )
        for item in family_result.scalars():
            item.revoked_at = item.revoked_at or now_utc()
        await db.commit()
        raise HTTPException(status_code=401, detail="Refresh token replay detected")
    user = await db.get(User, refresh.user_id)
    if not user or user.disabled:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    session = await db.get(Session, refresh.session_id)
    client = await db.get(AuthClient, refresh.client_id) if refresh.client_id else None
    memberships = await org_roles(db, user.id)
    derived_scopes = {permission for org in memberships for permission in org.permissions}
    scopes = client.scopes if client else sorted(derived_scopes or {"auth:read"})
    org_id = session.org_id if session else (memberships[0].id if memberships else None)
    audience = (
        client.audiences[0]
        if client and client.audiences
        else settings.issuer
    )
    refresh.used_at = now_utc()
    new_refresh_secret = new_opaque_token("gkr")
    new_refresh = RefreshToken(
        session_id=refresh.session_id,
        user_id=refresh.user_id,
        client_id=refresh.client_id,
        family_id=refresh.family_id,
        token_hash=token_hash(new_refresh_secret),
        expires_at=utc_after(days=settings.refresh_token_ttl_days),
    )
    db.add(new_refresh)
    access = create_access_token(
        subject=user.id,
        audience=audience,
        scopes=scopes,
        token_type="user",
        client_id=client.client_id if client else None,
        org_id=org_id,
        extra={"email": user.email},
    )
    await db.commit()
    return access, new_refresh_secret, user, scopes


def user_read(user: User) -> UserRead:
    return UserRead(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        email_verified=user.email_verified,
    )


async def get_client_by_client_id(db: AsyncSession, client_id: str) -> AuthClient:
    result = await db.execute(select(AuthClient).where(AuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    if not client or not client.enabled:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    return client


def validate_redirect(client: AuthClient, redirect_uri: str) -> None:
    if redirect_uri not in (client.redirect_uris or []):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")


def validate_audience(client: AuthClient, audience: str | None) -> str | None:
    if not audience:
        return None
    if audience not in (client.audiences or []) and audience != client.mcp_resource_uri:
        raise HTTPException(status_code=400, detail="Invalid audience")
    return audience


def validate_scopes(client: AuthClient, scope: str) -> list[str]:
    requested = [item for item in scope.split() if item]
    allowed = set(client.scopes or [])
    if requested and not set(requested).issubset(allowed):
        raise HTTPException(status_code=400, detail="Invalid scope")
    return requested or list(client.scopes or [])


async def create_api_token(
    db: AsyncSession,
    *,
    name: str,
    token_type_value: str,
    org_id: str | None,
    user_id: str | None,
    project_id: str | None,
    client_id: str | None,
    scopes: list[str],
    audiences: list[str],
    expires_at,
) -> tuple[ApiToken, str]:
    raw = new_opaque_token("gk")
    api_token = ApiToken(
        name=name,
        token_type=token_type_value,
        org_id=org_id,
        user_id=user_id,
        project_id=project_id,
        client_id=client_id,
        token_hash=token_hash(raw),
        token_hint=token_hint(raw),
        scopes=scopes,
        audiences=audiences,
        expires_at=expires_at,
    )
    db.add(api_token)
    await db.flush()
    return api_token, raw


async def create_one_time_code(
    db: AsyncSession,
    *,
    email: str,
    purpose: str,
    user_id: str | None = None,
    code: str | None = None,
) -> str:
    raw_code = code or new_code(8)
    db.add(
        OneTimeCode(
            user_id=user_id,
            email=email.strip().lower(),
            purpose=purpose,
            code_hash=token_hash(raw_code),
            expires_at=utc_after(seconds=settings.email_code_ttl_seconds),
        )
    )
    return raw_code


async def verify_one_time_code(db: AsyncSession, *, email: str, purpose: str, code: str) -> OneTimeCode:
    result = await db.execute(
        select(OneTimeCode).where(
            OneTimeCode.email == email.strip().lower(),
            OneTimeCode.purpose == purpose,
            OneTimeCode.code_hash == token_hash(code.strip().upper()),
        )
    )
    record = result.scalar_one_or_none()
    if not record or record.used_at or record.expires_at <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    record.used_at = now_utc()
    return record
