from __future__ import annotations

import ipaddress
import logging
import secrets
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts import send_security_alert
from app.config import settings
from app.models import (
    ApiToken,
    AuditEvent,
    AuthClient,
    InstallClaim,
    Membership,
    OneTimeCode,
    Organization,
    RateLimitBucket,
    RefreshToken,
    Role,
    Session,
    User,
    WebAuthnCredential,
    uuid_str,
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

logger = logging.getLogger("gatekeeper")
SIGNUP_CLOSED_DETAIL = "Sign up is closed. Ask an administrator to invite you."
MFA_AMR_VALUES = {"otp", "recovery", "webauthn"}
TRUSTED_DEVICE_AMR = "trusted_device"
DEFAULT_ORG_ROLES = [
    ("owner", ["*"]),
    ("admin", ["admin:*", "auth:*", "mcp:*"]),
    ("operator", ["auth:read", "token:*", "mcp:*"]),
    ("viewer", ["auth:read"]),
]
# OIDC identity scopes carry no permissions, so role capping lets them through.
IDENTITY_SCOPES = {"openid", "profile", "email", "offline_access"}
# Self-service baseline for sessions that are not bound to an organization.
BASELINE_PERMISSIONS = ["auth:read"]
PRIVILEGED_ROLES = {"owner", "admin", "operator"}
SECURITY_ALERT_SUBJECTS = {
    "user.create": "User created",
    "org.create": "Organization created",
    "client.create": "OAuth client created",
    "client.update": "OAuth client updated",
    "client.secret.rotate": "OAuth client secret rotated",
    "mfa.totp.disable": "Authenticator MFA disabled",
    "user.mfa.totp.reset": "Authenticator MFA reset by an admin",
    "mfa.passkey.revoke": "Passkey removed",
    "mfa.totp.enable": "Authenticator MFA added",
    "mfa.passkey.register": "Passkey added",
    "auth.signup.refused": "Signup refused",
    "auth.email_code.refused": "Email code refused",
    "auth.invitation.refused": "Invitation signup refused",
    "auth.oauth.signup.refused": "Federated signup refused",
    "auth.login.new_ip": "Privileged login from a new IP",
    "org.owner.missing": "Bootstrap organization has no owner",
    "org.owner.bootstrap": "Bootstrap owner set by an operator",
}
ROLE_ALERT_ACTIONS = {
    "user.membership.update",
    "user.provision",
    "invitation.accept",
    "scim.user.upsert",
    "scim.user.replace",
    "scim.user.patch",
}
# Only these audit detail keys are copied into alert emails, so secrets never leave the database.
ALERT_DETAIL_KEYS = (
    "email",
    "role",
    "roles",
    "scopes",
    "token_type",
    "client_id",
    "audiences",
    "public",
    "provider",
    "purpose",
    "signup_mode",
)


def amr_satisfies_mfa(amr: list[str] | None) -> bool:
    return bool(set(amr or []).intersection(MFA_AMR_VALUES))


async def active_passkey_count(db: AsyncSession, user_id: str) -> int:
    result = await db.execute(
        select(func.count(WebAuthnCredential.id)).where(
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.credential_id.is_not(None),
            WebAuthnCredential.revoked_at.is_(None),
        )
    )
    return int(result.scalar_one() or 0)


async def user_has_mfa(db: AsyncSession, user: User) -> bool:
    return bool(user.mfa_totp_enabled_at) or await active_passkey_count(db, user.id) > 0


def session_trusted_device_active(session: Session) -> bool:
    return bool(session.trusted_at and (not session.trusted_until or session.trusted_until > now_utc()))


def trusted_device_mfa_bypass_allowed(client: AuthClient | None, org: Organization | None) -> bool:
    client_requires_mfa = bool(client and client.require_mfa)
    org_requires_mfa = bool(org and org.require_mfa)
    if not client_requires_mfa and not org_requires_mfa:
        return False
    if client_requires_mfa and not client.trusted_device_mfa_bypass:
        return False
    if org_requires_mfa and not org.trusted_device_mfa_bypass:
        return False
    return True


def scope_granted(scope: str, permissions: list[str]) -> bool:
    granted = set(permissions)
    if scope in IDENTITY_SCOPES or "*" in granted or scope in granted:
        return True
    prefix, separator, _rest = scope.partition(":")
    return bool(separator) and f"{prefix}:*" in granted


def cap_scopes(requested: list[str], permissions: list[str]) -> list[str]:
    return [scope for scope in dict.fromkeys(requested) if scope_granted(scope, permissions)]


def capped_session_scopes(requested: list[str], selected_org: OrgRead | None) -> list[str]:
    permissions = (selected_org.permissions or []) if selected_org else BASELINE_PERMISSIONS
    return cap_scopes(requested, permissions) or cap_scopes(BASELINE_PERMISSIONS, permissions)


async def effective_api_token_scopes(db: AsyncSession, token: ApiToken) -> list[str] | None:
    """Scopes a user-owned API token may use now: its stored scopes capped to the owner's current role in the token's
    org (the self-service baseline when it has no org). None when the owner is no longer an active member there."""
    if not token.user_id:
        return list(token.scopes or [])
    if not token.org_id:
        return cap_scopes(token.scopes or [], BASELINE_PERMISSIONS)
    result = await db.execute(
        select(Role.permissions)
        .join(Membership, Membership.role_id == Role.id)
        .where(Membership.user_id == token.user_id, Membership.org_id == token.org_id, Membership.status == "active")
    )
    row = result.first()
    return None if row is None else cap_scopes(token.scopes or [], row[0] or [])


def derive_membership_scopes(memberships: list[OrgRead], org_id: str | None = None) -> list[str]:
    selected_org = next((org for org in memberships if org.id == org_id), None) if org_id else None
    derived_scopes = set(selected_org.permissions if selected_org else [])
    if not derived_scopes:
        derived_scopes = {permission for org in memberships for permission in org.permissions}
    return sorted(derived_scopes or {"auth:read"})


def _trusted_proxy(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in settings.trusted_proxy_networks)


def client_ip(request: Request | None) -> str | None:
    """Real client IP. X-Forwarded-For counts only when the TCP peer is a trusted proxy, and then the
    rightmost entry that is not itself a trusted proxy wins, so client-supplied entries are ignored.
    CF-Connecting-IP is never trusted."""
    if not request or not request.client:
        return None
    peer = request.client.host
    try:
        if not _trusted_proxy(ipaddress.ip_address(peer)):
            return peer
    except ValueError:
        return peer
    entries = [item.strip() for item in request.headers.get("x-forwarded-for", "").split(",") if item.strip()]
    for entry in reversed(entries):
        try:
            address = ipaddress.ip_address(entry)
        except ValueError:
            return peer
        if not _trusted_proxy(address):
            return str(address)
    return entries[0] if entries else peer


def security_alert_subject(action: str, details: dict[str, Any]) -> str | None:
    if action in SECURITY_ALERT_SUBJECTS:
        return SECURITY_ALERT_SUBJECTS[action]
    if action == "user.provision" and details.get("created_user"):
        return "User created"
    role = details.get("role")
    if action in ROLE_ALERT_ACTIONS and role in PRIVILEGED_ROLES and details.get("membership_changed", True):
        return f"Role set to {role}"
    group = details.get("display_name")
    if action.startswith("scim.group.") and group in PRIVILEGED_ROLES and details.get("changed_members"):
        return f"Role set to {group}"
    if action in {"token.create", "token.rotate"} and set(details.get("scopes") or []) - {"auth:read"}:
        return "API token created"
    return None


async def queue_security_alert(db: AsyncSession, event: AuditEvent, subject: str) -> None:
    actor = await db.get(User, event.actor_user_id) if event.actor_user_id else None
    now = now_utc()
    key = f"gatekeeper-{event.id}"
    if event.action.endswith(".refused"):
        # One email per source IP per hour, however many attempts it makes.
        key = f"gatekeeper-{event.action}-{event.ip_address or 'unknown'}-{now:%Y%m%d%H}"
    lines = [
        f"Action: {event.action}",
        f"Actor: {actor.email if actor else 'none'}",
        f"Target: {event.target_type or '-'} {event.target_id or ''}".rstrip(),
        f"Organization: {event.org_id or '-'}",
        f"Client IP: {event.ip_address or 'unknown'}",
        f"Time (UTC): {now:%Y-%m-%d %H:%M:%S}",
    ]
    for detail_key in ALERT_DETAIL_KEYS:
        value = (event.details or {}).get(detail_key)
        if value not in (None, "", []):
            lines.append(f"{detail_key}: {', '.join(map(str, value)) if isinstance(value, list) else value}")
    send_security_alert(subject, lines, key)


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
    event = AuditEvent(
        id=uuid_str(),
        org_id=org_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=client_ip(request),
        details=details or {},
    )
    db.add(event)
    subject = security_alert_subject(action, details or {})
    if subject:
        await queue_security_alert(db, event, subject)


async def enforce_rate_limit(
    db: AsyncSession,
    *,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    now = now_utc()
    cutoff = now - timedelta(seconds=window_seconds)
    active = await db.execute(
        update(RateLimitBucket)
        .where(
            RateLimitBucket.key == key,
            RateLimitBucket.window_start > cutoff,
        )
        .values(count=RateLimitBucket.count + 1)
        .returning(RateLimitBucket.count)
    )
    count = active.scalar_one_or_none()
    if count is None:
        reset = await db.execute(
            update(RateLimitBucket)
            .where(
                RateLimitBucket.key == key,
                RateLimitBucket.window_start <= cutoff,
            )
            .values(count=1, window_start=now)
            .returning(RateLimitBucket.count)
        )
        count = reset.scalar_one_or_none()
    if count is None:
        db.add(RateLimitBucket(key=key, count=1, window_start=now))
        try:
            await db.commit()
            return
        except IntegrityError:
            await db.rollback()
            await enforce_rate_limit(
                db,
                key=key,
                limit=limit,
                window_seconds=window_seconds,
            )
            return
    await db.commit()
    if count > limit:
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


def send_invitation_email(*, email: str, token: str, org_name: str, role_name: str) -> None:
    if not settings.smtp_host:
        if settings.email_dev_mode:
            return
        raise HTTPException(status_code=503, detail="SMTP is not configured")

    accept_url = f"{settings.ui_url.rstrip('/')}/accept-invite?token={token}"
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = email
    message["Subject"] = f"GateKeeper invitation to {org_name}"
    message.set_content(
        f"You have been invited to {org_name} as {role_name}.\n\n"
        f"Accept the invitation:\n{accept_url}\n\n"
        "If your product owns the auth UI, paste this invitation token into that flow:\n"
        f"{token}\n"
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
        await report_missing_bootstrap_owner(db, org)
        await db.commit()
        return org

    org = Organization(name=settings.bootstrap_org_name, slug=settings.bootstrap_org_slug)
    db.add(org)
    await db.flush()
    await add_default_org_roles(db, org)
    await audit(db, "org.bootstrap", org_id=org.id, target_type="organization", target_id=org.id)
    await ensure_default_clients(db, org)
    await report_missing_bootstrap_owner(db, org)
    await db.commit()
    return org


async def add_default_org_roles(db: AsyncSession, org: Organization) -> dict[str, Role]:
    roles = {
        name: Role(org_id=org.id, name=name, permissions=permissions)
        for name, permissions in DEFAULT_ORG_ROLES
    }
    db.add_all(roles.values())
    await db.flush()
    return roles


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


async def report_missing_bootstrap_owner(db: AsyncSession, org: Organization) -> None:
    """Never promote anyone automatically. An ownerless bootstrap org with members is an incident
    for an operator to resolve with `python -m app.ops bootstrap-owner --email ...`."""
    if await org_has_owner(db, org.id):
        return
    member = await db.execute(
        select(Membership.id).where(Membership.org_id == org.id, Membership.status == "active").limit(1)
    )
    if member.scalar_one_or_none() is None:
        return
    logger.warning(
        "Bootstrap organization %s has active members but no active owner; "
        "run python -m app.ops bootstrap-owner --email <owner email>",
        org.slug,
    )
    await audit(db, "org.owner.missing", org_id=org.id, target_type="organization", target_id=org.id)


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
            require_mfa=org.require_mfa,
            trusted_device_mfa_bypass=org.trusted_device_mfa_bypass,
            admin_step_up_mfa_required=org.admin_step_up_mfa_required,
            session_idle_timeout_minutes=org.session_idle_timeout_minutes,
            audit_retention_days=org.audit_retention_days,
            allow_user_hard_delete=org.allow_user_hard_delete,
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
    first_user = (await db.execute(select(User.id).limit(1))).scalar_one_or_none() is None
    user = User(
        email=normalized,
        display_name=display_name,
        password_hash=hash_password(password) if password else None,
        email_verified=verified,
    )
    db.add(user)
    await db.flush()
    if first_user:
        # The primary key lets exactly one concurrent signup claim the empty install.
        db.add(InstallClaim(name="first-owner", user_id=user.id))
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=403, detail=SIGNUP_CLOSED_DETAIL) from None

    # New accounts get no organization by default. Only the first owner of an empty install, or the
    # configured bootstrap admin while the bootstrap org has no owner, joins the bootstrap org.
    bootstrap_org_id = None
    if first_user or normalized == str(settings.bootstrap_admin_email).lower():
        bootstrap_org = await ensure_bootstrap(db)
        if first_user or not await org_has_owner(db, bootstrap_org.id):
            result = await db.execute(select(Role).where(Role.org_id == bootstrap_org.id, Role.name == "owner"))
            role = result.scalar_one()
            db.add(Membership(org_id=bootstrap_org.id, user_id=user.id, role_id=role.id, status="active"))
            bootstrap_org_id = bootstrap_org.id
    await audit(
        db,
        "user.create",
        org_id=bootstrap_org_id,
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"role": "owner" if bootstrap_org_id else None, "first_owner": first_user},
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
    bind_default_org: bool = True,
    amr: list[str] | None = None,
    device_id_hash: str | None = None,
    trusted_at=None,
    trusted_until=None,
) -> tuple[str, str, Session, RefreshToken, list[str]]:
    memberships = await org_roles(db, user.id)
    if org_id is None and bind_default_org:
        org_id = memberships[0].id if memberships else None
    selected_org = next((org for org in memberships if org.id == org_id), None) if org_id else None
    if org_id and not selected_org:
        raise HTTPException(status_code=403, detail="Organization membership required")
    if scopes is None:
        scopes = derive_membership_scopes(memberships, org_id)
    scopes = capped_session_scopes(scopes, selected_org)
    audience = audience or (client_default_audience(client) if client else settings.issuer)
    login_ip = client_ip(request)
    privileged_roles = sorted({org.role for org in memberships if org.role in PRIVILEGED_ROLES})
    if login_ip and privileged_roles:
        seen = await db.execute(
            select(Session.id)
            .where(
                Session.user_id == user.id,
                Session.ip_address == login_ip,
                Session.created_at >= now_utc() - timedelta(days=30),
            )
            .limit(1)
        )
        if seen.scalar_one_or_none() is None:
            await audit(
                db,
                "auth.login.new_ip",
                org_id=org_id,
                actor_user_id=user.id,
                target_type="user",
                target_id=user.id,
                details={"roles": privileged_roles},
                request=request,
            )
    session_secret = new_opaque_token("gks")
    refresh_secret = new_opaque_token("gkr")
    issued_at = now_utc()
    session = Session(
        user_id=user.id,
        org_id=org_id,
        client_id=client.id if client else None,
        token_hash=token_hash(session_secret),
        device_id_hash=device_id_hash,
        ip_address=login_ip,
        user_agent=request.headers.get("user-agent") if request else None,
        amr=list(amr or []),
        scopes=scopes,
        audience=audience or settings.issuer,
        trusted_at=trusted_at,
        trusted_until=trusted_until,
        last_seen_at=issued_at,
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
    extra_claims: dict[str, Any] = {
        "email": user.email,
        "display_name": user.display_name,
        "email_verified": user.email_verified,
        "session_id": session.id,
        "mfa_totp_enabled": bool(user.mfa_totp_enabled_at),
        "mfa_passkey_enabled": await active_passkey_count(db, user.id) > 0,
    }
    if amr:
        extra_claims["amr"] = amr
    extra_claims["roles"] = [selected_org.role] if selected_org and selected_org.role else []
    if selected_org:
        extra_claims.update(
            {
                "org_slug": selected_org.slug,
                "org_role": selected_org.role,
                "permissions": selected_org.permissions or [],
            }
        )
    access = create_access_token(
        subject=user.id,
        audience=audience or settings.issuer,
        scopes=scopes,
        token_type="user",
        client_id=client.client_id if client else None,
        org_id=org_id,
        extra=extra_claims,
    )
    return access, refresh_secret, session, refresh, scopes


async def revoke_session_with_refresh_tokens(
    db: AsyncSession,
    session: Session,
    *,
    revoked_at=None,
) -> None:
    session.revoked_at = session.revoked_at or revoked_at or now_utc()
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.session_id == session.id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    for refresh in result.scalars():
        refresh.revoked_at = refresh.revoked_at or session.revoked_at


async def effective_session_idle_timeout_minutes(
    db: AsyncSession,
    *,
    session: Session,
    client: AuthClient | None = None,
) -> int | None:
    candidate_values: list[int] = []
    if client and client.session_idle_timeout_minutes:
        candidate_values.append(client.session_idle_timeout_minutes)
    policy_org_id = session.org_id or (client.org_id if client else None)
    if policy_org_id:
        org = await db.get(Organization, policy_org_id)
        if org and org.session_idle_timeout_minutes:
            candidate_values.append(org.session_idle_timeout_minutes)
    return min(candidate_values) if candidate_values else None


async def enforce_session_idle_timeout(
    db: AsyncSession,
    *,
    session: Session,
    client: AuthClient | None = None,
    commit_on_expire: bool = False,
) -> None:
    timeout_minutes = await effective_session_idle_timeout_minutes(db, session=session, client=client)
    now = now_utc()
    last_seen_at = session.last_seen_at or session.created_at or now
    if timeout_minutes and last_seen_at <= now - timedelta(minutes=timeout_minutes):
        await revoke_session_with_refresh_tokens(db, session, revoked_at=now)
        if commit_on_expire:
            await db.commit()
        raise HTTPException(status_code=401, detail="Session idle timeout expired")
    session.last_seen_at = now


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
    if not session or session.revoked_at or session.expires_at <= now_utc():
        refresh.revoked_at = refresh.revoked_at or now_utc()
        await db.commit()
        raise HTTPException(status_code=401, detail="Session revoked or expired")
    await enforce_session_idle_timeout(db, session=session, client=client, commit_on_expire=True)
    org_id = session.org_id
    selected_org = next((org for org in memberships if org.id == org_id), None) if org_id else None
    if org_id and not selected_org:
        session.revoked_at = session.revoked_at or now_utc()
        refresh.revoked_at = refresh.revoked_at or session.revoked_at
        await db.commit()
        raise HTTPException(status_code=401, detail="Organization membership required")
    policy_org_id = org_id or (client.org_id if client else None)
    policy_org = await db.get(Organization, policy_org_id) if policy_org_id else None
    if client and (client.require_mfa or (policy_org and policy_org.require_mfa)):
        trusted_device_ok = (
            TRUSTED_DEVICE_AMR in (session.amr or [])
            and session_trusted_device_active(session)
            and trusted_device_mfa_bypass_allowed(client, policy_org)
        )
        if not await user_has_mfa(db, user) or (
            not amr_satisfies_mfa(session.amr) and not trusted_device_ok
        ):
            session.revoked_at = session.revoked_at or now_utc()
            refresh.revoked_at = refresh.revoked_at or session.revoked_at
            await db.commit()
            raise HTTPException(status_code=401, detail="MFA required for this session")
    if session.scopes is not None:
        requested_scopes = list(session.scopes)
    else:  # sessions created before scopes were stored
        requested_scopes = list(client.scopes or []) if client else derive_membership_scopes(memberships, org_id)
    scopes = capped_session_scopes(requested_scopes, selected_org)
    audience = session.audience or (client_default_audience(client) if client else settings.issuer)
    # Only the hosted UI's own logins (they always carry a device cookie hash) keep the issuer audience for a
    # client. Code and device flow sessions never store one, so an app session stored with the issuer is narrowed.
    if client and audience == settings.issuer and not session.device_id_hash:
        audience = client_default_audience(client)
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
    extra_claims: dict[str, Any] = {
        "email": user.email,
        "display_name": user.display_name,
        "email_verified": user.email_verified,
        "session_id": session.id,
        "mfa_totp_enabled": bool(user.mfa_totp_enabled_at),
        "mfa_passkey_enabled": await active_passkey_count(db, user.id) > 0,
    }
    if session.amr:
        extra_claims["amr"] = session.amr
    extra_claims["roles"] = [selected_org.role] if selected_org and selected_org.role else []
    if selected_org:
        extra_claims.update(
            {
                "org_slug": selected_org.slug,
                "org_role": selected_org.role,
                "permissions": selected_org.permissions or [],
            }
        )
    access = create_access_token(
        subject=user.id,
        audience=audience,
        scopes=scopes,
        token_type="user",
        client_id=client.client_id if client else None,
        org_id=org_id,
        extra=extra_claims,
    )
    await db.commit()
    return access, new_refresh_secret, user, scopes


def user_read(user: User) -> UserRead:
    return UserRead(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        email_verified=user.email_verified,
        mfa_totp_enabled=bool(user.mfa_totp_enabled_at),
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


def client_default_audience(client: AuthClient) -> list[str] | str:
    """Audience for a client's tokens when none was asked for. Never the issuer: that audience marks hosted
    GateKeeper sessions, which alone may authorize apps and switch orgs."""
    return list(client.audiences or []) or client.mcp_resource_uri or settings.gatekeeper_api_audience


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
