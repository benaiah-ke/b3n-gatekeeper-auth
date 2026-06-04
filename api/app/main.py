from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode, urlparse

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from jose import JWTError, jwt
from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import OAuthProviderConfig, settings
from app.database import Base, async_session_factory, engine, get_db
from app.deps import Principal, current_principal, optional_principal, require_scopes
from app.models import (
    ApiToken,
    AuditEvent,
    AuthClient,
    DeviceGrant,
    Identity,
    Invitation,
    McpResource,
    Membership,
    MfaRecoveryCode,
    OAuthAuthorizationCode,
    OAuthGrant,
    OAuthProvider,
    OneTimeCode,
    Organization,
    Project,
    RefreshToken,
    Role,
    Session,
    User,
    WebAuthnCredential,
    Workspace,
)
from app.schemas import (
    AccountDeactivateRequest,
    AccountDeactivateResponse,
    AuditPruneRequest,
    AuditPruneResponse,
    AuditRead,
    ClientCreate,
    ClientRead,
    ClientUpdate,
    CurrentUserUpdate,
    DeviceAuthorizationRequest,
    DeviceAuthorizeApprove,
    EmailChangeConfirm,
    EmailChangeRequest,
    EmailChangeResponse,
    EmailCodeRequest,
    EmailCodeVerify,
    IdentityRead,
    InvitationAcceptRequest,
    InvitationCreate,
    InvitationCreateResponse,
    InvitationRead,
    LoginRequest,
    McpResourceCreate,
    MfaRecoveryCodesRead,
    MfaStatusRead,
    OAuthAuthorizeRequest,
    OAuthGrantRead,
    OAuthProviderAdminCreate,
    OAuthProviderAdminRead,
    OAuthProviderAdminUpdate,
    OAuthProviderRead,
    OrgCreate,
    OrgRead,
    OrgSwitchRequest,
    OrgUpdate,
    PasswordChangeRequest,
    PasswordChangeResponse,
    PasswordResetConfirm,
    ProjectCreate,
    ProjectRead,
    RefreshRequest,
    RoleCreate,
    RoleRead,
    SessionDeviceUpdate,
    SessionRead,
    SessionRevokeAllRequest,
    SessionRevokeAllResponse,
    SetupStatusRead,
    SignupRequest,
    TokenCreate,
    TokenRead,
    TokenResponse,
    TokenValidateRequest,
    TokenValidateResponse,
    TotpEnableRead,
    TotpSetupRead,
    TotpVerifyRequest,
    UserAdminRead,
    UserAdminUpdate,
    UserDeleteRequest,
    UserDeleteResponse,
    UserMembershipUpdate,
    UserMfaResetResponse,
    UserProvisionRequest,
    UserProvisionResponse,
    UserRead,
    UserSessionsRevokeResponse,
    WorkspaceCreate,
    WorkspaceRead,
)
from app.security import (
    create_access_token,
    decode_access_token,
    decrypt_mfa_secret,
    decrypt_secret,
    encrypt_mfa_secret,
    encrypt_secret,
    hash_password,
    new_code,
    new_opaque_token,
    new_recovery_code,
    new_totp_secret,
    normalize_recovery_code,
    now_utc,
    public_jwk,
    token_hash,
    token_hint,
    utc_after,
    verify_password,
    verify_pkce,
    verify_totp_code,
)
from app.services import (
    add_default_org_roles,
    audit,
    authenticate_password,
    create_api_token,
    create_one_time_code,
    create_session_tokens,
    create_user,
    derive_membership_scopes,
    enforce_rate_limit,
    enforce_session_idle_timeout,
    ensure_bootstrap,
    get_client_by_client_id,
    org_has_owner,
    org_roles,
    rotate_refresh_token,
    send_invitation_email,
    send_one_time_code,
    user_read,
    validate_audience,
    validate_redirect,
    validate_scopes,
    verify_one_time_code,
)

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("gatekeeper")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting GateKeeper API (env=%s)", settings.app_env)
    if settings.app_env in {"development", "test"}:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    async with async_session_factory() as db:
        await ensure_bootstrap(db)
    yield
    await engine.dispose()
    logger.info("GateKeeper API stopped")


app = FastAPI(
    title="GateKeeper API",
    description="API-first self-hostable auth platform",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def session_cookie_options() -> dict[str, object]:
    options: dict[str, object] = {
        "httponly": True,
        "secure": settings.cookie_secure,
        "samesite": "lax",
    }
    if settings.cookie_domain:
        options["domain"] = settings.cookie_domain
    return options


def set_session_cookie(response: Response, access_token: str) -> None:
    response.set_cookie(settings.cookie_name, access_token, **session_cookie_options())


def set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        settings.refresh_cookie_name,
        refresh_token,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
        **session_cookie_options(),
    )


def set_device_cookie(response: Response, device_id: str) -> None:
    response.set_cookie(
        settings.device_cookie_name,
        device_id,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
        **session_cookie_options(),
    )


def delete_session_cookie(response: Response) -> None:
    kwargs: dict[str, object] = {}
    if settings.cookie_domain:
        kwargs["domain"] = settings.cookie_domain
    response.delete_cookie(settings.cookie_name, **kwargs)


def delete_refresh_cookie(response: Response) -> None:
    kwargs: dict[str, object] = {}
    if settings.cookie_domain:
        kwargs["domain"] = settings.cookie_domain
    response.delete_cookie(settings.refresh_cookie_name, **kwargs)
    response.delete_cookie("gk_refresh_hint", **kwargs)


def oauth_authorize_query(request: Request, *, approve: bool | None = None) -> str:
    params = dict(request.query_params)
    if approve is None:
        params.pop("approve", None)
    else:
        params["approve"] = "true" if approve else "false"
    return urlencode(params)


def oauth_authorize_path(request: Request) -> str:
    query = oauth_authorize_query(request)
    return f"{request.url.path}?{query}" if query else request.url.path


async def resolve_authorize_org(
    db: AsyncSession,
    *,
    client: AuthClient,
    principal: Principal,
    org_id: str | None,
) -> tuple[OrgRead | None, list[OrgRead]]:
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound authorization required")
    orgs = await org_roles(db, principal.user_id)
    selected_org = None
    if client.require_org_membership and client.org_id:
        if org_id and org_id != client.org_id:
            raise HTTPException(status_code=403, detail="Client is bound to another organization")
        selected_org = next((org for org in orgs if org.id == client.org_id), None)
    elif org_id:
        selected_org = next((org for org in orgs if org.id == org_id), None)
        if not selected_org:
            raise HTTPException(status_code=403, detail="Organization membership required")
    elif client.require_org_membership:
        selected_org = orgs[0] if orgs else None
    if client.require_org_membership and not selected_org:
        raise HTTPException(status_code=403, detail="Organization membership required")
    return selected_org, orgs


async def find_oauth_grant(
    db: AsyncSession,
    *,
    user_id: str,
    client: AuthClient,
    org_id: str | None,
    audience: str | None,
    scopes: list[str],
) -> OAuthGrant | None:
    query = select(OAuthGrant).where(
        OAuthGrant.user_id == user_id,
        OAuthGrant.client_id == client.id,
        OAuthGrant.revoked_at.is_(None),
    )
    query = query.where(OAuthGrant.org_id == org_id) if org_id else query.where(OAuthGrant.org_id.is_(None))
    query = query.where(OAuthGrant.audience == audience) if audience else query.where(OAuthGrant.audience.is_(None))
    result = await db.execute(query.order_by(OAuthGrant.updated_at.desc()))
    requested = set(scopes)
    return next((grant for grant in result.scalars() if requested.issubset(set(grant.scopes or []))), None)


async def remember_oauth_grant(
    db: AsyncSession,
    *,
    user_id: str,
    client: AuthClient,
    org_id: str | None,
    audience: str | None,
    scopes: list[str],
) -> OAuthGrant:
    query = select(OAuthGrant).where(
        OAuthGrant.user_id == user_id,
        OAuthGrant.client_id == client.id,
        OAuthGrant.revoked_at.is_(None),
    )
    query = query.where(OAuthGrant.org_id == org_id) if org_id else query.where(OAuthGrant.org_id.is_(None))
    query = query.where(OAuthGrant.audience == audience) if audience else query.where(OAuthGrant.audience.is_(None))
    result = await db.execute(query.order_by(OAuthGrant.updated_at.desc()))
    grant = result.scalars().first()
    authorized_at = now_utc()
    if grant:
        grant.scopes = sorted(set(grant.scopes or []).union(scopes))
        grant.last_authorized_at = authorized_at
        return grant
    grant = OAuthGrant(
        client_id=client.id,
        user_id=user_id,
        org_id=org_id,
        audience=audience,
        scopes=sorted(set(scopes)),
        last_authorized_at=authorized_at,
    )
    db.add(grant)
    await db.flush()
    return grant


async def issue_oauth_authorization_code(
    db: AsyncSession,
    *,
    request: Request,
    client: AuthClient,
    user_id: str,
    org_id: str | None,
    redirect_uri: str,
    scopes: list[str],
    audience: str | None,
    code_challenge: str,
    code_challenge_method: str,
    amr: list[str],
    state: str | None,
) -> RedirectResponse:
    code = new_opaque_token("gkc")
    db.add(
        OAuthAuthorizationCode(
            code_hash=token_hash(code),
            client_id=client.id,
            user_id=user_id,
            org_id=org_id,
            redirect_uri=redirect_uri,
            scope=" ".join(scopes),
            audience=audience,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            amr=list(amr),
            expires_at=utc_after(minutes=10),
        )
    )
    await audit(
        db,
        "oauth.code.issue",
        org_id=org_id,
        actor_user_id=user_id,
        target_type="client",
        target_id=client.id,
        request=request,
    )
    await db.commit()
    query = {"code": code}
    if state:
        query["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(query)}", status_code=302)


def has_capability(values: list[str], *accepted: str) -> bool:
    value_set = set(values)
    if "*" in value_set:
        return True
    return any(value in value_set for value in accepted)


def totp_otpauth_uri(user: User, secret: str) -> str:
    issuer = "GateKeeper"
    label = f"{issuer}:{user.email}"
    return "otpauth://totp/{label}?{query}".format(
        label=quote(label),
        query=urlencode(
            {
                "secret": secret,
                "issuer": issuer,
                "algorithm": "SHA1",
                "digits": "6",
                "period": "30",
            }
        ),
    )


def decrypted_totp_secret(user: User) -> str:
    if not user.mfa_totp_secret_encrypted:
        raise HTTPException(status_code=400, detail="TOTP is not configured")
    try:
        return decrypt_mfa_secret(user.mfa_totp_secret_encrypted)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="TOTP secret cannot be decrypted") from exc


def verify_user_totp(user: User, code: str) -> None:
    if not verify_totp_code(decrypted_totp_secret(user), code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")


RECOVERY_CODE_COUNT = 10


def recovery_code_digest(code: str) -> str:
    return token_hash(normalize_recovery_code(code))


async def recovery_codes_remaining(db: AsyncSession, user_id: str) -> int:
    result = await db.execute(
        select(func.count(MfaRecoveryCode.id)).where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    return int(result.scalar_one() or 0)


async def retire_recovery_codes(db: AsyncSession, user_id: str) -> None:
    result = await db.execute(
        select(MfaRecoveryCode).where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    retired_at = now_utc()
    for code in result.scalars():
        code.used_at = retired_at


async def issue_recovery_codes(db: AsyncSession, user: User) -> list[str]:
    await retire_recovery_codes(db, user.id)
    raw_codes = [new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    for raw_code in raw_codes:
        db.add(
            MfaRecoveryCode(
                user_id=user.id,
                code_hash=recovery_code_digest(raw_code),
                code_hint=normalize_recovery_code(raw_code)[-4:],
            )
        )
    return raw_codes


async def verify_user_recovery_code(db: AsyncSession, user: User, code: str) -> None:
    normalized = normalize_recovery_code(code)
    if len(normalized) < 8:
        raise HTTPException(status_code=401, detail="Invalid recovery code")
    result = await db.execute(
        select(MfaRecoveryCode).where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.code_hash == token_hash(normalized),
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    recovery_code = result.scalar_one_or_none()
    if not recovery_code:
        raise HTTPException(status_code=401, detail="Invalid recovery code")
    recovery_code.used_at = now_utc()


MFA_AMR_VALUES = {"otp", "recovery"}
TRUSTED_DEVICE_AMR = "trusted_device"


def amr_satisfies_mfa(amr: list[str] | None) -> bool:
    return bool(set(amr or []).intersection(MFA_AMR_VALUES))


def principal_amr(principal: Principal) -> list[str]:
    claims = principal.claims or {}
    value = claims.get("amr")
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def trusted_session_active(session: Session | None) -> bool:
    return bool(session and session.trusted_at and (not session.trusted_until or session.trusted_until > now_utc()))


def current_or_new_device_id(request: Request) -> str:
    return request.cookies.get(settings.device_cookie_name) or new_opaque_token("gkdv")


async def trusted_session_for_request(
    db: AsyncSession,
    *,
    request: Request,
    user: User,
    client: AuthClient | None,
    org_id: str | None,
) -> Session | None:
    device_id = request.cookies.get(settings.device_cookie_name)
    if not device_id:
        return None
    query = select(Session).where(
        Session.user_id == user.id,
        Session.device_id_hash == token_hash(device_id),
        Session.revoked_at.is_(None),
        Session.expires_at > now_utc(),
        Session.trusted_at.is_not(None),
    )
    if client:
        query = query.where(Session.client_id == client.id)
    if org_id:
        query = query.where(Session.org_id == org_id)
    query = query.order_by(Session.trusted_at.desc())
    result = await db.execute(query)
    for session in result.scalars():
        if trusted_session_active(session):
            return session
    return None


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


def enforce_mfa_policy(
    *,
    client: AuthClient | None,
    org: Organization | None,
    user: User,
    amr: list[str] | None,
    trusted_device: bool = False,
) -> None:
    client_requires_mfa = bool(client and client.require_mfa)
    org_requires_mfa = bool(org and org.require_mfa)
    if not client_requires_mfa and not org_requires_mfa:
        return
    if not user.mfa_totp_enabled_at:
        detail = (
            "MFA enrollment required for this client"
            if client_requires_mfa
            else "MFA enrollment required for this organization"
        )
        raise HTTPException(status_code=403, detail=detail)
    if not amr_satisfies_mfa(amr):
        if trusted_device and trusted_device_mfa_bypass_allowed(client, org):
            return
        detail = "MFA required for this client" if client_requires_mfa else "MFA required for this organization"
        raise HTTPException(status_code=403, detail=detail)


async def org_requires_mfa(db: AsyncSession, org_id: str | None) -> bool:
    if not org_id:
        return False
    org = await db.get(Organization, org_id)
    return bool(org and org.require_mfa)


async def effective_client_org_id(db: AsyncSession, *, client: AuthClient | None, user: User) -> str | None:
    if not client:
        return None
    if client.org_id:
        return client.org_id
    if client.require_org_membership:
        memberships = await org_roles(db, user.id)
        return memberships[0].id if memberships else None
    return None


async def enforce_client_and_org_mfa_policy(
    db: AsyncSession,
    *,
    client: AuthClient | None,
    org_id: str | None,
    user: User,
    amr: list[str] | None,
    trusted_device: bool = False,
) -> None:
    org = await db.get(Organization, org_id) if org_id else None
    enforce_mfa_policy(
        client=client,
        org=org,
        user=user,
        amr=amr,
        trusted_device=trusted_device,
    )


async def principal_trusted_device_active(db: AsyncSession, principal: Principal) -> bool:
    if TRUSTED_DEVICE_AMR not in principal_amr(principal) or not principal.session_id:
        return False
    session = await db.get(Session, principal.session_id)
    return trusted_session_active(session)


async def require_admin_step_up_for_org(
    db: AsyncSession,
    *,
    principal: Principal,
    org_id: str | None,
) -> None:
    if not org_id:
        return
    org = await db.get(Organization, org_id)
    if not org or not org.admin_step_up_mfa_required:
        return
    if principal.auth_type != "user" or not principal.user_id or not principal.session_id:
        raise HTTPException(status_code=403, detail="MFA step-up required for sensitive organization actions")
    user = await db.get(User, principal.user_id)
    if not user or not user.mfa_totp_enabled_at:
        raise HTTPException(status_code=403, detail="MFA enrollment required for sensitive organization actions")
    amr = principal_amr(principal)
    if amr_satisfies_mfa(amr):
        return
    session = await db.get(Session, principal.session_id)
    trusted_device_ok = (
        TRUSTED_DEVICE_AMR in amr
        and trusted_session_active(session)
        and org.trusted_device_mfa_bypass
    )
    if trusted_device_ok:
        return
    raise HTTPException(status_code=403, detail="MFA required for sensitive organization actions")


async def require_admin_step_up_for_orgs(
    db: AsyncSession,
    *,
    principal: Principal,
    org_ids: list[str | None] | None,
) -> None:
    for org_id in sorted({item for item in org_ids or [] if item}):
        await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)


def validate_url_list(values: list[str], *, field_name: str, origin_only: bool = False) -> list[str]:
    cleaned: list[str] = []
    for raw in values:
        value = raw.strip()
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPException(status_code=422, detail=f"{field_name} must be absolute http(s) URLs")
        if origin_only and (parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment):
            raise HTTPException(status_code=422, detail=f"{field_name} must be origins without paths")
        cleaned.append(value.rstrip("/") if origin_only else value)
    return cleaned


def validate_optional_url(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be an absolute http(s) URL")
    return cleaned


def normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    if request.url.path not in {"/health"}:
        logger.info("%s %s -> %d (%.0fms)", request.method, request.url.path, response.status_code, duration_ms)
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health")
async def health():
    checks = {"service": "gatekeeper-api"}
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "connected"
    except Exception:
        checks["database"] = "unreachable"
    checks["status"] = "ok" if checks["database"] == "connected" else "degraded"
    if checks["status"] != "ok":
        return JSONResponse(status_code=503, content=checks)
    return checks


@app.get("/version")
async def version():
    return {
        "service": "gatekeeper-api",
        "version": settings.app_version,
        "environment": settings.app_env,
        "issuer": settings.issuer,
    }


@app.get("/.well-known/openid-configuration")
@app.get("/.well-known/oauth-authorization-server")
async def openid_configuration():
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "introspection_endpoint": f"{issuer}/oauth/introspect",
        "device_authorization_endpoint": f"{issuer}/oauth/device_authorization",
        "jwks_uri": f"{issuer}/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "scopes_supported": ["openid", "profile", "email", "auth:read", "token:*", "mcp:tools", "mcp:resources"],
        "client_id_metadata_document_supported": True,
        "registration_endpoint": f"{issuer}/oauth/register"
        if settings.enable_dynamic_client_registration
        else None,
    }


@app.get("/oauth/jwks.json")
async def jwks():
    return {"keys": [public_jwk()]}


async def mcp_metadata_for(resource_path: str | None, db: AsyncSession):
    resource = f"{settings.issuer}/{resource_path.strip('/')}" if resource_path else settings.issuer
    result = await db.execute(select(McpResource).where(McpResource.resource_uri == resource))
    item = result.scalar_one_or_none()
    return {
        "resource": item.resource_uri if item else resource,
        "authorization_servers": [settings.issuer],
        "scopes_supported": item.scopes if item else settings.mcp_default_scope_list,
    }


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_root(db: AsyncSession = Depends(get_db)):
    return await mcp_metadata_for(None, db)


@app.get("/.well-known/oauth-protected-resource/{resource_path:path}")
async def oauth_protected_resource_path(resource_path: str, db: AsyncSession = Depends(get_db)):
    return await mcp_metadata_for(resource_path, db)


@app.post("/api/v1/auth/signup", response_model=TokenResponse)
async def signup(body: SignupRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    user = await create_user(
        db,
        email=str(body.email),
        password=body.password,
        display_name=body.display_name,
        verified=False,
    )
    device_id = current_or_new_device_id(request)
    access, refresh, _session, _refresh_model = await create_session_tokens(
        db,
        user,
        request=request,
        amr=["pwd"],
        device_id_hash=token_hash(device_id),
    )
    orgs = await org_roles(db, user.id)
    await db.commit()
    set_session_cookie(response, access)
    set_refresh_cookie(response, refresh)
    set_device_cookie(response, device_id)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(derive_membership_scopes(orgs)),
        user=user_read(user),
        orgs=orgs,
    )


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(
        db,
        key=f"login:{str(body.email).lower()}:{request.client.host if request.client else 'unknown'}",
        limit=10,
        window_seconds=300,
    )
    user = await authenticate_password(db, str(body.email), body.password)
    client = await get_client_by_client_id(db, body.client_id) if body.client_id else None
    amr = ["pwd"]
    effective_org_id = await effective_client_org_id(db, client=client, user=user)
    policy_org = await db.get(Organization, effective_org_id) if effective_org_id else None
    device_id = current_or_new_device_id(request)
    trusted_session = await trusted_session_for_request(
        db,
        request=request,
        user=user,
        client=client,
        org_id=effective_org_id if client and client.require_org_membership else None,
    )
    if user.mfa_totp_enabled_at:
        if body.totp_code:
            verify_user_totp(user, body.totp_code)
            amr.append("otp")
        elif body.recovery_code:
            await verify_user_recovery_code(db, user, body.recovery_code)
            amr.append("recovery")
        elif trusted_session and trusted_device_mfa_bypass_allowed(client, policy_org):
            amr.append(TRUSTED_DEVICE_AMR)
        else:
            raise HTTPException(status_code=401, detail="TOTP code required")
    await enforce_client_and_org_mfa_policy(
        db,
        client=client,
        org_id=effective_org_id,
        user=user,
        amr=amr,
        trusted_device=TRUSTED_DEVICE_AMR in amr,
    )
    orgs = await org_roles(db, user.id)
    scopes = validate_scopes(client, body.scope or "") if client else derive_membership_scopes(orgs, effective_org_id)
    selected_audience = validate_audience(client, body.audience) if client else None
    audience = selected_audience or (client.audiences[0] if client and client.audiences else settings.issuer)
    access, refresh, _session, _refresh_model = await create_session_tokens(
        db,
        user,
        request=request,
        client=client,
        org_id=effective_org_id if client and client.require_org_membership else None,
        scopes=scopes,
        audience=audience,
        amr=amr,
        device_id_hash=token_hash(device_id),
        trusted_at=trusted_session.trusted_at if TRUSTED_DEVICE_AMR in amr and trusted_session else None,
        trusted_until=trusted_session.trusted_until if TRUSTED_DEVICE_AMR in amr and trusted_session else None,
    )
    await audit(db, "auth.login", actor_user_id=user.id, request=request)
    await db.commit()
    set_session_cookie(response, access)
    set_refresh_cookie(response, refresh)
    set_device_cookie(response, device_id)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
        user=user_read(user),
        orgs=orgs,
    )


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    db: AsyncSession = Depends(get_db),
):
    raw_refresh_token = (body.refresh_token if body else None) or request.cookies.get(settings.refresh_cookie_name)
    if not raw_refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token required")
    access, refresh_token, user, scopes = await rotate_refresh_token(db, raw_refresh_token)
    memberships = await org_roles(db, user.id)
    set_session_cookie(response, access)
    set_refresh_cookie(response, refresh_token)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh_token,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
        user=user_read(user),
        orgs=memberships,
    )


@app.post("/api/v1/auth/session/switch-org", response_model=TokenResponse)
async def switch_session_org(
    body: OrgSwitchRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    memberships = await org_roles(db, user.id)
    selected_org = next((org for org in memberships if org.id == body.org_id), None)
    if not selected_org:
        raise HTTPException(status_code=403, detail="Organization membership required")

    client = await get_client_by_client_id(db, body.client_id) if body.client_id else None
    if client and client.org_id and client.org_id != selected_org.id:
        raise HTTPException(status_code=403, detail="Client is bound to another organization")

    if client:
        scopes = validate_scopes(client, body.scope or "")
        audience = validate_audience(client, body.audience) or (
            client.audiences[0] if client.audiences else settings.issuer
        )
    else:
        if body.audience and body.audience != settings.issuer:
            raise HTTPException(status_code=400, detail="client_id is required for custom audience")
        if body.scope:
            scopes = [item for item in body.scope.split() if item]
            allowed_scopes = set(selected_org.permissions or [])
            if "*" not in allowed_scopes and not set(scopes).issubset(allowed_scopes):
                raise HTTPException(status_code=400, detail="Invalid scope")
        else:
            scopes = derive_membership_scopes(memberships, selected_org.id)
        audience = settings.issuer

    amr = principal_amr(principal)
    await enforce_client_and_org_mfa_policy(
        db,
        client=client,
        org_id=selected_org.id,
        user=user,
        amr=amr,
        trusted_device=await principal_trusted_device_active(db, principal),
    )
    device_id = current_or_new_device_id(request)
    access, refresh_token, session, _refresh_model = await create_session_tokens(
        db,
        user,
        request=request,
        client=client,
        org_id=selected_org.id,
        scopes=scopes,
        audience=audience,
        bind_default_org=False,
        amr=amr,
        device_id_hash=token_hash(device_id),
    )
    revoked_previous_session = False
    if body.revoke_current_session and principal.session_id:
        current_session = await db.get(Session, principal.session_id)
        if current_session and current_session.user_id == user.id and current_session.id != session.id:
            current_session.revoked_at = current_session.revoked_at or now_utc()
            result = await db.execute(select(RefreshToken).where(RefreshToken.session_id == current_session.id))
            for refresh in result.scalars():
                refresh.revoked_at = refresh.revoked_at or current_session.revoked_at
            revoked_previous_session = True

    await audit(
        db,
        "auth.org.switch",
        org_id=selected_org.id,
        actor_user_id=user.id,
        target_type="session",
        target_id=session.id,
        details={
            "client_id": client.client_id if client else None,
            "previous_org_id": principal.org_id,
            "previous_session_revoked": revoked_previous_session,
        },
        request=request,
    )
    await db.commit()
    set_session_cookie(response, access)
    set_refresh_cookie(response, refresh_token)
    set_device_cookie(response, device_id)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh_token,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
        user=user_read(user),
        orgs=memberships,
    )


@app.post("/api/v1/auth/logout")
async def logout(
    response: Response,
    principal: Principal | None = Depends(optional_principal),
    db: AsyncSession = Depends(get_db),
):
    session_revoked = False
    if principal and principal.session_id:
        session = await db.get(Session, principal.session_id)
        if session and session.user_id == principal.user_id and not session.revoked_at:
            session.revoked_at = now_utc()
            result = await db.execute(
                select(RefreshToken).where(
                    RefreshToken.session_id == session.id,
                    RefreshToken.revoked_at.is_(None),
                )
            )
            for refresh in result.scalars():
                refresh.revoked_at = refresh.revoked_at or session.revoked_at
            await audit(
                db,
                "auth.logout",
                org_id=session.org_id,
                actor_user_id=principal.user_id,
                target_type="session",
                target_id=session.id,
            )
            await db.commit()
            session_revoked = True
    delete_session_cookie(response)
    delete_refresh_cookie(response)
    return {"status": "ok", "session_revoked": session_revoked}


@app.get("/api/v1/auth/me")
async def me(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, principal.user_id) if principal.user_id else None
    return {
        "subject": principal.subject,
        "auth_type": principal.auth_type,
        "scopes": principal.scopes,
        "org_id": principal.org_id,
        "user": user_read(user) if user else None,
    }


async def require_session_user(principal: Principal, db: AsyncSession) -> User:
    if principal.auth_type != "user" or not principal.user_id or not principal.session_id:
        raise HTTPException(status_code=403, detail="Session-bound user token required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def revoke_other_user_sessions(db: AsyncSession, *, user_id: str, current_session_id: str) -> int:
    revoked_at = now_utc()
    result = await db.execute(
        select(Session).where(
            Session.user_id == user_id,
            Session.id != current_session_id,
            Session.revoked_at.is_(None),
        )
    )
    session_ids: list[str] = []
    for session in result.scalars():
        session.revoked_at = revoked_at
        session_ids.append(session.id)
    if not session_ids:
        return 0
    refresh_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.session_id.in_(session_ids),
            RefreshToken.revoked_at.is_(None),
        )
    )
    for refresh in refresh_result.scalars():
        refresh.revoked_at = refresh.revoked_at or revoked_at
    return len(session_ids)


async def user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.strip().lower()))
    return result.scalar_one_or_none()


def audit_event_read(event: AuditEvent) -> AuditRead:
    return AuditRead(
        id=event.id,
        org_id=event.org_id,
        actor_user_id=event.actor_user_id,
        action=event.action,
        target_type=event.target_type,
        target_id=event.target_id,
        details=event.details or {},
        created_at=event.created_at,
    )


def identity_read(identity: Identity) -> IdentityRead:
    return IdentityRead(
        id=identity.id,
        provider=identity.provider,
        email=identity.email,
        created_at=identity.created_at,
        updated_at=identity.updated_at,
    )


async def count_user_identities(db: AsyncSession, user_id: str) -> int:
    result = await db.execute(select(func.count(Identity.id)).where(Identity.user_id == user_id))
    return int(result.scalar_one() or 0)


async def ensure_user_can_deactivate(db: AsyncSession, *, user_id: str) -> None:
    owner_memberships = await db.execute(
        select(Membership)
        .join(Role, Role.id == Membership.role_id)
        .where(
            Membership.user_id == user_id,
            Membership.status == "active",
            Role.name == "owner",
        )
    )
    for membership in owner_memberships.scalars():
        await ensure_other_active_owner(db, org_id=membership.org_id, user_id=user_id)


async def revoke_org_client_sessions_without_mfa(db: AsyncSession, *, org_id: str) -> int:
    revoked_at = now_utc()
    result = await db.execute(
        select(Session).where(
            Session.org_id == org_id,
            Session.client_id.is_not(None),
            Session.revoked_at.is_(None),
        )
    )
    revoked_session_ids: list[str] = []
    for session in result.scalars():
        if amr_satisfies_mfa(session.amr):
            continue
        session.revoked_at = revoked_at
        revoked_session_ids.append(session.id)
    if not revoked_session_ids:
        return 0
    refresh_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.session_id.in_(revoked_session_ids),
            RefreshToken.revoked_at.is_(None),
        )
    )
    for refresh in refresh_result.scalars():
        refresh.revoked_at = refresh.revoked_at or revoked_at
    return len(revoked_session_ids)


@app.patch("/api/v1/auth/me", response_model=UserRead)
async def update_me(
    body: CurrentUserUpdate,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    details = body.model_dump(exclude_unset=True)
    if "display_name" in body.model_fields_set:
        user.display_name = body.display_name.strip() or None if body.display_name is not None else None
    await audit(
        db,
        "user.profile.update",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details=details,
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return user_read(user)


@app.post("/api/v1/auth/password/change", response_model=PasswordChangeResponse)
async def change_password(
    body: PasswordChangeRequest,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid current password")
    user.password_hash = hash_password(body.new_password)
    revoked_count = 0
    if body.revoke_other_sessions and principal.session_id:
        revoked_count = await revoke_other_user_sessions(db, user_id=user.id, current_session_id=principal.session_id)
    await audit(
        db,
        "auth.password.change",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={
            "revoked_count": revoked_count,
            "revoke_other_sessions": body.revoke_other_sessions,
            "current_session_kept": True,
        },
        request=request,
    )
    await db.commit()
    return PasswordChangeResponse(status="updated", revoked_count=revoked_count, current_session_kept=True)


@app.post("/api/v1/auth/email/change/request")
async def request_email_change(
    body: EmailChangeRequest,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    new_email = str(body.new_email).strip().lower()
    if new_email == user.email:
        raise HTTPException(status_code=400, detail="New email must differ from the current email")
    if user.password_hash and not verify_password(body.current_password or "", user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid current password")
    if await user_by_email(db, new_email):
        raise HTTPException(status_code=409, detail="Email already exists")

    await enforce_rate_limit(
        db,
        key=f"email-change:{user.id}:{new_email}",
        limit=5,
        window_seconds=900,
    )
    code = await create_one_time_code(
        db,
        email=new_email,
        purpose="email_change",
        user_id=user.id,
    )
    send_one_time_code(email=new_email, code=code, purpose="email_change")
    await audit(
        db,
        "auth.email_change.request",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"new_email": new_email},
        request=request,
    )
    await db.commit()
    return {"status": "sent"}


@app.post("/api/v1/auth/email/change/confirm", response_model=EmailChangeResponse)
async def confirm_email_change(
    body: EmailChangeConfirm,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    new_email = str(body.new_email).strip().lower()
    if new_email == user.email:
        raise HTTPException(status_code=400, detail="New email must differ from the current email")
    if await user_by_email(db, new_email):
        raise HTTPException(status_code=409, detail="Email already exists")

    code = await verify_one_time_code(db, email=new_email, purpose="email_change", code=body.code)
    if code.user_id != user.id:
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    old_email = user.email
    user.email = new_email
    user.email_verified = True
    revoked_count = 0
    if body.revoke_other_sessions and principal.session_id:
        revoked_count = await revoke_other_user_sessions(db, user_id=user.id, current_session_id=principal.session_id)
    await audit(
        db,
        "auth.email_change.confirm",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={
            "old_email": old_email,
            "new_email": new_email,
            "revoked_count": revoked_count,
            "revoke_other_sessions": body.revoke_other_sessions,
            "current_session_kept": True,
        },
        request=request,
    )
    await db.commit()
    return EmailChangeResponse(
        status="updated",
        email=new_email,
        revoked_count=revoked_count,
        current_session_kept=True,
    )


@app.get("/api/v1/auth/identities", response_model=list[IdentityRead])
async def list_linked_identities(
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    result = await db.execute(select(Identity).where(Identity.user_id == user.id).order_by(Identity.created_at.desc()))
    return [identity_read(identity) for identity in result.scalars()]


@app.get("/api/v1/auth/identities/{provider_id}/link/start")
async def start_identity_link(
    provider_id: str,
    redirect: str | None = None,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    await require_session_user(principal, db)
    return await start_oauth_provider(db, provider_id, redirect, link_principal=principal)


@app.delete("/api/v1/auth/identities/{identity_id}")
async def unlink_identity(
    identity_id: str,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    identity = await db.get(Identity, identity_id)
    if not identity or identity.user_id != user.id:
        raise HTTPException(status_code=404, detail="Linked identity not found")
    if not user.password_hash and await count_user_identities(db, user.id) <= 1:
        raise HTTPException(status_code=400, detail="Cannot unlink the last sign-in method")
    target_id = identity.id
    provider = identity.provider
    email = identity.email
    await db.delete(identity)
    await audit(
        db,
        "auth.identity.unlink",
        actor_user_id=user.id,
        target_type="identity",
        target_id=target_id,
        details={"provider": provider, "email": email},
        request=request,
    )
    await db.commit()
    return {"status": "unlinked", "id": target_id}


@app.get("/api/v1/auth/account/export")
async def export_account(
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    memberships = await org_roles(db, user.id)
    session_result = await db.execute(
        select(Session, AuthClient)
        .join(AuthClient, AuthClient.id == Session.client_id, isouter=True)
        .where(Session.user_id == user.id)
        .order_by(Session.created_at.desc())
    )
    token_result = await db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    )
    grant_result = await db.execute(
        select(OAuthGrant, AuthClient)
        .join(AuthClient, AuthClient.id == OAuthGrant.client_id)
        .where(OAuthGrant.user_id == user.id)
        .order_by(OAuthGrant.created_at.desc())
    )
    identity_result = await db.execute(select(Identity).where(Identity.user_id == user.id))
    audit_result = await db.execute(
        select(AuditEvent)
        .where(AuditEvent.actor_user_id == user.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(100)
    )
    return {
        "exported_at": now_utc(),
        "user": user_read(user),
        "memberships": memberships,
        "mfa": {
            "totp_enabled": bool(user.mfa_totp_enabled_at),
            "totp_enabled_at": user.mfa_totp_enabled_at,
            "recovery_codes_remaining": await recovery_codes_remaining(db, user.id),
        },
        "sessions": [
            session_read(session, client=client, current_session_id=principal.session_id)
            for session, client in session_result.all()
        ],
        "api_tokens": [token_read(token) for token in token_result.scalars()],
        "oauth_grants": [oauth_grant_read(grant, client) for grant, client in grant_result.all()],
        "identities": [
            {
                "id": identity.id,
                "provider": identity.provider,
                "email": identity.email,
                "created_at": identity.created_at,
            }
            for identity in identity_result.scalars()
        ],
        "recent_audit_events": [audit_event_read(event) for event in audit_result.scalars()],
    }


@app.post("/api/v1/auth/account/deactivate", response_model=AccountDeactivateResponse)
async def deactivate_account(
    body: AccountDeactivateRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    user = await require_session_user(principal, db)
    if user.password_hash and not verify_password(body.current_password or "", user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid current password")
    if user.mfa_totp_enabled_at:
        if body.totp_code:
            verify_user_totp(user, body.totp_code)
        elif body.recovery_code:
            await verify_user_recovery_code(db, user, body.recovery_code)
        else:
            raise HTTPException(status_code=401, detail="TOTP code required")
    await ensure_user_can_deactivate(db, user_id=user.id)

    revoked_sessions = await revoke_user_sessions(db, user_id=user.id)
    revoked_at = now_utc()
    token_result = await db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
    )
    revoked_tokens = 0
    for token in token_result.scalars():
        token.revoked_at = revoked_at
        revoked_tokens += 1
    grant_result = await db.execute(
        select(OAuthGrant).where(OAuthGrant.user_id == user.id, OAuthGrant.revoked_at.is_(None))
    )
    revoked_grants = 0
    for grant in grant_result.scalars():
        grant.revoked_at = revoked_at
        revoked_grants += 1
    user.disabled = True
    await audit(
        db,
        "user.account.deactivate",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={
            "revoked_sessions": revoked_sessions,
            "revoked_tokens": revoked_tokens,
            "revoked_grants": revoked_grants,
        },
        request=request,
    )
    await db.commit()
    delete_session_cookie(response)
    return AccountDeactivateResponse(
        status="deactivated",
        revoked_sessions=revoked_sessions,
        revoked_tokens=revoked_tokens,
        revoked_grants=revoked_grants,
    )


@app.get("/api/v1/auth/mfa/status", response_model=MfaStatusRead)
async def mfa_status(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return MfaStatusRead(
        totp_enabled=bool(user.mfa_totp_enabled_at),
        totp_enabled_at=user.mfa_totp_enabled_at,
        totp_pending=bool(user.mfa_totp_secret_encrypted and not user.mfa_totp_enabled_at),
        recovery_codes_remaining=await recovery_codes_remaining(db, user.id),
    )


@app.post("/api/v1/auth/mfa/totp/setup", response_model=TotpSetupRead)
async def setup_totp(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.mfa_totp_enabled_at:
        raise HTTPException(status_code=400, detail="TOTP is already enabled")
    secret = new_totp_secret()
    user.mfa_totp_secret_encrypted = encrypt_mfa_secret(secret)
    await audit(
        db,
        "mfa.totp.setup",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
    )
    await db.commit()
    return TotpSetupRead(
        secret=secret,
        otpauth_uri=totp_otpauth_uri(user, secret),
        issuer="GateKeeper",
        account=user.email,
    )


@app.post("/api/v1/auth/mfa/totp/enable", response_model=TotpEnableRead)
async def enable_totp(
    body: TotpVerifyRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.mfa_totp_enabled_at:
        raise HTTPException(status_code=400, detail="TOTP is already enabled")
    verify_user_totp(user, body.code)
    user.mfa_totp_enabled_at = now_utc()
    recovery_codes = await issue_recovery_codes(db, user)
    await audit(
        db,
        "mfa.totp.enable",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"recovery_codes_issued": len(recovery_codes)},
    )
    await db.commit()
    return TotpEnableRead(
        totp_enabled=True,
        totp_enabled_at=user.mfa_totp_enabled_at,
        totp_pending=False,
        recovery_codes=recovery_codes,
        recovery_codes_remaining=len(recovery_codes),
    )


@app.post("/api/v1/auth/mfa/recovery-codes/regenerate", response_model=MfaRecoveryCodesRead)
async def regenerate_recovery_codes(
    body: TotpVerifyRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.mfa_totp_enabled_at:
        raise HTTPException(status_code=400, detail="TOTP is not enabled")
    verify_user_totp(user, body.code)
    recovery_codes = await issue_recovery_codes(db, user)
    await audit(
        db,
        "mfa.recovery_codes.regenerate",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"recovery_codes_issued": len(recovery_codes)},
    )
    await db.commit()
    return MfaRecoveryCodesRead(recovery_codes=recovery_codes, recovery_codes_remaining=len(recovery_codes))


@app.post("/api/v1/auth/mfa/totp/disable", response_model=MfaStatusRead)
async def disable_totp(
    body: TotpVerifyRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.mfa_totp_enabled_at:
        user.mfa_totp_secret_encrypted = None
        await retire_recovery_codes(db, user.id)
        await db.commit()
        return MfaStatusRead(totp_enabled=False, totp_enabled_at=None, totp_pending=False, recovery_codes_remaining=0)
    verify_user_totp(user, body.code)
    user.mfa_totp_secret_encrypted = None
    user.mfa_totp_enabled_at = None
    await retire_recovery_codes(db, user.id)
    await audit(
        db,
        "mfa.totp.disable",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
    )
    await db.commit()
    return MfaStatusRead(totp_enabled=False, totp_enabled_at=None, totp_pending=False, recovery_codes_remaining=0)


@app.get("/api/v1/setup/status", response_model=SetupStatusRead)
async def setup_status(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, principal.user_id) if principal.user_id else None
    memberships = await org_roles(db, user.id) if user else []
    selected_org = next((org for org in memberships if org.id == principal.org_id), None)
    selected_org = selected_org or (memberships[0] if memberships else None)
    permissions = selected_org.permissions if selected_org else principal.scopes
    exp = principal.claims.get("exp") if principal.claims else None
    access_expires_at = datetime.fromtimestamp(int(exp), UTC) if exp else None
    owner_exists = await org_has_owner(db, selected_org.id) if selected_org else False
    return SetupStatusRead(
        issuer=settings.issuer,
        jwks_uri=f"{settings.issuer}/oauth/jwks.json",
        user=user_read(user) if user else None,
        org=selected_org,
        orgs=memberships,
        auth_type=principal.auth_type,
        scopes=principal.scopes,
        owner_exists=owner_exists,
        can_manage_clients=has_capability(permissions, "admin:*"),
        can_issue_tokens=has_capability(permissions, "admin:*", "token:*"),
        can_manage_projects=has_capability(permissions, "admin:*"),
        can_manage_roles=has_capability(permissions, "admin:*"),
        access_expires_at=access_expires_at,
        smtp_configured=bool(settings.smtp_host),
        email_dev_mode=settings.email_dev_mode,
        dynamic_client_registration_enabled=settings.enable_dynamic_client_registration,
    )


async def user_admin_read(db: AsyncSession, user: User, org_ids: list[str] | None = None) -> UserAdminRead:
    query = (
        select(Membership, Organization, Role)
        .join(Organization, Organization.id == Membership.org_id)
        .join(Role, Role.id == Membership.role_id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.name.asc(), Role.name.asc())
    )
    if org_ids is not None:
        query = query.where(Membership.org_id.in_(org_ids))
    result = await db.execute(query)
    memberships = [
        {
            "id": membership.id,
            "org_id": org.id,
            "org_name": org.name,
            "role_id": role.id,
            "role": role.name,
            "permissions": role.permissions or [],
            "status": membership.status,
            "created_at": membership.created_at,
            "updated_at": membership.updated_at,
        }
        for membership, org, role in result.all()
    ]
    return UserAdminRead(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        email_verified=user.email_verified,
        mfa_totp_enabled=bool(user.mfa_totp_enabled_at),
        mfa_totp_enabled_at=user.mfa_totp_enabled_at,
        disabled=user.disabled,
        created_at=user.created_at,
        updated_at=user.updated_at,
        memberships=memberships,
    )


async def ensure_other_active_owner(db: AsyncSession, *, org_id: str, user_id: str) -> None:
    result = await db.execute(
        select(func.count(Membership.id))
        .join(Role, Role.id == Membership.role_id)
        .where(
            Membership.org_id == org_id,
            Membership.user_id != user_id,
            Membership.status == "active",
            Role.name == "owner",
        )
    )
    if int(result.scalar_one() or 0) < 1:
        raise HTTPException(status_code=400, detail="Cannot remove the last active owner")


async def revoke_user_sessions(db: AsyncSession, *, user_id: str) -> int:
    revoked_at = now_utc()
    result = await db.execute(
        select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
    )
    revoked_count = 0
    for session in result.scalars():
        session.revoked_at = revoked_at
        revoked_count += 1
    refresh_result = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
    )
    for refresh in refresh_result.scalars():
        refresh.revoked_at = refresh.revoked_at or revoked_at
    return revoked_count


async def count_user_delete_artifacts(db: AsyncSession, *, user_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    queries = {
        "memberships": select(func.count(Membership.id)).where(Membership.user_id == user_id),
        "sessions": select(func.count(Session.id)).where(Session.user_id == user_id),
        "refresh_tokens": select(func.count(RefreshToken.id)).where(RefreshToken.user_id == user_id),
        "api_tokens": select(func.count(ApiToken.id)).where(ApiToken.user_id == user_id),
        "oauth_grants": select(func.count(OAuthGrant.id)).where(OAuthGrant.user_id == user_id),
        "identities": select(func.count(Identity.id)).where(Identity.user_id == user_id),
        "mfa_recovery_codes": select(func.count(MfaRecoveryCode.id)).where(MfaRecoveryCode.user_id == user_id),
        "webauthn_credentials": select(func.count(WebAuthnCredential.id)).where(WebAuthnCredential.user_id == user_id),
        "device_grants": select(func.count(DeviceGrant.id)).where(DeviceGrant.user_id == user_id),
        "authorization_codes": select(func.count(OAuthAuthorizationCode.id)).where(
            OAuthAuthorizationCode.user_id == user_id
        ),
        "one_time_codes": select(func.count(OneTimeCode.id)).where(OneTimeCode.user_id == user_id),
        "invitations": select(func.count(Invitation.id)).where(
            or_(Invitation.invited_by_user_id == user_id, Invitation.accepted_user_id == user_id)
        ),
        "audit_actor_events": select(func.count(AuditEvent.id)).where(AuditEvent.actor_user_id == user_id),
    }
    for key, query in queries.items():
        result = await db.execute(query)
        counts[key] = int(result.scalar_one() or 0)
    return counts


async def user_membership_org_ids(db: AsyncSession, *, user_id: str) -> list[str]:
    result = await db.execute(select(Membership.org_id).where(Membership.user_id == user_id))
    return list(result.scalars())


async def ensure_user_hard_delete_policy(
    db: AsyncSession,
    *,
    user_id: str,
    visible_org_ids: list[str] | None,
) -> list[str]:
    membership_org_ids = await user_membership_org_ids(db, user_id=user_id)
    if visible_org_ids is not None:
        hidden_org_ids = sorted(set(membership_org_ids) - set(visible_org_ids))
        if hidden_org_ids:
            raise HTTPException(status_code=409, detail="User belongs to another organization")
        policy_org_ids = sorted(set(membership_org_ids).intersection(visible_org_ids))
    else:
        policy_org_ids = sorted(set(membership_org_ids))
    if not policy_org_ids:
        return []
    result = await db.execute(select(Organization).where(Organization.id.in_(policy_org_ids)))
    orgs = result.scalars().all()
    disabled = [org.id for org in orgs if not org.allow_user_hard_delete]
    if disabled:
        raise HTTPException(status_code=403, detail="User hard delete is disabled for this organization")
    return policy_org_ids


async def ensure_user_admin_visible(
    db: AsyncSession,
    *,
    user_id: str,
    principal: Principal,
) -> list[str] | None:
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, None)
    if visible_org_ids is None:
        return None
    if not visible_org_ids:
        raise HTTPException(status_code=404, detail="User not found")
    result = await db.execute(
        select(Membership.id)
        .where(Membership.user_id == user_id, Membership.org_id.in_(visible_org_ids))
        .limit(1)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found")
    return visible_org_ids


async def resolve_org_role(
    db: AsyncSession,
    *,
    org_id: str,
    role_id: str | None,
    role_name: str | None,
    default_role: str = "viewer",
) -> Role:
    role_query = select(Role).where(Role.org_id == org_id)
    if role_id:
        role_query = role_query.where(Role.id == role_id)
    elif role_name:
        role_query = role_query.where(Role.name == role_name)
    else:
        role_query = role_query.where(Role.name == default_role)
    role_result = await db.execute(role_query)
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
SCIM_BULK_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_ENTERPRISE_FIELDS = {"employeeNumber", "costCenter", "organization", "division", "department"}
SCIM_ENTERPRISE_FIELD_ALIASES = {field.lower(): field for field in SCIM_ENTERPRISE_FIELDS}
SCIM_UNSET = object()


def scim_resource_location(resource_type: str, resource_id: str) -> str:
    return f"{settings.issuer.rstrip('/')}/scim/v2/{resource_type}/{resource_id}"


def scim_datetime(value: datetime | None) -> str | None:
    if not value:
        return None
    aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return aware.isoformat().replace("+00:00", "Z")


def scim_bool(value: Any, *, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"false", "0", "no", "off"}
    return bool(value)


def scim_display_name(body: dict[str, Any]) -> str | None:
    display_name = body.get("displayName")
    if isinstance(display_name, str) and display_name.strip():
        return display_name.strip()
    name = body.get("name")
    if isinstance(name, dict):
        formatted = name.get("formatted")
        if isinstance(formatted, str) and formatted.strip():
            return formatted.strip()
        parts = [
            str(name.get("givenName") or "").strip(),
            str(name.get("familyName") or "").strip(),
        ]
        combined = " ".join(part for part in parts if part)
        return combined or None
    return None


def scim_user_email(body: dict[str, Any]) -> str:
    username = body.get("userName")
    if isinstance(username, str) and username.strip():
        return username.strip().lower()
    emails = body.get("emails")
    if isinstance(emails, list):
        for item in emails:
            if isinstance(item, dict) and isinstance(item.get("value"), str) and item["value"].strip():
                return item["value"].strip().lower()
    raise HTTPException(status_code=422, detail="SCIM userName or emails[0].value is required")


def scim_role_name(body: dict[str, Any]) -> str | None:
    roles = body.get("roles")
    if not isinstance(roles, list):
        return None
    for item in roles:
        if isinstance(item, str) and item.strip():
            return item.strip()
        if isinstance(item, dict):
            value = item.get("value") or item.get("display")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def scim_password(body: dict[str, Any]) -> object:
    if "password" not in body:
        return SCIM_UNSET
    value = body.get("password")
    if not isinstance(value, str) or len(value) < 12:
        raise HTTPException(status_code=422, detail="SCIM password must be at least 12 characters")
    return value


def scim_external_id(body: dict[str, Any]) -> object:
    if "externalId" not in body:
        return SCIM_UNSET
    value = body.get("externalId")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def scim_enterprise_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def scim_enterprise_manager(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return {"value": text} if text else None
    if not isinstance(value, dict):
        return None
    manager: dict[str, str] = {}
    for key in ("value", "display", "$ref"):
        text = scim_enterprise_text(value.get(key))
        if text:
            manager[key] = text
    return manager or None


def scim_enterprise_profile(body: dict[str, Any]) -> object:
    extension = body.get(SCIM_ENTERPRISE_USER_SCHEMA)
    if not isinstance(extension, dict):
        return SCIM_UNSET
    profile: dict[str, Any] = {}
    for field in SCIM_ENTERPRISE_FIELDS:
        if field in extension:
            profile[field] = scim_enterprise_text(extension.get(field))
    if "manager" in extension:
        profile["manager"] = scim_enterprise_manager(extension.get("manager"))
    return profile


def scim_enterprise_patch_field(path: str) -> str | None:
    normalized = path.strip()
    if ":" in normalized:
        normalized = normalized.split(":")[-1]
    normalized = normalized.split(".", 1)[0].lower()
    if normalized == "manager":
        return "manager"
    return SCIM_ENTERPRISE_FIELD_ALIASES.get(normalized)


def scim_filter_user_name(filter_value: str | None) -> str | None:
    if not filter_value:
        return None
    cleaned = filter_value.strip()
    prefix = "username eq "
    if not cleaned.lower().startswith(prefix):
        raise HTTPException(status_code=400, detail="Only SCIM filter 'userName eq <email>' is supported")
    value = cleaned[len(prefix):].strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    return value.strip().lower() or None


def scim_filter_display_name(filter_value: str | None) -> str | None:
    if not filter_value:
        return None
    cleaned = filter_value.strip()
    prefix = "displayname eq "
    if not cleaned.lower().startswith(prefix):
        raise HTTPException(status_code=400, detail="Only SCIM filter 'displayName eq <name>' is supported")
    value = cleaned[len(prefix):].strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    return value.strip() or None


def scim_sort_descending(sort_by: str | None, sort_order: str | None) -> bool:
    if not sort_by:
        return False
    normalized = (sort_order or "ascending").strip().lower()
    if normalized in {"ascending", "asc"}:
        return False
    if normalized in {"descending", "desc"}:
        return True
    raise HTTPException(status_code=400, detail="SCIM sortOrder must be 'ascending' or 'descending'")


def scim_sort_expression(expression: Any, *, descending: bool) -> Any:
    return expression.desc() if descending else expression.asc()


def scim_user_ordering(sort_by: str | None, sort_order: str | None) -> list[Any]:
    if not sort_by:
        return [User.created_at.desc(), User.id.asc()]
    descending = scim_sort_descending(sort_by, sort_order)
    normalized = sort_by.strip().lower()
    fields: dict[str, Any] = {
        "username": User.email,
        "displayname": func.coalesce(User.display_name, User.email),
        "name.formatted": func.coalesce(User.display_name, User.email),
        "roles": Role.name,
        "meta.created": User.created_at,
        "created": User.created_at,
        "meta.lastmodified": User.updated_at,
        "lastmodified": User.updated_at,
    }
    expression = fields.get(normalized)
    if expression is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only SCIM user sortBy userName, displayName, roles, "
                "meta.created, and meta.lastModified are supported"
            ),
        )
    return [scim_sort_expression(expression, descending=descending), User.id.asc()]


def scim_group_ordering(sort_by: str | None, sort_order: str | None) -> list[Any]:
    if not sort_by:
        return [Role.name.asc(), Role.id.asc()]
    descending = scim_sort_descending(sort_by, sort_order)
    normalized = sort_by.strip().lower()
    fields: dict[str, Any] = {
        "displayname": Role.name,
        "meta.created": Role.created_at,
        "created": Role.created_at,
        "meta.lastmodified": Role.updated_at,
        "lastmodified": Role.updated_at,
    }
    expression = fields.get(normalized)
    if expression is None:
        raise HTTPException(
            status_code=400,
            detail="Only SCIM group sortBy displayName, meta.created, and meta.lastModified are supported",
        )
    return [scim_sort_expression(expression, descending=descending), Role.id.asc()]


def scim_group_display_name(body: dict[str, Any]) -> str:
    display_name = body.get("displayName")
    if not isinstance(display_name, str) or not display_name.strip():
        raise HTTPException(status_code=422, detail="SCIM group displayName is required")
    return display_name.strip()


def scim_member_ids(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    member_ids: list[str] = []
    for item in items:
        if isinstance(item, str) and item.strip():
            member_ids.append(item.strip())
        elif isinstance(item, dict) and isinstance(item.get("value"), str) and item["value"].strip():
            member_ids.append(item["value"].strip())
    return member_ids


def scim_member_ids_from_path(path: str) -> list[str]:
    lower_path = path.lower()
    if "value eq" not in lower_path:
        return []
    raw = path.split("value", 1)[1].split("eq", 1)[1].strip().rstrip("]")
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        raw = raw[1:-1]
    return [raw.strip()] if raw.strip() else []


def scim_patch_values(body: dict[str, Any]) -> tuple[object, object, object, object, object, object]:
    active: object = SCIM_UNSET
    display_name: object = SCIM_UNSET
    role_name: object = SCIM_UNSET
    password: object = SCIM_UNSET
    external_id: object = SCIM_UNSET
    enterprise_profile: object = SCIM_UNSET
    operations = body.get("Operations") or body.get("operations")
    if not isinstance(operations, list):
        raise HTTPException(status_code=422, detail="SCIM PatchOp Operations array is required")
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        op_name = str(operation.get("op") or "replace").lower()
        if op_name not in {"add", "replace", "remove"}:
            raise HTTPException(status_code=400, detail="Unsupported SCIM patch operation")
        path = str(operation.get("path") or "").strip()
        value = operation.get("value")
        if not path and isinstance(value, dict):
            if "active" in value:
                active = scim_bool(value.get("active"))
            if "displayName" in value or "name" in value:
                display_name = scim_display_name(value)
            role = scim_role_name(value)
            if role:
                role_name = role
            if "password" in value:
                password = scim_password(value)
            if "externalId" in value:
                external_id = scim_external_id(value)
            profile = scim_enterprise_profile(value)
            if profile is not SCIM_UNSET:
                enterprise_profile = profile
            continue
        normalized_path = path.lower()
        if normalized_path == "active":
            active = False if op_name == "remove" else scim_bool(value)
        elif normalized_path in {"displayname", "name.formatted"}:
            display_name = None if op_name == "remove" else (str(value).strip() if value is not None else None)
        elif normalized_path.startswith("roles"):
            role = scim_role_name({"roles": value if isinstance(value, list) else [value]})
            if role:
                role_name = role
        elif normalized_path == "password":
            if op_name == "remove":
                raise HTTPException(status_code=400, detail="SCIM password removal is not supported")
            password = scim_password({"password": value})
        elif normalized_path == "externalid":
            external_id = None if op_name == "remove" else scim_external_id({"externalId": value})
        else:
            enterprise_field = scim_enterprise_patch_field(path)
            if enterprise_field:
                if enterprise_profile is SCIM_UNSET:
                    enterprise_profile = {}
                if enterprise_field == "manager":
                    enterprise_profile["manager"] = (
                        None if op_name == "remove" else scim_enterprise_manager(value)
                    )
                else:
                    enterprise_profile[enterprise_field] = (
                        None if op_name == "remove" else scim_enterprise_text(value)
                    )
    return active, display_name, role_name, password, external_id, enterprise_profile


async def scim_selected_org(db: AsyncSession, principal: Principal, requested_org_id: str | None) -> Organization:
    org_id = await setup_resource_org_id(db, principal, requested_org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="SCIM organization context is required")
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


async def scim_user_row(
    db: AsyncSession,
    *,
    user_id: str,
    org_id: str,
) -> tuple[User, Membership, Role]:
    result = await db.execute(
        select(User, Membership, Role)
        .join(Membership, Membership.user_id == User.id)
        .join(Role, Role.id == Membership.role_id)
        .where(User.id == user_id, Membership.org_id == org_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="SCIM user not found")
    return row[0], row[1], row[2]


def scim_user_resource(user: User, org: Organization, membership: Membership, role: Role) -> dict[str, Any]:
    schemas = [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA]
    display_name = user.display_name or user.email
    enterprise_profile = dict(membership.scim_enterprise_profile or {})
    enterprise_payload: dict[str, Any] = {
        "organization": enterprise_profile.get("organization") or org.name,
        "department": enterprise_profile.get("department") or org.slug,
    }
    for field in ("employeeNumber", "costCenter", "division"):
        if enterprise_profile.get(field):
            enterprise_payload[field] = enterprise_profile[field]
    manager = enterprise_profile.get("manager")
    if isinstance(manager, dict) and manager.get("value"):
        enterprise_payload["manager"] = {
            "value": manager["value"],
            "display": manager.get("display") or manager["value"],
            "$ref": manager.get("$ref") or scim_resource_location("Users", manager["value"]),
        }
    resource = {
        "schemas": schemas,
        "id": user.id,
        "userName": user.email,
        "name": {"formatted": display_name},
        "displayName": user.display_name,
        "active": bool(not user.disabled and membership.status == "active"),
        "emails": [{"value": user.email, "primary": True, "type": "work"}],
        "roles": [
            {
                "value": role.name,
                "display": role.name,
                "type": "organization",
                "primary": True,
            }
        ],
        SCIM_ENTERPRISE_USER_SCHEMA: enterprise_payload,
        "meta": {
            "resourceType": "User",
            "created": scim_datetime(user.created_at),
            "lastModified": scim_datetime(user.updated_at),
            "location": scim_resource_location("Users", user.id),
        },
    }
    if membership.scim_external_id:
        resource["externalId"] = membership.scim_external_id
    return resource


async def scim_group_resource(db: AsyncSession, org: Organization, role: Role) -> dict[str, Any]:
    result = await db.execute(
        select(User)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.org_id == org.id, Membership.role_id == role.id, Membership.status == "active")
        .order_by(User.email.asc())
    )
    members = [
        {
            "value": user.id,
            "display": user.email,
            "$ref": scim_resource_location("Users", user.id),
        }
        for user in result.scalars()
    ]
    return {
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": role.id,
        "displayName": role.name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": scim_datetime(role.created_at),
            "lastModified": scim_datetime(role.updated_at),
            "location": scim_resource_location("Groups", role.id),
        },
    }


async def scim_group_role(db: AsyncSession, *, role_id: str, org_id: str) -> Role:
    role = await db.get(Role, role_id)
    if not role or role.org_id != org_id:
        raise HTTPException(status_code=404, detail="SCIM group not found")
    return role


async def scim_assign_group_member(db: AsyncSession, *, org: Organization, role: Role, user_id: str) -> bool:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="SCIM member not found")
    result = await db.execute(select(Membership).where(Membership.user_id == user.id, Membership.org_id == org.id))
    membership = result.scalar_one_or_none()
    current_role = await db.get(Role, membership.role_id) if membership else None
    changed = (
        membership is None
        or membership.role_id != role.id
        or membership.status != "active"
        or user.disabled
    )
    if membership and current_role and membership.status == "active" and current_role.name == "owner":
        if role.id != current_role.id:
            await ensure_other_active_owner(db, org_id=org.id, user_id=user.id)
    if membership:
        membership.role_id = role.id
        membership.status = "active"
    else:
        membership = Membership(org_id=org.id, user_id=user.id, role_id=role.id, status="active")
        db.add(membership)
    user.disabled = False
    if changed:
        await revoke_user_sessions(db, user_id=user.id)
    return changed


async def scim_remove_group_member(db: AsyncSession, *, org: Organization, role: Role, user_id: str) -> bool:
    result = await db.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.user_id == user_id, Membership.org_id == org.id)
    )
    row = result.first()
    if not row:
        return False
    user, membership = row[0], row[1]
    if membership.role_id != role.id or membership.status != "active":
        return False
    if role.name == "owner":
        await ensure_other_active_owner(db, org_id=org.id, user_id=user.id)
    membership.status = "revoked"
    await revoke_user_sessions(db, user_id=user.id)
    return True


async def scim_apply_user_state(
    db: AsyncSession,
    *,
    user: User,
    org: Organization,
    principal: Principal,
    request: Request,
    display_name: object = SCIM_UNSET,
    active: object = SCIM_UNSET,
    role_name: object = SCIM_UNSET,
    password: object = SCIM_UNSET,
    external_id: object = SCIM_UNSET,
    enterprise_profile: object = SCIM_UNSET,
    default_role: str = "viewer",
    audit_action: str,
) -> tuple[Membership, Role, int]:
    membership_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id, Membership.org_id == org.id)
    )
    membership = membership_result.scalar_one_or_none()
    current_role = await db.get(Role, membership.role_id) if membership else None
    role = current_role
    if role_name is not SCIM_UNSET or not role:
        role = await resolve_org_role(
            db,
            org_id=org.id,
            role_id=None,
            role_name=str(role_name) if role_name is not SCIM_UNSET and role_name else None,
            default_role=default_role,
        )
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    target_status = (
        membership.status
        if membership and active is SCIM_UNSET
        else ("active" if scim_bool(active) else "revoked")
    )
    if membership and current_role and membership.status == "active" and current_role.name == "owner":
        if target_status != "active" or role.name != "owner":
            await ensure_other_active_owner(db, org_id=org.id, user_id=user.id)

    previous_disabled = user.disabled
    if display_name is not SCIM_UNSET:
        user.display_name = str(display_name).strip() or None if display_name is not None else None
    password_changed = False
    if password is not SCIM_UNSET:
        user.password_hash = hash_password(str(password))
        password_changed = True
    created_membership = membership is None
    membership_changed = created_membership
    if membership:
        membership_changed = membership.role_id != role.id or membership.status != target_status
        membership.role_id = role.id
        membership.status = target_status
    else:
        membership = Membership(org_id=org.id, user_id=user.id, role_id=role.id, status=target_status)
        db.add(membership)
    if external_id is not SCIM_UNSET:
        membership.scim_external_id = str(external_id).strip() if external_id else None
    if enterprise_profile is not SCIM_UNSET:
        current_profile = dict(membership.scim_enterprise_profile or {})
        for key, value in dict(enterprise_profile).items():
            if value in (None, "", {}):
                current_profile.pop(key, None)
            else:
                current_profile[key] = value
        membership.scim_enterprise_profile = current_profile

    if active is not SCIM_UNSET and scim_bool(active):
        user.disabled = False
    await db.flush()
    if active is not SCIM_UNSET and not scim_bool(active):
        active_count_result = await db.execute(
            select(func.count(Membership.id)).where(Membership.user_id == user.id, Membership.status == "active")
        )
        if int(active_count_result.scalar_one() or 0) == 0:
            user.disabled = True

    disabled_changed = previous_disabled != user.disabled
    revoked_sessions = 0
    if membership_changed or disabled_changed or password_changed:
        revoked_sessions = await revoke_user_sessions(db, user_id=user.id)
    await audit(
        db,
        audit_action,
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=user.id,
        details={
            "email": user.email,
            "role": role.name,
            "status": membership.status,
            "active": not user.disabled and membership.status == "active",
            "password_updated": password_changed,
            "external_id_updated": external_id is not SCIM_UNSET,
            "enterprise_profile_updated": enterprise_profile is not SCIM_UNSET,
            "revoked_sessions": revoked_sessions,
        },
        request=request,
    )
    return membership, role, revoked_sessions


def scim_error_payload(status_code: int, detail: str) -> dict[str, Any]:
    return {"schemas": [SCIM_ERROR_SCHEMA], "status": str(status_code), "detail": detail}


def scim_bulk_path(path: str) -> tuple[str, str | None]:
    parsed = urlparse(path.strip())
    raw_path = parsed.path.strip("/")
    if raw_path.startswith("scim/v2/"):
        raw_path = raw_path.removeprefix("scim/v2/")
    parts = [part for part in raw_path.split("/") if part]
    if not parts or parts[0] not in {"Users", "Groups"}:
        raise HTTPException(status_code=400, detail="SCIM bulk path must target Users or Groups")
    if len(parts) > 2:
        raise HTTPException(status_code=400, detail="SCIM bulk path is not supported")
    return parts[0], parts[1] if len(parts) == 2 else None


def scim_bulk_resolve_refs(value: Any, bulk_ids: dict[str, str]) -> Any:
    if isinstance(value, str):
        if value.startswith("bulkId:"):
            bulk_id = value.removeprefix("bulkId:")
            if bulk_id not in bulk_ids:
                raise HTTPException(status_code=400, detail=f"SCIM bulkId {bulk_id} has not been created")
            return bulk_ids[bulk_id]
        return value
    if isinstance(value, list):
        return [scim_bulk_resolve_refs(item, bulk_ids) for item in value]
    if isinstance(value, dict):
        return {key: scim_bulk_resolve_refs(item, bulk_ids) for key, item in value.items()}
    return value


async def scim_execute_bulk_operation(
    operation: dict[str, Any],
    *,
    request: Request,
    org_id: str | None,
    principal: Principal,
    db: AsyncSession,
    bulk_ids: dict[str, str],
) -> dict[str, Any]:
    method = str(operation.get("method") or "").upper()
    path = str(operation.get("path") or "")
    bulk_id = str(operation.get("bulkId") or "").strip() or None
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise HTTPException(status_code=400, detail="Unsupported SCIM bulk operation method")
    resource_type, resource_id = scim_bulk_path(path)
    if resource_id and resource_id.startswith("bulkId:"):
        resource_id = str(scim_bulk_resolve_refs(resource_id, bulk_ids))
    data = scim_bulk_resolve_refs(operation.get("data") or operation.get("Data") or {}, bulk_ids)
    response = Response()
    resource: Any = None
    status_code = 200
    location: str | None = None

    if resource_type == "Users":
        if method == "POST" and not resource_id:
            resource = await scim_create_user(data, request, response, org_id=org_id, principal=principal, db=db)
            status_code = response.status_code or 201
            location = resource["meta"]["location"]
            if bulk_id:
                bulk_ids[bulk_id] = resource["id"]
        elif method == "GET" and resource_id:
            resource = await scim_get_user(resource_id, org_id=org_id, principal=principal, db=db)
            location = resource["meta"]["location"]
        elif method == "PUT" and resource_id:
            resource = await scim_replace_user(resource_id, data, request, org_id=org_id, principal=principal, db=db)
            location = resource["meta"]["location"]
        elif method == "PATCH" and resource_id:
            resource = await scim_patch_user(resource_id, data, request, org_id=org_id, principal=principal, db=db)
            location = resource["meta"]["location"]
        elif method == "DELETE" and resource_id:
            await scim_delete_user(resource_id, request, org_id=org_id, principal=principal, db=db)
            status_code = 204
        else:
            raise HTTPException(status_code=400, detail="Unsupported SCIM bulk Users operation")
    elif resource_type == "Groups":
        if method == "POST" and not resource_id:
            resource = await scim_create_group(data, request, response, org_id=org_id, principal=principal, db=db)
            status_code = response.status_code or 201
            location = resource["meta"]["location"]
            if bulk_id:
                bulk_ids[bulk_id] = resource["id"]
        elif method == "GET" and resource_id:
            resource = await scim_get_group(resource_id, org_id=org_id, principal=principal, db=db)
            location = resource["meta"]["location"]
        elif method == "PUT" and resource_id:
            resource = await scim_replace_group(resource_id, data, request, org_id=org_id, principal=principal, db=db)
            location = resource["meta"]["location"]
        elif method == "PATCH" and resource_id:
            resource = await scim_patch_group(resource_id, data, request, org_id=org_id, principal=principal, db=db)
            location = resource["meta"]["location"]
        elif method == "DELETE" and resource_id:
            await scim_delete_group(resource_id, org_id=org_id, principal=principal, db=db)
        else:
            raise HTTPException(status_code=400, detail="Unsupported SCIM bulk Groups operation")

    bulk_response: dict[str, Any] = {"method": method, "status": str(status_code)}
    if bulk_id:
        bulk_response["bulkId"] = bulk_id
    if location:
        bulk_response["location"] = location
    if resource is not None:
        bulk_response["response"] = resource
    return bulk_response


@app.post("/scim/v2/Bulk")
async def scim_bulk(
    body: dict[str, Any],
    request: Request,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    operations = body.get("Operations") or body.get("operations")
    if not isinstance(operations, list):
        raise HTTPException(status_code=422, detail="SCIM Bulk Operations array is required")
    if len(operations) > 100:
        raise HTTPException(status_code=413, detail="SCIM bulk request supports at most 100 operations")
    fail_on_errors = int(body.get("failOnErrors") or 0)
    errors = 0
    bulk_ids: dict[str, str] = {}
    responses: list[dict[str, Any]] = []
    for operation in operations:
        if not isinstance(operation, dict):
            operation = {}
        try:
            responses.append(
                await scim_execute_bulk_operation(
                    operation,
                    request=request,
                    org_id=org_id,
                    principal=principal,
                    db=db,
                    bulk_ids=bulk_ids,
                )
            )
        except HTTPException as exc:
            await db.rollback()
            status_code = int(exc.status_code or 500)
            errors += 1
            error_response: dict[str, Any] = {
                "method": str(operation.get("method") or "").upper() or "UNKNOWN",
                "status": str(status_code),
                "response": scim_error_payload(status_code, str(exc.detail)),
            }
            if operation.get("bulkId"):
                error_response["bulkId"] = str(operation["bulkId"])
            responses.append(error_response)
            if fail_on_errors and errors >= fail_on_errors:
                break
    return {"schemas": [SCIM_BULK_RESPONSE_SCHEMA], "Operations": responses}


@app.get("/scim/v2/ServiceProviderConfig")
async def scim_service_provider_config():
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": True, "maxOperations": 100, "maxPayloadSize": 1048576},
        "filter": {"supported": True, "maxResults": 500},
        "changePassword": {"supported": True},
        "sort": {"supported": True},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Use a GateKeeper admin-scoped bearer token.",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{settings.issuer.rstrip('/')}/scim/v2/ServiceProviderConfig",
        },
    }


@app.get("/scim/v2/ResourceTypes")
async def scim_resource_types():
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 2,
        "itemsPerPage": 2,
        "startIndex": 1,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": SCIM_USER_SCHEMA,
                "schemaExtensions": [{"schema": SCIM_ENTERPRISE_USER_SCHEMA, "required": False}],
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": SCIM_GROUP_SCHEMA,
            },
        ],
    }


@app.get("/scim/v2/Schemas")
async def scim_schemas():
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 3,
        "itemsPerPage": 3,
        "startIndex": 1,
        "Resources": [
            {
                "id": SCIM_USER_SCHEMA,
                "name": "User",
                "description": "GateKeeper SCIM user compatibility schema.",
                "attributes": [
                    {"name": "externalId", "type": "string", "mutability": "readWrite"},
                    {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
                    {"name": "displayName", "type": "string"},
                    {"name": "active", "type": "boolean"},
                    {"name": "emails", "type": "complex", "multiValued": True},
                    {"name": "roles", "type": "complex", "multiValued": True},
                    {"name": "password", "type": "string", "mutability": "writeOnly", "returned": "never"},
                ],
            },
            {
                "id": SCIM_GROUP_SCHEMA,
                "name": "Group",
                "description": "GateKeeper role-backed SCIM group compatibility schema.",
                "attributes": [
                    {"name": "displayName", "type": "string", "required": True},
                    {"name": "members", "type": "complex", "multiValued": True},
                ],
            },
            {
                "id": SCIM_ENTERPRISE_USER_SCHEMA,
                "name": "EnterpriseUser",
                "description": "GateKeeper membership-scoped enterprise user attributes.",
                "attributes": [
                    {"name": "employeeNumber", "type": "string"},
                    {"name": "costCenter", "type": "string"},
                    {"name": "organization", "type": "string"},
                    {"name": "division", "type": "string"},
                    {"name": "department", "type": "string"},
                    {"name": "manager", "type": "complex"},
                ],
            },
        ],
    }


@app.get("/scim/v2/Groups")
async def scim_list_groups(
    org_id: str | None = None,
    filter: str | None = None,
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=0, le=500),
    sortBy: str | None = None,
    sortOrder: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    display_filter = scim_filter_display_name(filter)
    filters = [Role.org_id == org.id]
    if display_filter:
        filters.append(Role.name == display_filter)
    total_result = await db.execute(select(func.count(Role.id)).where(*filters))
    total_results = int(total_result.scalar_one() or 0)
    result = await db.execute(
        select(Role)
        .where(*filters)
        .order_by(*scim_group_ordering(sortBy, sortOrder))
        .offset(startIndex - 1)
        .limit(count)
    )
    resources = [await scim_group_resource(db, org, role) for role in result.scalars()]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total_results,
        "itemsPerPage": len(resources),
        "startIndex": startIndex,
        "Resources": resources,
    }


@app.post("/scim/v2/Groups")
async def scim_create_group(
    body: dict[str, Any],
    request: Request,
    response: Response,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    display_name = scim_group_display_name(body)
    existing = await db.execute(select(Role).where(Role.org_id == org.id, Role.name == display_name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="SCIM group already exists")
    role = Role(org_id=org.id, name=display_name, permissions=[])
    db.add(role)
    await db.flush()
    changed_members = 0
    for member_id in scim_member_ids(body.get("members")):
        if await scim_assign_group_member(db, org=org, role=role, user_id=member_id):
            changed_members += 1
    await audit(
        db,
        "scim.group.create",
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="role",
        target_id=role.id,
        details={"display_name": role.name, "changed_members": changed_members},
        request=request,
    )
    await db.commit()
    await db.refresh(role)
    response.status_code = 201
    return await scim_group_resource(db, org, role)


@app.get("/scim/v2/Groups/{group_id}")
async def scim_get_group(
    group_id: str,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    role = await scim_group_role(db, role_id=group_id, org_id=org.id)
    return await scim_group_resource(db, org, role)


@app.put("/scim/v2/Groups/{group_id}")
async def scim_replace_group(
    group_id: str,
    body: dict[str, Any],
    request: Request,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    role = await scim_group_role(db, role_id=group_id, org_id=org.id)
    display_name = scim_group_display_name(body)
    if display_name != role.name:
        duplicate = await db.execute(select(Role.id).where(Role.org_id == org.id, Role.name == display_name))
        if duplicate.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="SCIM group already exists")
        role.name = display_name
    desired_member_ids = set(scim_member_ids(body.get("members")))
    current_result = await db.execute(
        select(Membership.user_id).where(
            Membership.org_id == org.id,
            Membership.role_id == role.id,
            Membership.status == "active",
        )
    )
    current_member_ids = set(current_result.scalars())
    changed_members = 0
    for member_id in sorted(current_member_ids - desired_member_ids):
        if await scim_remove_group_member(db, org=org, role=role, user_id=member_id):
            changed_members += 1
    for member_id in sorted(desired_member_ids - current_member_ids):
        if await scim_assign_group_member(db, org=org, role=role, user_id=member_id):
            changed_members += 1
    await audit(
        db,
        "scim.group.replace",
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="role",
        target_id=role.id,
        details={"display_name": role.name, "changed_members": changed_members},
        request=request,
    )
    await db.commit()
    await db.refresh(role)
    return await scim_group_resource(db, org, role)


@app.patch("/scim/v2/Groups/{group_id}")
async def scim_patch_group(
    group_id: str,
    body: dict[str, Any],
    request: Request,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    role = await scim_group_role(db, role_id=group_id, org_id=org.id)
    operations = body.get("Operations") or body.get("operations")
    if not isinstance(operations, list):
        raise HTTPException(status_code=422, detail="SCIM PatchOp Operations array is required")
    changed_members = 0
    renamed = False
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        op_name = str(operation.get("op") or "replace").lower()
        if op_name not in {"add", "replace", "remove"}:
            raise HTTPException(status_code=400, detail="Unsupported SCIM patch operation")
        path = str(operation.get("path") or "").strip()
        value = operation.get("value")
        normalized_path = path.lower()
        if not path and isinstance(value, dict) and "displayName" in value:
            normalized_path = "displayname"
            value = value.get("displayName")
        if normalized_path == "displayname":
            if op_name == "remove":
                raise HTTPException(status_code=400, detail="SCIM group displayName is required")
            display_name = scim_group_display_name({"displayName": value})
            if display_name != role.name:
                duplicate = await db.execute(select(Role.id).where(Role.org_id == org.id, Role.name == display_name))
                if duplicate.scalar_one_or_none():
                    raise HTTPException(status_code=409, detail="SCIM group already exists")
                role.name = display_name
                renamed = True
            continue
        if not normalized_path.startswith("members") and not (
            not path and isinstance(value, dict) and "members" in value
        ):
            raise HTTPException(status_code=400, detail="Unsupported SCIM group patch path")
        if not path and isinstance(value, dict):
            value = value.get("members")
        member_ids = scim_member_ids(value) or scim_member_ids_from_path(path)
        if op_name == "replace":
            desired_member_ids = set(member_ids)
            current_result = await db.execute(
                select(Membership.user_id).where(
                    Membership.org_id == org.id,
                    Membership.role_id == role.id,
                    Membership.status == "active",
                )
            )
            current_member_ids = set(current_result.scalars())
            for member_id in sorted(current_member_ids - desired_member_ids):
                if await scim_remove_group_member(db, org=org, role=role, user_id=member_id):
                    changed_members += 1
            for member_id in sorted(desired_member_ids - current_member_ids):
                if await scim_assign_group_member(db, org=org, role=role, user_id=member_id):
                    changed_members += 1
        elif op_name == "remove":
            if not member_ids:
                current_result = await db.execute(
                    select(Membership.user_id).where(
                        Membership.org_id == org.id,
                        Membership.role_id == role.id,
                        Membership.status == "active",
                    )
                )
                member_ids = list(current_result.scalars())
            for member_id in member_ids:
                if await scim_remove_group_member(db, org=org, role=role, user_id=member_id):
                    changed_members += 1
        else:
            for member_id in member_ids:
                if await scim_assign_group_member(db, org=org, role=role, user_id=member_id):
                    changed_members += 1
    await audit(
        db,
        "scim.group.patch",
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="role",
        target_id=role.id,
        details={"display_name": role.name, "changed_members": changed_members, "renamed": renamed},
        request=request,
    )
    await db.commit()
    await db.refresh(role)
    return await scim_group_resource(db, org, role)


@app.delete("/scim/v2/Groups/{group_id}")
async def scim_delete_group(
    group_id: str,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await scim_group_role(db, role_id=group_id, org_id=org.id)
    raise HTTPException(status_code=501, detail="SCIM group deletion is not supported; remove members instead")


@app.get("/scim/v2/Users")
async def scim_list_users(
    org_id: str | None = None,
    filter: str | None = None,
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=0, le=500),
    sortBy: str | None = None,
    sortOrder: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    filter_email = scim_filter_user_name(filter)
    filters = [Membership.org_id == org.id]
    if filter_email:
        filters.append(User.email == filter_email)
    total_result = await db.execute(
        select(func.count(User.id)).join(Membership, Membership.user_id == User.id).where(*filters)
    )
    total_results = int(total_result.scalar_one() or 0)
    result = await db.execute(
        select(User, Membership, Role)
        .join(Membership, Membership.user_id == User.id)
        .join(Role, Role.id == Membership.role_id)
        .where(*filters)
        .order_by(*scim_user_ordering(sortBy, sortOrder))
        .offset(startIndex - 1)
        .limit(count)
    )
    resources = [scim_user_resource(user, org, membership, role) for user, membership, role in result.all()]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total_results,
        "itemsPerPage": len(resources),
        "startIndex": startIndex,
        "Resources": resources,
    }


@app.post("/scim/v2/Users")
async def scim_create_user(
    body: dict[str, Any],
    request: Request,
    response: Response,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    email = scim_user_email(body)
    role_name = scim_role_name(body)
    display_name = scim_display_name(body)
    active = scim_bool(body.get("active"), default=True)
    password = scim_password(body)
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        user = User(
            email=email,
            display_name=display_name,
            password_hash=None,
            email_verified=True,
            disabled=not active,
        )
        db.add(user)
        await db.flush()
    membership, role, _revoked_sessions = await scim_apply_user_state(
        db,
        user=user,
        org=org,
        principal=principal,
        request=request,
        display_name=display_name,
        active=active,
        role_name=role_name or SCIM_UNSET,
        password=password,
        external_id=scim_external_id(body),
        enterprise_profile=scim_enterprise_profile(body),
        audit_action="scim.user.upsert",
    )
    await db.commit()
    await db.refresh(user)
    response.status_code = 201
    return scim_user_resource(user, org, membership, role)


@app.get("/scim/v2/Users/{user_id}")
async def scim_get_user(
    user_id: str,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    user, membership, role = await scim_user_row(db, user_id=user_id, org_id=org.id)
    return scim_user_resource(user, org, membership, role)


@app.put("/scim/v2/Users/{user_id}")
async def scim_replace_user(
    user_id: str,
    body: dict[str, Any],
    request: Request,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    user, _membership, _role = await scim_user_row(db, user_id=user_id, org_id=org.id)
    email = scim_user_email(body)
    if email != user.email:
        raise HTTPException(status_code=400, detail="SCIM userName changes are not supported")
    membership, role, _revoked_sessions = await scim_apply_user_state(
        db,
        user=user,
        org=org,
        principal=principal,
        request=request,
        display_name=scim_display_name(body),
        active=scim_bool(body.get("active"), default=True),
        role_name=scim_role_name(body) or SCIM_UNSET,
        password=scim_password(body),
        external_id=scim_external_id(body),
        enterprise_profile=scim_enterprise_profile(body),
        audit_action="scim.user.replace",
    )
    await db.commit()
    await db.refresh(user)
    return scim_user_resource(user, org, membership, role)


@app.patch("/scim/v2/Users/{user_id}")
async def scim_patch_user(
    user_id: str,
    body: dict[str, Any],
    request: Request,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    user, _membership, _role = await scim_user_row(db, user_id=user_id, org_id=org.id)
    active, display_name, role_name, password, external_id, enterprise_profile = scim_patch_values(body)
    membership, role, _revoked_sessions = await scim_apply_user_state(
        db,
        user=user,
        org=org,
        principal=principal,
        request=request,
        active=active,
        display_name=display_name,
        role_name=role_name,
        password=password,
        external_id=external_id,
        enterprise_profile=enterprise_profile,
        audit_action="scim.user.patch",
    )
    await db.commit()
    await db.refresh(user)
    return scim_user_resource(user, org, membership, role)


@app.delete("/scim/v2/Users/{user_id}")
async def scim_delete_user(
    user_id: str,
    request: Request,
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await scim_selected_org(db, principal, org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    user, _membership, _role = await scim_user_row(db, user_id=user_id, org_id=org.id)
    await scim_apply_user_state(
        db,
        user=user,
        org=org,
        principal=principal,
        request=request,
        active=False,
        audit_action="scim.user.delete",
    )
    await db.commit()
    return Response(status_code=204)


@app.get("/api/v1/users", response_model=list[UserAdminRead])
async def list_users(
    org_id: str | None = None,
    q: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(User).order_by(User.created_at.desc()).limit(limit)
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.join(Membership, Membership.user_id == User.id).where(Membership.org_id.in_(visible_org_ids))
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(User.email.ilike(pattern) | User.display_name.ilike(pattern))
    result = await db.execute(query)
    users = result.scalars().unique().all()
    return [await user_admin_read(db, user, visible_org_ids) for user in users]


@app.post("/api/v1/users/provision", response_model=UserProvisionResponse)
async def provision_user(
    body: UserProvisionRequest,
    request: Request,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, body.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    role = await resolve_org_role(db, org_id=org_id, role_id=body.role_id, role_name=body.role)

    email = str(body.email).strip().lower()
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()
    created_user = user is None
    if user is None:
        user = User(
            email=email,
            display_name=body.display_name.strip() or None if body.display_name else None,
            password_hash=None,
            email_verified=bool(body.email_verified),
            disabled=bool(body.disabled),
        )
        db.add(user)
        await db.flush()
    else:
        if "display_name" in body.model_fields_set:
            user.display_name = body.display_name.strip() or None if body.display_name else None
        if body.email_verified is not None:
            user.email_verified = body.email_verified

    membership_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id, Membership.org_id == org_id)
    )
    membership = membership_result.scalar_one_or_none()
    created_membership = membership is None
    current_role = await db.get(Role, membership.role_id) if membership else None
    if membership and current_role and membership.status == "active" and current_role.name == "owner":
        if body.status != "active" or role.name != "owner":
            await ensure_other_active_owner(db, org_id=org_id, user_id=user.id)
    if body.disabled is True and not user.disabled:
        await ensure_user_can_deactivate(db, user_id=user.id)

    membership_changed = created_membership
    if membership:
        membership_changed = membership.role_id != role.id or membership.status != body.status
        membership.role_id = role.id
        membership.status = body.status
    else:
        membership = Membership(org_id=org_id, user_id=user.id, role_id=role.id, status=body.status)
        db.add(membership)
    disabled_changed = body.disabled is not None and user.disabled != body.disabled
    if body.disabled is not None:
        user.disabled = body.disabled

    revoked_sessions = 0
    if not created_user and (membership_changed or disabled_changed):
        revoked_sessions = await revoke_user_sessions(db, user_id=user.id)
    await audit(
        db,
        "user.provision",
        org_id=org_id,
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=user.id,
        details={
            "email": email,
            "role": role.name,
            "status": body.status,
            "created_user": created_user,
            "created_membership": created_membership,
            "disabled": user.disabled,
            "revoked_sessions": revoked_sessions,
        },
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return UserProvisionResponse(
        status="created" if created_user else "updated",
        created_user=created_user,
        created_membership=created_membership,
        revoked_sessions=revoked_sessions,
        user=await user_admin_read(db, user, [org_id]),
    )


@app.get("/api/v1/users/{user_id}", response_model=UserAdminRead)
async def get_user_admin(
    user_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    visible_org_ids = await ensure_user_admin_visible(db, user_id=user.id, principal=principal)
    return await user_admin_read(db, user, visible_org_ids)


@app.patch("/api/v1/users/{user_id}", response_model=UserAdminRead)
async def update_user_admin(
    user_id: str,
    body: UserAdminUpdate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    visible_org_ids = await ensure_user_admin_visible(db, user_id=user.id, principal=principal)
    await require_admin_step_up_for_orgs(
        db,
        principal=principal,
        org_ids=visible_org_ids if visible_org_ids is not None else [principal.org_id],
    )
    if body.disabled is True and not user.disabled:
        owner_memberships = await db.execute(
            select(Membership)
            .join(Role, Role.id == Membership.role_id)
            .where(
                Membership.user_id == user.id,
                Membership.status == "active",
                Role.name == "owner",
            )
        )
        for membership in owner_memberships.scalars():
            await ensure_other_active_owner(db, org_id=membership.org_id, user_id=user.id)
        await revoke_user_sessions(db, user_id=user.id)
    if "display_name" in body.model_fields_set:
        user.display_name = body.display_name
    if body.email_verified is not None:
        user.email_verified = body.email_verified
    if body.disabled is not None:
        user.disabled = body.disabled
    await audit(
        db,
        "user.update",
        org_id=principal.org_id,
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=user.id,
        details=body.model_dump(exclude_unset=True),
    )
    await db.commit()
    await db.refresh(user)
    return await user_admin_read(db, user, visible_org_ids)


@app.put("/api/v1/users/{user_id}/membership", response_model=UserAdminRead)
async def update_user_membership(
    user_id: str,
    body: UserMembershipUpdate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    org = await db.get(Organization, body.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    role = await resolve_org_role(db, org_id=org_id, role_id=body.role_id, role_name=body.role)

    membership_result = await db.execute(
        select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)
    )
    membership = membership_result.scalar_one_or_none()
    current_role = await db.get(Role, membership.role_id) if membership else None
    if membership and current_role and membership.status == "active" and current_role.name == "owner":
        if body.status != "active" or role.name != "owner":
            await ensure_other_active_owner(db, org_id=org_id, user_id=user.id)
    if membership:
        membership.role_id = role.id
        membership.status = body.status
    else:
        membership = Membership(org_id=org_id, user_id=user.id, role_id=role.id, status=body.status)
        db.add(membership)
    revoked_count = await revoke_user_sessions(db, user_id=user.id)
    await audit(
        db,
        "user.membership.update",
        org_id=org_id,
        actor_user_id=principal.user_id,
        target_type="membership",
        target_id=membership.id,
        details={"user_id": user.id, "role": role.name, "status": body.status, "revoked_sessions": revoked_count},
    )
    await db.commit()
    await db.refresh(user)
    return await user_admin_read(db, user, [org_id])


@app.post("/api/v1/users/{user_id}/sessions/revoke", response_model=UserSessionsRevokeResponse)
async def revoke_admin_user_sessions(
    user_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    visible_org_ids = await ensure_user_admin_visible(db, user_id=user.id, principal=principal)
    await require_admin_step_up_for_orgs(
        db,
        principal=principal,
        org_ids=visible_org_ids if visible_org_ids is not None else [principal.org_id],
    )
    revoked_count = await revoke_user_sessions(db, user_id=user.id)
    await audit(
        db,
        "user.sessions.revoke",
        org_id=principal.org_id or (visible_org_ids[0] if visible_org_ids else None),
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=user.id,
        details={"revoked_sessions": revoked_count},
    )
    await db.commit()
    return UserSessionsRevokeResponse(status="revoked", revoked_count=revoked_count)


@app.post("/api/v1/users/{user_id}/mfa/totp/reset", response_model=UserMfaResetResponse)
async def reset_admin_user_totp(
    user_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    visible_org_ids = await ensure_user_admin_visible(db, user_id=user.id, principal=principal)
    await require_admin_step_up_for_orgs(
        db,
        principal=principal,
        org_ids=visible_org_ids if visible_org_ids is not None else [principal.org_id],
    )
    had_enabled_totp = bool(user.mfa_totp_enabled_at)
    had_pending_totp = bool(user.mfa_totp_secret_encrypted and not user.mfa_totp_enabled_at)
    user.mfa_totp_secret_encrypted = None
    user.mfa_totp_enabled_at = None
    await retire_recovery_codes(db, user.id)
    revoked_count = await revoke_user_sessions(db, user_id=user.id)
    await audit(
        db,
        "user.mfa.totp.reset",
        org_id=principal.org_id or (visible_org_ids[0] if visible_org_ids else None),
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=user.id,
        details={
            "totp_was_enabled": had_enabled_totp,
            "totp_was_pending": had_pending_totp,
            "revoked_sessions": revoked_count,
        },
    )
    await db.commit()
    await db.refresh(user)
    return UserMfaResetResponse(
        status="reset",
        revoked_count=revoked_count,
        user=await user_admin_read(db, user, visible_org_ids),
    )


@app.post("/api/v1/users/{user_id}/delete", response_model=UserDeleteResponse)
async def delete_user_admin(
    user_id: str,
    body: UserDeleteRequest,
    request: Request,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if principal.user_id == user.id:
        raise HTTPException(status_code=400, detail="Use self-service account deactivation for the current user")
    visible_org_ids = await ensure_user_admin_visible(db, user_id=user.id, principal=principal)
    policy_org_ids = await ensure_user_hard_delete_policy(db, user_id=user.id, visible_org_ids=visible_org_ids)
    await require_admin_step_up_for_orgs(
        db,
        principal=principal,
        org_ids=policy_org_ids or (visible_org_ids if visible_org_ids is not None else [principal.org_id]),
    )
    await ensure_user_can_deactivate(db, user_id=user.id)
    counts = await count_user_delete_artifacts(db, user_id=user.id)

    if body.dry_run:
        return UserDeleteResponse(
            status="preview",
            dry_run=True,
            user_id=user.id,
            email=user.email,
            counts=counts,
            policy_org_ids=policy_org_ids,
        )
    if str(body.confirm_email or "").strip().lower() != user.email:
        raise HTTPException(status_code=400, detail="Confirm email must match the user email")

    deleted_user_id = user.id
    deleted_email = user.email
    await db.execute(update(AuditEvent).where(AuditEvent.actor_user_id == user.id).values(actor_user_id=None))
    await db.execute(update(Invitation).where(Invitation.invited_by_user_id == user.id).values(invited_by_user_id=None))
    await db.execute(update(Invitation).where(Invitation.accepted_user_id == user.id).values(accepted_user_id=None))
    await audit(
        db,
        "user.hard_delete",
        org_id=principal.org_id or (policy_org_ids[0] if policy_org_ids else None),
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=deleted_user_id,
        details={"email": deleted_email, "counts": counts, "policy_org_ids": policy_org_ids},
        request=request,
    )
    for model in (
        RefreshToken,
        Session,
        ApiToken,
        OAuthGrant,
        Identity,
        MfaRecoveryCode,
        WebAuthnCredential,
        DeviceGrant,
        OAuthAuthorizationCode,
        OneTimeCode,
        Membership,
    ):
        await db.execute(delete(model).where(model.user_id == user.id))
    await db.delete(user)
    await db.commit()
    return UserDeleteResponse(
        status="deleted",
        dry_run=False,
        user_id=deleted_user_id,
        email=deleted_email,
        counts=counts,
        policy_org_ids=policy_org_ids,
    )


async def invitation_role(db: AsyncSession, *, org_id: str, role_id: str | None, role_name: str | None) -> Role:
    query = select(Role).where(Role.org_id == org_id)
    if role_id:
        query = query.where(Role.id == role_id)
    elif role_name:
        query = query.where(Role.name == role_name)
    else:
        query = query.where(Role.name == "viewer")
    result = await db.execute(query)
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


async def invitation_read(db: AsyncSession, invitation: Invitation) -> InvitationRead:
    result = await db.execute(
        select(Invitation, Organization, Role)
        .join(Organization, Organization.id == Invitation.org_id)
        .join(Role, Role.id == Invitation.role_id)
        .where(Invitation.id == invitation.id)
    )
    row = result.one()
    item, org, role = row
    return InvitationRead(
        id=item.id,
        org_id=org.id,
        org_name=org.name,
        email=item.email,
        role_id=role.id,
        role=role.name,
        permissions=role.permissions or [],
        invited_by_user_id=item.invited_by_user_id,
        accepted_user_id=item.accepted_user_id,
        token_hint=item.token_hint,
        expires_at=item.expires_at,
        accepted_at=item.accepted_at,
        revoked_at=item.revoked_at,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


@app.get("/api/v1/invitations", response_model=list[InvitationRead])
async def list_invitations(
    org_id: str | None = None,
    include_inactive: bool = False,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(Invitation).order_by(Invitation.created_at.desc()).limit(200)
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.where(Invitation.org_id.in_(visible_org_ids))
    if not include_inactive:
        query = query.where(
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
            Invitation.expires_at > now_utc(),
        )
    result = await db.execute(query)
    return [await invitation_read(db, invitation) for invitation in result.scalars()]


@app.post("/api/v1/invitations", response_model=InvitationCreateResponse)
async def create_invitation(
    body: InvitationCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    role = await invitation_role(db, org_id=org.id, role_id=body.role_id, role_name=body.role)
    email = str(body.email).lower()
    revoked_at = now_utc()
    existing_result = await db.execute(
        select(Invitation).where(
            Invitation.org_id == org.id,
            Invitation.email == email,
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
            Invitation.expires_at > revoked_at,
        )
    )
    for existing in existing_result.scalars():
        existing.revoked_at = revoked_at
    raw_token = new_opaque_token("gki")
    invitation = Invitation(
        org_id=org.id,
        email=email,
        role_id=role.id,
        invited_by_user_id=principal.user_id,
        token_hash=token_hash(raw_token),
        token_hint=token_hint(raw_token),
        expires_at=utc_after(days=body.expires_in_days),
    )
    db.add(invitation)
    await db.flush()
    send_invitation_email(email=email, token=raw_token, org_name=org.name, role_name=role.name)
    await audit(
        db,
        "invitation.create",
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="invitation",
        target_id=invitation.id,
        details={"email": email, "role": role.name, "expires_in_days": body.expires_in_days},
    )
    await db.commit()
    read = await invitation_read(db, invitation)
    return InvitationCreateResponse(**read.model_dump(), token=raw_token)


@app.delete("/api/v1/invitations/{invitation_id}")
async def revoke_invitation(
    invitation_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    invitation = await db.get(Invitation, invitation_id)
    if not invitation:
        raise HTTPException(status_code=404, detail="Invitation not found")
    if principal.org_id and invitation.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="Invitation not found")
    if invitation.org_id and principal.user_id:
        await ensure_user_org_membership(db, user_id=principal.user_id, org_id=invitation.org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=invitation.org_id)
    invitation.revoked_at = invitation.revoked_at or now_utc()
    await audit(
        db,
        "invitation.revoke",
        org_id=invitation.org_id,
        actor_user_id=principal.user_id,
        target_type="invitation",
        target_id=invitation.id,
        details={"email": invitation.email},
    )
    await db.commit()
    return {"status": "revoked", "id": invitation.id}


@app.post("/api/v1/auth/invitations/accept", response_model=TokenResponse)
async def accept_invitation(
    body: InvitationAcceptRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    email = str(body.email).lower()
    await enforce_rate_limit(
        db,
        key=f"invitation-accept:{email}:{request.client.host if request.client else 'unknown'}",
        limit=10,
        window_seconds=300,
    )
    result = await db.execute(select(Invitation).where(Invitation.token_hash == token_hash(body.token.strip())))
    invitation = result.scalar_one_or_none()
    if (
        not invitation
        or invitation.accepted_at
        or invitation.revoked_at
        or invitation.expires_at <= now_utc()
    ):
        raise HTTPException(status_code=401, detail="Invalid or expired invitation")
    if invitation.email != email:
        raise HTTPException(status_code=403, detail="Invitation email mismatch")
    role = await db.get(Role, invitation.role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()
    amr = ["pwd"]
    if user:
        if user.disabled or not verify_password(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if user.mfa_totp_enabled_at:
            if body.totp_code:
                verify_user_totp(user, body.totp_code)
                amr.append("otp")
            elif body.recovery_code:
                await verify_user_recovery_code(db, user, body.recovery_code)
                amr.append("recovery")
            else:
                raise HTTPException(status_code=401, detail="TOTP code required")
    else:
        user = await create_user(
            db,
            email=email,
            password=body.password,
            display_name=body.display_name,
            verified=True,
        )

    membership_result = await db.execute(
        select(Membership).where(Membership.org_id == invitation.org_id, Membership.user_id == user.id)
    )
    membership = membership_result.scalar_one_or_none()
    if membership:
        membership.role_id = role.id
        membership.status = "active"
    else:
        db.add(Membership(org_id=invitation.org_id, user_id=user.id, role_id=role.id, status="active"))
    invitation.accepted_at = now_utc()
    invitation.accepted_user_id = user.id
    access, refresh, _session, _refresh_model = await create_session_tokens(
        db,
        user,
        request=request,
        org_id=invitation.org_id,
        amr=amr,
    )
    await audit(
        db,
        "invitation.accept",
        org_id=invitation.org_id,
        actor_user_id=user.id,
        target_type="invitation",
        target_id=invitation.id,
        details={"email": email, "role": role.name},
    )
    await db.commit()
    set_session_cookie(response, access)
    set_refresh_cookie(response, refresh)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join((role.permissions or []) or ["auth:read"]),
        user=user_read(user),
        orgs=await org_roles(db, user.id),
    )


@app.post("/api/v1/auth/email-code/request")
async def request_email_code(body: EmailCodeRequest, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(
        db,
        key=f"email-code:{str(body.email).lower()}:{body.purpose}",
        limit=5,
        window_seconds=900,
    )
    user_result = await db.execute(select(User).where(User.email == str(body.email).lower()))
    user = user_result.scalar_one_or_none()
    code = await create_one_time_code(
        db,
        email=str(body.email),
        purpose=body.purpose,
        user_id=user.id if user else None,
    )
    send_one_time_code(email=str(body.email), code=code, purpose=body.purpose)
    await db.commit()
    return {"status": "sent"}


@app.post("/api/v1/auth/email-code/verify", response_model=TokenResponse)
async def verify_email_code(
    body: EmailCodeVerify,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    await verify_one_time_code(db, email=str(body.email), purpose=body.purpose, code=body.code)
    result = await db.execute(select(User).where(User.email == str(body.email).lower()))
    user = result.scalar_one_or_none()
    if not user:
        user = await create_user(db, email=str(body.email), password=None, verified=True)
    if body.purpose == "verify_email":
        user.email_verified = True
    access, refresh, _session, _refresh_model = await create_session_tokens(db, user, request=request, amr=["email"])
    orgs = await org_roles(db, user.id)
    await audit(db, f"auth.email_code.{body.purpose}", actor_user_id=user.id, request=request)
    await db.commit()
    set_session_cookie(response, access)
    set_refresh_cookie(response, refresh)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(derive_membership_scopes(orgs)),
        user=user_read(user),
        orgs=orgs,
    )


@app.post("/api/v1/auth/password/reset/request")
async def request_password_reset(body: EmailCodeRequest, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(
        db,
        key=f"password-reset:{str(body.email).lower()}",
        limit=5,
        window_seconds=900,
    )
    result = await db.execute(select(User).where(User.email == str(body.email).lower()))
    user = result.scalar_one_or_none()
    if user:
        code = await create_one_time_code(
            db,
            email=str(body.email),
            purpose="reset_password",
            user_id=user.id,
        )
        send_one_time_code(email=str(body.email), code=code, purpose="reset_password")
        await db.commit()
    return {"status": "sent"}


@app.post("/api/v1/auth/password/reset/confirm")
async def confirm_password_reset(
    body: PasswordResetConfirm,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    await verify_one_time_code(
        db,
        email=str(body.email),
        purpose="reset_password",
        code=body.code,
    )
    result = await db.execute(select(User).where(User.email == str(body.email).lower()))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password_hash = hash_password(body.new_password)
    await audit(db, "auth.password.reset", actor_user_id=user.id, request=request)
    await db.commit()
    return {"status": "updated"}


def session_read(
    session: Session,
    *,
    client: AuthClient | None = None,
    current_session_id: str | None = None,
) -> SessionRead:
    return SessionRead(
        id=session.id,
        user_id=session.user_id,
        org_id=session.org_id,
        auth_client_id=session.client_id,
        client_id=client.client_id if client else None,
        client_name=client.name if client else None,
        client_public=client.public if client else None,
        current=bool(current_session_id and session.id == current_session_id),
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        device_label=session.device_label,
        amr=session.amr or [],
        trusted=bool(session.trusted_at and (not session.trusted_until or session.trusted_until > now_utc())),
        trusted_at=session.trusted_at,
        trusted_until=session.trusted_until,
        last_seen_at=session.last_seen_at,
        expires_at=session.expires_at,
        revoked_at=session.revoked_at,
        created_at=session.created_at,
    )


@app.get("/api/v1/sessions", response_model=list[SessionRead])
async def list_sessions(
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Session, AuthClient)
        .join(AuthClient, AuthClient.id == Session.client_id, isouter=True)
        .order_by(Session.created_at.desc())
    )
    if "*" not in principal.scopes and principal.user_id:
        query = query.where(Session.user_id == principal.user_id)
    result = await db.execute(query)
    return [
        session_read(session, client=client, current_session_id=principal.session_id)
        for session, client in result.all()
    ]


@app.post("/api/v1/sessions/revoke-all", response_model=SessionRevokeAllResponse)
async def revoke_all_sessions(
    body: SessionRevokeAllRequest,
    response: Response,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    query = select(Session).where(Session.user_id == principal.user_id, Session.revoked_at.is_(None))
    if not body.include_current and principal.session_id:
        query = query.where(Session.id != principal.session_id)
    result = await db.execute(query)
    sessions = list(result.scalars())
    revoked_at = now_utc()
    session_ids = []
    for session in sessions:
        session.revoked_at = revoked_at
        session_ids.append(session.id)
    if session_ids:
        refresh_result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.session_id.in_(session_ids),
                RefreshToken.revoked_at.is_(None),
            )
        )
        for refresh in refresh_result.scalars():
            refresh.revoked_at = revoked_at
    await audit(
        db,
        "session.revoke_all",
        org_id=principal.org_id,
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=principal.user_id,
        details={"include_current": body.include_current, "revoked_count": len(session_ids)},
    )
    await db.commit()
    if body.include_current:
        delete_session_cookie(response)
    return SessionRevokeAllResponse(
        status="revoked",
        revoked_count=len(session_ids),
        include_current=body.include_current,
    )


@app.patch("/api/v1/sessions/{session_id}/device", response_model=SessionRead)
async def update_session_device(
    session_id: str,
    body: SessionDeviceUpdate,
    request: Request,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Session, AuthClient)
        .join(AuthClient, AuthClient.id == Session.client_id, isouter=True)
        .where(Session.id == session_id)
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    session, client = row
    if not principal.user_id or principal.user_id != session.user_id:
        raise HTTPException(status_code=403, detail="Session ownership required")
    if session.revoked_at:
        raise HTTPException(status_code=400, detail="Cannot manage a revoked session")

    details: dict[str, object] = {}
    if "device_label" in body.model_fields_set:
        label = body.device_label.strip() if body.device_label else None
        session.device_label = label or None
        details["device_label"] = session.device_label
    if "trusted" in body.model_fields_set and body.trusted is not None:
        if body.trusted:
            trusted_until = body.trusted_until
            if trusted_until and trusted_until.tzinfo:
                trusted_until = trusted_until.astimezone(UTC).replace(tzinfo=None)
            trusted_until = trusted_until or utc_after(days=90)
            if trusted_until <= now_utc():
                raise HTTPException(status_code=400, detail="Trusted device expiry must be in the future")
            if not session.device_id_hash and request.cookies.get(settings.device_cookie_name):
                session.device_id_hash = token_hash(str(request.cookies[settings.device_cookie_name]))
            session.trusted_at = now_utc()
            session.trusted_until = trusted_until
            details["trusted"] = True
            details["trusted_until"] = trusted_until.isoformat()
        else:
            session.trusted_at = None
            session.trusted_until = None
            details["trusted"] = False
    if details:
        await audit(
            db,
            "session.device.update",
            org_id=session.org_id,
            actor_user_id=principal.user_id,
            target_type="session",
            target_id=session.id,
            details=details,
            request=request,
        )
    await db.commit()
    return session_read(session, client=client, current_session_id=principal.session_id)


@app.delete("/api/v1/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    session = await db.get(Session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if "*" not in principal.scopes and principal.user_id != session.user_id:
        raise HTTPException(status_code=403, detail="Session ownership required")
    session.revoked_at = now_utc()
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.session_id == session.id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    for refresh in result.scalars():
        refresh.revoked_at = refresh.revoked_at or session.revoked_at
    await audit(
        db,
        "session.revoke",
        org_id=session.org_id,
        actor_user_id=principal.user_id,
        target_type="session",
        target_id=session.id,
    )
    await db.commit()
    return {"status": "revoked", "id": session.id}


def settings_oauth_provider_configs() -> dict[str, OAuthProviderConfig]:
    try:
        return settings.oauth_provider_configs()
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=f"OAuth provider configuration is invalid: {exc}") from exc


def normalize_provider_scopes(scopes: list[str] | None) -> list[str]:
    normalized = [scope.strip() for scope in scopes or [] if scope.strip()]
    return normalized or ["openid", "email", "profile"]


def validate_provider_url(value: str, *, field_name: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail=f"{field_name} must be an absolute HTTP(S) URL")
    return value


def provider_config_from_model(provider: OAuthProvider) -> OAuthProviderConfig:
    client_secret = ""
    if provider.client_secret_encrypted:
        try:
            client_secret = decrypt_secret(provider.client_secret_encrypted)
        except ValueError as exc:
            raise HTTPException(status_code=500, detail="OAuth provider secret cannot be decrypted") from exc
    return OAuthProviderConfig(
        id=provider.provider_id,
        name=provider.name,
        client_id=provider.client_id,
        client_secret=client_secret,
        authorization_url=provider.authorization_url,
        token_url=provider.token_url,
        userinfo_url=provider.userinfo_url,
        redirect_uri=provider.redirect_uri,
        scopes=normalize_provider_scopes(provider.scopes),
        subject_claim=provider.subject_claim,
        email_claim=provider.email_claim,
        name_claim=provider.name_claim,
        email_verified_claim=provider.email_verified_claim,
        allow_email_linking=provider.allow_email_linking,
        require_verified_email=provider.require_verified_email,
    )


async def oauth_provider_configs(db: AsyncSession) -> dict[str, OAuthProviderConfig]:
    providers = settings_oauth_provider_configs()
    result = await db.execute(select(OAuthProvider).where(OAuthProvider.enabled.is_(True)))
    for provider in result.scalars():
        providers[provider.provider_id] = provider_config_from_model(provider)
    return providers


async def get_oauth_provider(db: AsyncSession, provider_id: str) -> OAuthProviderConfig:
    provider = (await oauth_provider_configs(db)).get(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="OAuth provider not found")
    return provider


async def get_db_oauth_provider(db: AsyncSession, provider_id: str) -> OAuthProvider | None:
    result = await db.execute(select(OAuthProvider).where(OAuthProvider.provider_id == provider_id))
    return result.scalar_one_or_none()


async def require_install_owner(db: AsyncSession, principal: Principal) -> Organization:
    if "*" not in principal.scopes or not principal.org_id:
        raise HTTPException(status_code=403, detail="Install owner required")
    result = await db.execute(select(Organization).where(Organization.slug == settings.bootstrap_org_slug))
    bootstrap_org = result.scalar_one_or_none()
    if not bootstrap_org or principal.org_id != bootstrap_org.id:
        raise HTTPException(status_code=403, detail="Install owner required")
    return bootstrap_org


def provider_admin_read_from_config(provider: OAuthProviderConfig) -> OAuthProviderAdminRead:
    return OAuthProviderAdminRead(
        id=provider.id,
        provider_id=provider.id,
        source="env",
        read_only=True,
        name=provider.name,
        enabled=True,
        configured=provider.configured,
        client_id=provider.client_id,
        client_secret_configured=bool(provider.client_secret),
        authorization_url=provider.authorization_url,
        token_url=provider.token_url,
        userinfo_url=provider.userinfo_url,
        redirect_uri=oauth_provider_redirect_uri(provider),
        scopes=provider.scopes,
        subject_claim=provider.subject_claim,
        email_claim=provider.email_claim,
        name_claim=provider.name_claim,
        email_verified_claim=provider.email_verified_claim,
        allow_email_linking=provider.allow_email_linking,
        require_verified_email=provider.require_verified_email,
    )


def provider_admin_read(provider: OAuthProvider) -> OAuthProviderAdminRead:
    configured = bool(provider.client_id and provider.client_secret_encrypted)
    return OAuthProviderAdminRead(
        id=provider.id,
        provider_id=provider.provider_id,
        source="database",
        read_only=False,
        name=provider.name,
        enabled=provider.enabled,
        configured=configured,
        client_id=provider.client_id,
        client_secret_configured=bool(provider.client_secret_encrypted),
        authorization_url=provider.authorization_url,
        token_url=provider.token_url,
        userinfo_url=provider.userinfo_url,
        redirect_uri=provider.redirect_uri or f"{settings.issuer}/api/v1/auth/oauth/{provider.provider_id}/callback",
        scopes=normalize_provider_scopes(provider.scopes),
        subject_claim=provider.subject_claim,
        email_claim=provider.email_claim,
        name_claim=provider.name_claim,
        email_verified_claim=provider.email_verified_claim,
        allow_email_linking=provider.allow_email_linking,
        require_verified_email=provider.require_verified_email,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


def oauth_provider_redirect_uri(provider: OAuthProviderConfig) -> str:
    return provider.redirect_uri or f"{settings.issuer}/api/v1/auth/oauth/{provider.id}/callback"


def safe_internal_redirect(value: str | None) -> str | None:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return None


def oauth_provider_state(
    provider_id: str,
    redirect: str | None,
    *,
    intent: str = "login",
    user_id: str | None = None,
    session_id: str | None = None,
) -> str:
    claims: dict[str, object] = {
        "provider": provider_id,
        "intent": intent,
        "nonce": new_opaque_token("gkos"),
        "exp": int(time.time()) + 600,
    }
    if user_id:
        claims["user_id"] = user_id
    if session_id:
        claims["session_id"] = session_id
    safe_redirect = safe_internal_redirect(redirect)
    if safe_redirect:
        claims["redirect"] = safe_redirect
    return jwt.encode(claims, settings.secret_key, algorithm="HS256")


def oauth_provider_state_claims(provider_id: str, state: str | None) -> dict[str, Any]:
    if not state:
        return {"provider": provider_id, "intent": "login"}
    try:
        claims = jwt.decode(state, settings.secret_key, algorithms=["HS256"])
    except JWTError as exc:
        raise HTTPException(status_code=400, detail="Invalid OAuth state") from exc
    if claims.get("provider") != provider_id:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    return claims


def oauth_provider_redirect_from_claims(claims: dict[str, Any]) -> str:
    return safe_internal_redirect(str(claims.get("redirect") or "")) or "/account"


def oauth_provider_redirect_from_state(provider_id: str, state: str | None) -> str:
    return oauth_provider_redirect_from_claims(oauth_provider_state_claims(provider_id, state))


def callback_redirect_url(path: str) -> str:
    if path.startswith("/oauth/"):
        return f"{settings.issuer}{path}"
    return f"{settings.ui_url.rstrip('/')}{path}"


def oauth_provider_read(provider: OAuthProviderConfig) -> OAuthProviderRead:
    return OAuthProviderRead(
        id=provider.id,
        name=provider.name,
        configured=provider.configured,
        scopes=provider.scopes,
        start_url=f"{settings.issuer}/api/v1/auth/oauth/{provider.id}/start",
        authorization_url=provider.authorization_url,
        require_verified_email=provider.require_verified_email,
        allow_email_linking=provider.allow_email_linking,
    )


@app.get("/api/v1/auth/oauth/providers/admin", response_model=list[OAuthProviderAdminRead])
async def list_admin_oauth_providers(
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    await require_install_owner(db, principal)
    env_providers = [
        provider_admin_read_from_config(provider)
        for provider in sorted(settings_oauth_provider_configs().values(), key=lambda item: item.name)
    ]
    result = await db.execute(select(OAuthProvider).order_by(OAuthProvider.name.asc()))
    db_providers = [provider_admin_read(provider) for provider in result.scalars()]
    return env_providers + db_providers


@app.post("/api/v1/auth/oauth/providers/admin", response_model=OAuthProviderAdminRead, status_code=201)
async def create_admin_oauth_provider(
    body: OAuthProviderAdminCreate,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    install_org = await require_install_owner(db, principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=install_org.id)
    if body.provider_id in settings_oauth_provider_configs():
        raise HTTPException(status_code=409, detail="Provider ID is managed by environment configuration")
    if await get_db_oauth_provider(db, body.provider_id):
        raise HTTPException(status_code=409, detail="OAuth provider already exists")
    provider = OAuthProvider(
        provider_id=body.provider_id,
        name=body.name,
        enabled=body.enabled,
        client_id=body.client_id.strip(),
        client_secret_encrypted=encrypt_secret(body.client_secret.strip()) if body.client_secret else None,
        authorization_url=validate_provider_url(body.authorization_url, field_name="authorization_url"),
        token_url=validate_provider_url(body.token_url, field_name="token_url"),
        userinfo_url=validate_provider_url(body.userinfo_url, field_name="userinfo_url"),
        redirect_uri=validate_provider_url(body.redirect_uri, field_name="redirect_uri") if body.redirect_uri else "",
        scopes=normalize_provider_scopes(body.scopes),
        subject_claim=body.subject_claim,
        email_claim=body.email_claim,
        name_claim=body.name_claim,
        email_verified_claim=body.email_verified_claim,
        allow_email_linking=body.allow_email_linking,
        require_verified_email=body.require_verified_email,
    )
    db.add(provider)
    await db.flush()
    await audit(
        db,
        "oauth_provider.create",
        org_id=install_org.id,
        actor_user_id=principal.user_id,
        target_type="oauth_provider",
        target_id=provider.provider_id,
        details={
            "enabled": provider.enabled,
            "configured": bool(provider.client_id and provider.client_secret_encrypted),
        },
        request=request,
    )
    await db.commit()
    await db.refresh(provider)
    return provider_admin_read(provider)


@app.patch("/api/v1/auth/oauth/providers/admin/{provider_id}", response_model=OAuthProviderAdminRead)
async def update_admin_oauth_provider(
    provider_id: str,
    body: OAuthProviderAdminUpdate,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    install_org = await require_install_owner(db, principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=install_org.id)
    provider = await get_db_oauth_provider(db, provider_id)
    if not provider:
        if provider_id in settings_oauth_provider_configs():
            raise HTTPException(status_code=400, detail="Environment-managed OAuth providers are read-only")
        raise HTTPException(status_code=404, detail="OAuth provider not found")

    changed: dict[str, object] = {}
    if body.name is not None:
        provider.name = body.name
        changed["name"] = body.name
    if body.enabled is not None:
        provider.enabled = body.enabled
        changed["enabled"] = body.enabled
    if body.client_id is not None:
        provider.client_id = body.client_id.strip()
        changed["client_id"] = bool(provider.client_id)
    if "client_secret" in body.model_fields_set:
        provider.client_secret_encrypted = encrypt_secret(body.client_secret.strip()) if body.client_secret else None
        changed["client_secret_configured"] = bool(provider.client_secret_encrypted)
    if body.authorization_url is not None:
        provider.authorization_url = validate_provider_url(body.authorization_url, field_name="authorization_url")
        changed["authorization_url"] = provider.authorization_url
    if body.token_url is not None:
        provider.token_url = validate_provider_url(body.token_url, field_name="token_url")
        changed["token_url"] = provider.token_url
    if body.userinfo_url is not None:
        provider.userinfo_url = validate_provider_url(body.userinfo_url, field_name="userinfo_url")
        changed["userinfo_url"] = provider.userinfo_url
    if "redirect_uri" in body.model_fields_set:
        provider.redirect_uri = (
            validate_provider_url(body.redirect_uri, field_name="redirect_uri") if body.redirect_uri else ""
        )
        changed["redirect_uri"] = provider.redirect_uri or "default"
    if body.scopes is not None:
        provider.scopes = normalize_provider_scopes(body.scopes)
        changed["scopes"] = provider.scopes
    if body.subject_claim is not None:
        provider.subject_claim = body.subject_claim
        changed["subject_claim"] = body.subject_claim
    if body.email_claim is not None:
        provider.email_claim = body.email_claim
        changed["email_claim"] = body.email_claim
    if body.name_claim is not None:
        provider.name_claim = body.name_claim
        changed["name_claim"] = body.name_claim
    if body.email_verified_claim is not None:
        provider.email_verified_claim = body.email_verified_claim
        changed["email_verified_claim"] = body.email_verified_claim
    if body.allow_email_linking is not None:
        provider.allow_email_linking = body.allow_email_linking
        changed["allow_email_linking"] = body.allow_email_linking
    if body.require_verified_email is not None:
        provider.require_verified_email = body.require_verified_email
        changed["require_verified_email"] = body.require_verified_email

    await audit(
        db,
        "oauth_provider.update",
        org_id=install_org.id,
        actor_user_id=principal.user_id,
        target_type="oauth_provider",
        target_id=provider.provider_id,
        details=changed,
        request=request,
    )
    await db.commit()
    await db.refresh(provider)
    return provider_admin_read(provider)


@app.delete("/api/v1/auth/oauth/providers/admin/{provider_id}")
async def delete_admin_oauth_provider(
    provider_id: str,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    install_org = await require_install_owner(db, principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=install_org.id)
    provider = await get_db_oauth_provider(db, provider_id)
    if not provider:
        if provider_id in settings_oauth_provider_configs():
            raise HTTPException(status_code=400, detail="Environment-managed OAuth providers are read-only")
        raise HTTPException(status_code=404, detail="OAuth provider not found")
    await audit(
        db,
        "oauth_provider.delete",
        org_id=install_org.id,
        actor_user_id=principal.user_id,
        target_type="oauth_provider",
        target_id=provider.provider_id,
        request=request,
    )
    await db.delete(provider)
    await db.commit()
    return {"status": "deleted", "id": provider_id}


def profile_claim(profile: dict[str, object], claim: str) -> str | None:
    value = profile.get(claim)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def profile_bool(profile: dict[str, object], claim: str) -> bool:
    value = profile.get(claim)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


async def fetch_oauth_provider_profile(provider: OAuthProviderConfig, code: str) -> dict[str, object]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_response = await client.post(
                provider.token_url,
                data={
                    "client_id": provider.client_id,
                    "client_secret": provider.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": oauth_provider_redirect_uri(provider),
                },
            )
            token_response.raise_for_status()
            provider_token = token_response.json()
            access_token = provider_token.get("access_token")
            if not access_token:
                raise HTTPException(status_code=502, detail="OAuth provider did not return an access token")
            userinfo = await client.get(
                provider.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            userinfo.raise_for_status()
            profile = userinfo.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="OAuth provider request failed") from exc
    if not isinstance(profile, dict):
        raise HTTPException(status_code=502, detail="OAuth provider profile response was invalid")
    return profile


async def start_oauth_provider(
    db: AsyncSession,
    provider_id: str,
    redirect: str | None = None,
    *,
    link_principal: Principal | None = None,
):
    provider = await get_oauth_provider(db, provider_id)
    if not provider.configured:
        raise HTTPException(status_code=503, detail=f"{provider.name} OAuth is not fully configured")
    state = oauth_provider_state(
        provider.id,
        redirect,
        intent="link" if link_principal else "login",
        user_id=link_principal.user_id if link_principal else None,
        session_id=link_principal.session_id if link_principal else None,
    )
    params = urlencode(
        {
            "client_id": provider.client_id,
            "redirect_uri": oauth_provider_redirect_uri(provider),
            "response_type": "code",
            "scope": " ".join(provider.scopes),
            "state": state,
        }
    )
    return {"provider": provider.id, "state": state, "authorization_url": f"{provider.authorization_url}?{params}"}


async def complete_oauth_provider_callback(
    provider_id: str,
    code: str,
    state: str | None,
    request: Request,
    db: AsyncSession,
    principal: Principal | None = None,
) -> RedirectResponse:
    provider = await get_oauth_provider(db, provider_id)
    if not provider.configured:
        raise HTTPException(status_code=503, detail=f"{provider.name} OAuth is not fully configured")
    state_claims = oauth_provider_state_claims(provider.id, state)
    intent = str(state_claims.get("intent") or "login")
    if intent not in {"login", "link"}:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    if intent == "link" and (
        not principal
        or principal.auth_type != "user"
        or not principal.user_id
        or not principal.session_id
        or principal.user_id != str(state_claims.get("user_id") or "")
        or principal.session_id != str(state_claims.get("session_id") or "")
    ):
        raise HTTPException(status_code=403, detail="Current session must match OAuth link state")
    profile = await fetch_oauth_provider_profile(provider, code)
    subject = profile_claim(profile, provider.subject_claim)
    email = profile_claim(profile, provider.email_claim)
    name = profile_claim(profile, provider.name_claim)
    email_verified = profile_bool(profile, provider.email_verified_claim)
    if not subject:
        raise HTTPException(status_code=400, detail="OAuth provider profile did not include a subject")
    if not email:
        raise HTTPException(status_code=400, detail="OAuth provider profile did not include an email")
    email = email.lower()

    identity_result = await db.execute(
        select(Identity).where(Identity.provider == provider.id, Identity.provider_subject == subject)
    )
    identity = identity_result.scalar_one_or_none()
    if intent == "link":
        user = await db.get(User, principal.user_id)
        if not user or user.disabled:
            raise HTTPException(status_code=401, detail="User is disabled")
        if provider.require_verified_email and not email_verified:
            raise HTTPException(status_code=403, detail="OAuth provider email must be verified before linking")
        if identity and identity.user_id != user.id:
            raise HTTPException(status_code=409, detail="OAuth identity is already linked to another account")
        if identity:
            identity.email = email
            linked_status = "updated"
        else:
            identity = Identity(
                user_id=user.id,
                provider=provider.id,
                provider_subject=subject,
                email=email,
            )
            db.add(identity)
            linked_status = "linked"
            await db.flush()
        await audit(
            db,
            "auth.identity.link",
            actor_user_id=user.id,
            target_type="identity",
            target_id=identity.id,
            details={"provider": provider.id, "email": email, "status": linked_status},
            request=request,
        )
        await db.commit()
        redirect_path = oauth_provider_redirect_from_claims(state_claims)
        return RedirectResponse(callback_redirect_url(redirect_path), status_code=302)

    user = await db.get(User, identity.user_id) if identity else None
    if not user and provider.allow_email_linking:
        user_result = await db.execute(select(User).where(User.email == email))
        user = user_result.scalar_one_or_none()
        if user and provider.require_verified_email and not email_verified:
            raise HTTPException(status_code=403, detail="OAuth provider email must be verified before linking")
    if not user:
        if provider.require_verified_email and not email_verified:
            raise HTTPException(status_code=403, detail="OAuth provider email must be verified before signup")
        user = await create_user(
            db,
            email=email,
            password=None,
            display_name=name,
            verified=email_verified,
        )
    if user.disabled:
        raise HTTPException(status_code=401, detail="User is disabled")
    if identity:
        identity.email = email
    else:
        db.add(
            Identity(
                user_id=user.id,
                provider=provider.id,
                provider_subject=subject,
                email=email,
            )
        )
    access, refresh, _session, _refresh_model = await create_session_tokens(
        db,
        user,
        request=request,
        amr=["federated"],
    )
    await audit(db, "auth.oauth.login", actor_user_id=user.id, details={"provider": provider.id}, request=request)
    await db.commit()
    redirect_path = oauth_provider_redirect_from_claims(state_claims)
    redirect = RedirectResponse(callback_redirect_url(redirect_path), status_code=302)
    set_session_cookie(redirect, access)
    set_refresh_cookie(redirect, refresh)
    return redirect


@app.get("/api/v1/auth/oauth/providers", response_model=list[OAuthProviderRead])
async def list_oauth_providers(db: AsyncSession = Depends(get_db)):
    providers = sorted((await oauth_provider_configs(db)).values(), key=lambda item: item.name)
    return [oauth_provider_read(provider) for provider in providers]


@app.get("/api/v1/auth/oauth/google/start")
async def google_start(redirect: str | None = None, db: AsyncSession = Depends(get_db)):
    providers = await oauth_provider_configs(db)
    if "google" not in providers:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    return await start_oauth_provider(db, "google", redirect)


@app.get("/api/v1/auth/oauth/google/callback")
async def google_callback(
    code: str,
    request: Request,
    state: str | None = None,
    principal: Principal | None = Depends(optional_principal),
    db: AsyncSession = Depends(get_db),
):
    providers = await oauth_provider_configs(db)
    if "google" not in providers:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    return await complete_oauth_provider_callback("google", code, state, request, db, principal=principal)


@app.get("/api/v1/auth/oauth/{provider_id}/start")
async def oauth_provider_start(provider_id: str, redirect: str | None = None, db: AsyncSession = Depends(get_db)):
    return await start_oauth_provider(db, provider_id, redirect)


@app.get("/api/v1/auth/oauth/{provider_id}/callback")
async def oauth_provider_callback(
    provider_id: str,
    code: str,
    request: Request,
    state: str | None = None,
    principal: Principal | None = Depends(optional_principal),
    db: AsyncSession = Depends(get_db),
):
    return await complete_oauth_provider_callback(provider_id, code, state, request, db, principal=principal)


@app.get("/oauth/authorize")
async def oauth_authorize_get(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    scope: str = "",
    state: str | None = None,
    audience: str | None = None,
    org_id: str | None = None,
    approve: bool = False,
    principal: Principal | None = Depends(optional_principal),
    db: AsyncSession = Depends(get_db),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    client = await get_client_by_client_id(db, client_id)
    validate_redirect(client, redirect_uri)
    selected_audience = validate_audience(client, audience)
    scopes = validate_scopes(client, scope)
    if not principal:
        login_url = f"{settings.ui_url.rstrip('/')}/login?{urlencode({'redirect': oauth_authorize_path(request)})}"
        return RedirectResponse(login_url, status_code=302)
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound authorization required")
    user = await db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    selected_org, _orgs = await resolve_authorize_org(db, client=client, principal=principal, org_id=org_id)
    selected_org_id = selected_org.id if selected_org else None
    amr = principal_amr(principal)
    try:
        await enforce_client_and_org_mfa_policy(
            db,
            client=client,
            org_id=selected_org_id or client.org_id,
            user=user,
            amr=amr,
            trusted_device=await principal_trusted_device_active(db, principal),
        )
    except HTTPException as exc:
        if exc.status_code == 403 and str(exc.detail).startswith("MFA required"):
            login_url = "{ui}/login?{query}".format(
                ui=settings.ui_url.rstrip("/"),
                query=urlencode({"redirect": oauth_authorize_path(request), "step_up": "mfa"}),
            )
            return RedirectResponse(login_url, status_code=302)
        raise
    if not approve:
        grant = await find_oauth_grant(
            db,
            user_id=principal.user_id,
            client=client,
            org_id=selected_org_id,
            audience=selected_audience,
            scopes=scopes,
        )
        if grant:
            return await issue_oauth_authorization_code(
                db,
                request=request,
                client=client,
                user_id=principal.user_id,
                org_id=selected_org_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                audience=selected_audience,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                amr=amr,
                state=state,
            )
        consent_url = f"{settings.ui_url.rstrip('/')}/authorize?{oauth_authorize_query(request)}"
        return RedirectResponse(consent_url, status_code=302)
    grant = await remember_oauth_grant(
        db,
        user_id=principal.user_id,
        client=client,
        org_id=selected_org_id,
        audience=selected_audience,
        scopes=scopes,
    )
    await audit(
        db,
        "oauth.grant.remember",
        org_id=selected_org_id,
        actor_user_id=principal.user_id,
        target_type="oauth_grant",
        target_id=grant.id,
        details={"client_id": client.id, "audience": selected_audience, "scopes": scopes},
        request=request,
    )
    return await issue_oauth_authorization_code(
        db,
        request=request,
        client=client,
        user_id=principal.user_id,
        org_id=selected_org_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        audience=selected_audience,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        amr=amr,
        state=state,
    )


@app.post("/oauth/authorize")
async def oauth_authorize_post(
    body: OAuthAuthorizeRequest,
    request: Request,
    principal: Principal | None = Depends(optional_principal),
    db: AsyncSession = Depends(get_db),
):
    return await oauth_authorize_get(
        request,
        body.response_type,
        body.client_id,
        body.redirect_uri,
        body.code_challenge,
        body.code_challenge_method,
        body.scope,
        body.state,
        body.audience,
        body.org_id,
        body.approve,
        principal,
        db,
    )


@app.get("/api/v1/oauth/authorize/context")
async def oauth_authorize_context(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    scope: str = "",
    state: str | None = None,
    audience: str | None = None,
    org_id: str | None = None,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound authorization required")
    client = await get_client_by_client_id(db, client_id)
    validate_redirect(client, redirect_uri)
    selected_audience = validate_audience(client, audience)
    scopes = validate_scopes(client, scope)
    selected_org, orgs = await resolve_authorize_org(db, client=client, principal=principal, org_id=org_id)
    return {
        "client": {
            "id": client.id,
            "name": client.name,
            "description": client.description,
            "logo_url": client.logo_url,
            "homepage_url": client.homepage_url,
            "privacy_policy_url": client.privacy_policy_url,
            "terms_url": client.terms_url,
            "publisher_name": client.publisher_name,
            "verified": bool(client.verified_at),
            "verified_at": client.verified_at.isoformat() if client.verified_at else None,
            "client_id": client.client_id,
            "public": client.public,
            "allowed_origins": client.allowed_origins or [],
            "audiences": client.audiences or [],
            "require_org_membership": client.require_org_membership,
            "require_mfa": client.require_mfa,
        },
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "audience": selected_audience,
        "state": state,
        "orgs": [org.model_dump() for org in orgs],
        "selected_org_id": selected_org.id if selected_org else None,
        "code_challenge_method": code_challenge_method,
    }


def oauth_grant_read(grant: OAuthGrant, client: AuthClient, user: User | None = None) -> OAuthGrantRead:
    return OAuthGrantRead(
        id=grant.id,
        auth_client_id=client.id,
        client_id=client.client_id,
        client_name=client.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        org_id=grant.org_id,
        audience=grant.audience,
        scopes=grant.scopes or [],
        last_authorized_at=grant.last_authorized_at,
        revoked_at=grant.revoked_at,
        created_at=grant.created_at,
    )


def admin_oauth_grant_org_scope(principal: Principal, requested_org_id: str | None = None) -> str | None:
    if principal.org_id and requested_org_id and requested_org_id != principal.org_id:
        raise HTTPException(status_code=403, detail="Current organization scope required")
    return requested_org_id or principal.org_id


async def client_create_org_id(db: AsyncSession, principal: Principal, requested_org_id: str | None) -> str | None:
    if principal.org_id:
        if requested_org_id and requested_org_id != principal.org_id:
            raise HTTPException(status_code=403, detail="Current organization scope required")
        return principal.org_id
    if requested_org_id:
        if principal.user_id:
            await ensure_user_org_membership(db, user_id=principal.user_id, org_id=requested_org_id)
        return requested_org_id
    if principal.user_id:
        memberships = await org_roles(db, principal.user_id)
        return memberships[0].id if memberships else None
    return None


async def ensure_client_management_allowed(db: AsyncSession, client: AuthClient, principal: Principal) -> None:
    if principal.org_id:
        if client.org_id != principal.org_id:
            raise HTTPException(status_code=404, detail="Client not found")
        return
    if client.org_id and principal.user_id:
        await ensure_user_org_membership(db, user_id=principal.user_id, org_id=client.org_id)


async def setup_resource_org_id(db: AsyncSession, principal: Principal, requested_org_id: str | None) -> str | None:
    if principal.org_id:
        if requested_org_id and requested_org_id != principal.org_id:
            raise HTTPException(status_code=403, detail="Current organization scope required")
        return principal.org_id
    if requested_org_id:
        if principal.user_id:
            await ensure_user_org_membership(db, user_id=principal.user_id, org_id=requested_org_id)
        return requested_org_id
    if principal.user_id:
        memberships = await org_roles(db, principal.user_id)
        return memberships[0].id if memberships else None
    return None


async def setup_resource_visible_org_ids(
    db: AsyncSession,
    principal: Principal,
    requested_org_id: str | None,
) -> list[str] | None:
    if principal.org_id:
        if requested_org_id and requested_org_id != principal.org_id:
            raise HTTPException(status_code=403, detail="Current organization scope required")
        return [principal.org_id]
    if requested_org_id:
        if principal.user_id:
            await ensure_user_org_membership(db, user_id=principal.user_id, org_id=requested_org_id)
        return [requested_org_id]
    if principal.user_id:
        memberships = await org_roles(db, principal.user_id)
        return [org.id for org in memberships]
    return None


@app.get("/api/v1/oauth/grants", response_model=list[OAuthGrantRead])
async def list_oauth_grants(
    include_revoked: bool = Query(default=False),
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    query = (
        select(OAuthGrant, AuthClient)
        .join(AuthClient, AuthClient.id == OAuthGrant.client_id)
        .where(OAuthGrant.user_id == principal.user_id)
        .order_by(OAuthGrant.last_authorized_at.desc())
    )
    if not include_revoked:
        query = query.where(OAuthGrant.revoked_at.is_(None))
    result = await db.execute(query)
    return [oauth_grant_read(grant, client) for grant, client in result.all()]


@app.get("/api/v1/oauth/grants/admin", response_model=list[OAuthGrantRead])
async def list_oauth_grants_admin(
    org_id: str | None = None,
    client_id: str | None = None,
    user_id: str | None = None,
    include_revoked: bool = Query(default=False),
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    effective_org_id = admin_oauth_grant_org_scope(principal, org_id)
    query = (
        select(OAuthGrant, AuthClient, User)
        .join(AuthClient, AuthClient.id == OAuthGrant.client_id)
        .join(User, User.id == OAuthGrant.user_id)
        .order_by(OAuthGrant.last_authorized_at.desc())
    )
    if effective_org_id:
        query = query.where(OAuthGrant.org_id == effective_org_id)
    if client_id:
        query = query.where(AuthClient.client_id == client_id)
    if user_id:
        query = query.where(OAuthGrant.user_id == user_id)
    if not include_revoked:
        query = query.where(OAuthGrant.revoked_at.is_(None))
    result = await db.execute(query)
    await audit(
        db,
        "oauth.grant.admin.list",
        org_id=effective_org_id,
        actor_user_id=principal.user_id,
        details={
            "requested_org_id": org_id,
            "effective_org_id": effective_org_id,
            "client_id": client_id,
            "user_id": user_id,
            "include_revoked": include_revoked,
        },
    )
    await db.commit()
    return [oauth_grant_read(grant, client, user) for grant, client, user in result.all()]


@app.delete("/api/v1/oauth/grants/{grant_id}")
async def revoke_oauth_grant(
    grant_id: str,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    grant = await db.get(OAuthGrant, grant_id)
    if not grant or grant.user_id != principal.user_id:
        raise HTTPException(status_code=404, detail="OAuth grant not found")
    grant.revoked_at = grant.revoked_at or now_utc()
    await audit(
        db,
        "oauth.grant.revoke",
        org_id=grant.org_id,
        actor_user_id=principal.user_id,
        target_type="oauth_grant",
        target_id=grant.id,
    )
    await db.commit()
    return {"status": "revoked", "id": grant.id}


@app.delete("/api/v1/oauth/grants/admin/{grant_id}")
async def revoke_oauth_grant_admin(
    grant_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    grant = await db.get(OAuthGrant, grant_id)
    if not grant or (principal.org_id and grant.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="OAuth grant not found")
    grant.revoked_at = grant.revoked_at or now_utc()
    await audit(
        db,
        "oauth.grant.admin.revoke",
        org_id=grant.org_id,
        actor_user_id=principal.user_id,
        target_type="oauth_grant",
        target_id=grant.id,
        details={"user_id": grant.user_id, "client_row_id": grant.client_id},
    )
    await db.commit()
    return {"status": "revoked", "id": grant.id}


@app.post("/oauth/token")
async def oauth_token(
    grant_type: str = Form(...),
    code: str | None = Form(default=None),
    redirect_uri: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    refresh_token: str | None = Form(default=None),
    device_code: str | None = Form(default=None),
    scope: str = Form(default=""),
    audience: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    if grant_type == "authorization_code":
        if not all([code, redirect_uri, client_id, code_verifier]):
            raise HTTPException(status_code=400, detail="Missing authorization_code fields")
        client = await get_client_by_client_id(db, client_id)
        result = await db.execute(
            select(OAuthAuthorizationCode).where(OAuthAuthorizationCode.code_hash == token_hash(code))
        )
        auth_code = result.scalar_one_or_none()
        if (
            not auth_code
            or auth_code.client_id != client.id
            or auth_code.redirect_uri != redirect_uri
            or auth_code.used_at
            or auth_code.expires_at <= now_utc()
        ):
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        if not verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
            raise HTTPException(status_code=400, detail="Invalid PKCE verifier")
        user = await db.get(User, auth_code.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        await enforce_client_and_org_mfa_policy(
            db,
            client=client,
            org_id=auth_code.org_id or client.org_id,
            user=user,
            amr=auth_code.amr or [],
            trusted_device=TRUSTED_DEVICE_AMR in (auth_code.amr or []),
        )
        auth_code.used_at = now_utc()
        access, refresh, _session, _refresh_model = await create_session_tokens(
            db,
            user,
            client=client,
            org_id=auth_code.org_id,
            scopes=auth_code.scope.split(),
            audience=auth_code.audience or client.audiences or settings.issuer,
            bind_default_org=False,
            amr=auth_code.amr or [],
        )
        await db.commit()
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_seconds,
            "scope": auth_code.scope,
        }

    if grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token")
        access, new_refresh, _user, scopes = await rotate_refresh_token(db, refresh_token)
        return {
            "access_token": access,
            "refresh_token": new_refresh,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_seconds,
            "scope": " ".join(scopes),
        }

    if grant_type == "client_credentials":
        if not client_id or not client_secret:
            raise HTTPException(status_code=400, detail="Client credentials required")
        client = await get_client_by_client_id(db, client_id)
        if (
            client.public
            or not client.client_secret_hash
            or not verify_password(client_secret, client.client_secret_hash)
        ):
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        scopes = validate_scopes(client, scope)
        aud = validate_audience(client, audience) or (client.audiences[0] if client.audiences else settings.issuer)
        access = create_access_token(
            subject=client.client_id,
            audience=aud,
            scopes=scopes,
            token_type="service",
            client_id=client.client_id,
            org_id=client.org_id,
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_seconds,
            "scope": " ".join(scopes),
        }

    if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        if not device_code or not client_id:
            raise HTTPException(status_code=400, detail="Missing device_code fields")
        client = await get_client_by_client_id(db, client_id)
        result = await db.execute(
            select(DeviceGrant).where(DeviceGrant.device_code_hash == token_hash(device_code))
        )
        grant = result.scalar_one_or_none()
        if not grant or grant.client_id != client.id or grant.expires_at <= now_utc():
            raise HTTPException(status_code=400, detail="Invalid device_code")
        if grant.denied_at:
            raise HTTPException(status_code=400, detail="access_denied")
        if not grant.approved_at or not grant.user_id:
            raise HTTPException(status_code=428, detail="authorization_pending")
        if grant.used_at:
            raise HTTPException(status_code=400, detail="Device code already used")
        grant.used_at = now_utc()
        user = await db.get(User, grant.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid device grant")
        await enforce_client_and_org_mfa_policy(
            db,
            client=client,
            org_id=grant.org_id or client.org_id,
            user=user,
            amr=grant.amr or [],
            trusted_device=TRUSTED_DEVICE_AMR in (grant.amr or []),
        )
        access, refresh, _session, _refresh_model = await create_session_tokens(
            db,
            user,
            client=client,
            org_id=grant.org_id,
            scopes=grant.scope.split(),
            audience=grant.audience or client.audiences or settings.issuer,
            amr=grant.amr or [],
        )
        await db.commit()
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_seconds,
            "scope": grant.scope,
        }

    raise HTTPException(status_code=400, detail="Unsupported grant_type")


@app.post("/oauth/device_authorization")
async def device_authorization(body: DeviceAuthorizationRequest, db: AsyncSession = Depends(get_db)):
    client = await get_client_by_client_id(db, body.client_id)
    scopes = validate_scopes(client, body.scope)
    validate_audience(client, body.audience)
    device_code = new_opaque_token("gkd")
    user_code = new_code(8)
    db.add(
        DeviceGrant(
            device_code_hash=token_hash(device_code),
            user_code_hash=token_hash(user_code),
            user_code_hint=user_code[-4:],
            client_id=client.id,
            scope=" ".join(scopes),
            audience=body.audience,
            expires_at=utc_after(seconds=settings.device_code_ttl_seconds),
        )
    )
    await db.commit()
    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": f"{settings.ui_url.rstrip('/')}/device",
        "verification_uri_complete": f"{settings.ui_url.rstrip('/')}/device?user_code={user_code}",
        "expires_in": settings.device_code_ttl_seconds,
        "interval": 5,
    }


@app.post("/api/v1/auth/device/approve")
async def approve_device(
    body: DeviceAuthorizeApprove,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    result = await db.execute(
        select(DeviceGrant).where(DeviceGrant.user_code_hash == token_hash(body.user_code.strip().upper()))
    )
    grant = result.scalar_one_or_none()
    if not grant or grant.expires_at <= now_utc() or grant.used_at:
        raise HTTPException(status_code=404, detail="Device grant not found")
    if body.approve:
        client = await db.get(AuthClient, grant.client_id)
        user = await db.get(User, principal.user_id)
        if not client or not user:
            raise HTTPException(status_code=404, detail="Device grant not found")
        amr = principal_amr(principal)
        selected_org_id = body.org_id or principal.org_id or client.org_id
        if client.require_org_membership and client.org_id:
            if body.org_id and body.org_id != client.org_id:
                raise HTTPException(status_code=403, detail="Client is bound to another organization")
            selected_org_id = client.org_id
        if selected_org_id:
            await ensure_user_org_membership(db, user_id=user.id, org_id=selected_org_id)
        elif client.require_org_membership:
            raise HTTPException(status_code=403, detail="Organization membership required")
        await enforce_client_and_org_mfa_policy(
            db,
            client=client,
            org_id=selected_org_id,
            user=user,
            amr=amr,
            trusted_device=await principal_trusted_device_active(db, principal),
        )
        grant.approved_at = now_utc()
        grant.user_id = principal.user_id
        grant.org_id = selected_org_id
        grant.amr = amr
    else:
        grant.denied_at = now_utc()
    await db.commit()
    return {"status": "approved" if body.approve else "denied"}


@app.post("/oauth/revoke")
async def revoke_token(token: str = Form(...), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiToken).where(ApiToken.token_hash == token_hash(token)))
    api_token = result.scalar_one_or_none()
    if api_token:
        api_token.revoked_at = now_utc()
    else:
        try:
            claims = decode_access_token(token)
        except ValueError:
            claims = {}
        session_id = claims.get("session_id") or claims.get("sid")
        if claims.get("token_type") == "user" and isinstance(session_id, str) and session_id:
            session = await db.get(Session, session_id)
            if session and not session.revoked_at:
                session.revoked_at = now_utc()
                refresh_result = await db.execute(
                    select(RefreshToken).where(
                        RefreshToken.session_id == session.id,
                        RefreshToken.revoked_at.is_(None),
                    )
                )
                for refresh in refresh_result.scalars():
                    refresh.revoked_at = refresh.revoked_at or session.revoked_at
    await db.commit()
    return Response(status_code=200)


@app.post("/oauth/introspect")
async def introspect(token: str = Form(...), db: AsyncSession = Depends(get_db)):
    if token.startswith("gk_"):
        result = await db.execute(select(ApiToken).where(ApiToken.token_hash == token_hash(token)))
        api_token = result.scalar_one_or_none()
        validation = await token_validation_response(
            db,
            token=api_token,
            request_body=TokenValidateRequest(token=token),
        )
        return {
            "active": validation.active,
            "reason": validation.reason,
            "scope": " ".join(validation.scopes or []),
            "client_id": validation.auth_client_id,
            "sub": validation.user_id,
            "user_display_name": validation.user_display_name,
            "aud": validation.audiences,
            "token_type": validation.token_type,
            "token_id": validation.token_id,
            "org_id": validation.org_id,
            "project_id": validation.project_id,
        }
    try:
        claims = decode_access_token(token)
    except ValueError:
        return {"active": False, "reason": "invalid_token"}

    token_type = str(claims.get("token_type") or "")
    subject = str(claims.get("sub") or "")
    if token_type == "user":
        user = await db.get(User, subject) if subject else None
        if not user:
            return {"active": False, "reason": "user_not_found"}
        if user.disabled:
            return {"active": False, "reason": "user_disabled"}

        session_id_value = claims.get("session_id") or claims.get("sid")
        session_id = session_id_value if isinstance(session_id_value, str) and session_id_value else None
        session = await db.get(Session, session_id) if session_id else None
        if (
            not session
            or session.user_id != subject
            or session.revoked_at
            or session.expires_at <= now_utc()
        ):
            return {"active": False, "reason": "session_revoked"}
        client_id = claims.get("azp")
        client = await db.get(AuthClient, session.client_id) if session.client_id else None
        if client_id and (not client or client.client_id != str(client_id)):
            client_result = await db.execute(select(AuthClient).where(AuthClient.client_id == str(client_id)))
            client = client_result.scalar_one_or_none()
        if (client_id and not client) or (client and not client.enabled):
            return {"active": False, "reason": "client_disabled"}
        try:
            await enforce_session_idle_timeout(db, session=session, client=client, commit_on_expire=True)
        except HTTPException:
            return {"active": False, "reason": "session_idle_timeout"}
        org_id = claims.get("org_id")
        if org_id:
            membership = await db.execute(
                select(Membership.id).where(
                    Membership.user_id == subject,
                    Membership.org_id == str(org_id),
                    Membership.status == "active",
                )
            )
            if not membership.scalar_one_or_none():
                return {"active": False, "reason": "org_membership_required"}

    if token_type == "service":
        client_id = str(claims.get("azp") or claims.get("sub") or "")
        client_result = await db.execute(select(AuthClient).where(AuthClient.client_id == client_id))
        client = client_result.scalar_one_or_none()
        if not client:
            return {"active": False, "reason": "client_not_found"}
        if not client.enabled:
            return {"active": False, "reason": "client_disabled"}
        if claims.get("org_id") and str(claims.get("org_id")) != str(client.org_id):
            return {"active": False, "reason": "org_mismatch"}

    return {
        "active": True,
        "reason": None,
        "scope": str(claims.get("scope", "")),
        "client_id": claims.get("azp"),
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "display_name": claims.get("display_name"),
        "email_verified": claims.get("email_verified"),
        "mfa_totp_enabled": claims.get("mfa_totp_enabled"),
        "aud": claims.get("aud", []),
        "iss": claims.get("iss"),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "token_type": claims.get("token_type"),
        "session_id": claims.get("session_id") or claims.get("sid"),
        "org_id": claims.get("org_id"),
        "org_slug": claims.get("org_slug"),
        "org_role": claims.get("org_role"),
        "permissions": claims.get("permissions", []),
        "amr": claims.get("amr", []),
    }


@app.post("/oauth/register")
async def dynamic_register():
    if not settings.enable_dynamic_client_registration:
        raise HTTPException(status_code=404, detail="Dynamic client registration is disabled")
    raise HTTPException(status_code=501, detail="Dynamic registration policy is not configured")


def client_read(client: AuthClient) -> ClientRead:
    return ClientRead(
        id=client.id,
        org_id=client.org_id,
        name=client.name,
        description=client.description,
        logo_url=client.logo_url,
        homepage_url=client.homepage_url,
        privacy_policy_url=client.privacy_policy_url,
        terms_url=client.terms_url,
        publisher_name=client.publisher_name,
        verified=bool(client.verified_at),
        verified_at=client.verified_at,
        client_id=client.client_id,
        public=client.public,
        enabled=client.enabled,
        redirect_uris=client.redirect_uris or [],
        allowed_origins=client.allowed_origins or [],
        audiences=client.audiences or [],
        scopes=client.scopes or [],
        require_org_membership=client.require_org_membership,
        require_mfa=client.require_mfa,
        trusted_device_mfa_bypass=client.trusted_device_mfa_bypass,
        session_idle_timeout_minutes=client.session_idle_timeout_minutes,
        mcp_resource_uri=client.mcp_resource_uri,
    )


@app.get("/api/v1/orgs", response_model=list[OrgRead])
async def list_orgs(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)):
    if principal.user_id:
        return await org_roles(db, principal.user_id)
    result = await db.execute(select(Organization).order_by(Organization.name))
    return [org_read(o) for o in result.scalars()]


def org_read(org: Organization) -> OrgRead:
    return OrgRead(
        id=org.id,
        name=org.name,
        slug=org.slug,
        require_mfa=org.require_mfa,
        trusted_device_mfa_bypass=org.trusted_device_mfa_bypass,
        admin_step_up_mfa_required=org.admin_step_up_mfa_required,
        session_idle_timeout_minutes=org.session_idle_timeout_minutes,
        audit_retention_days=org.audit_retention_days,
        allow_user_hard_delete=org.allow_user_hard_delete,
    )


@app.post("/api/v1/orgs", response_model=OrgRead)
async def create_org(
    body: OrgCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = Organization(
        name=body.name,
        slug=body.slug,
        require_mfa=body.require_mfa,
        trusted_device_mfa_bypass=body.trusted_device_mfa_bypass,
        admin_step_up_mfa_required=body.admin_step_up_mfa_required,
        session_idle_timeout_minutes=body.session_idle_timeout_minutes,
        audit_retention_days=body.audit_retention_days,
        allow_user_hard_delete=body.allow_user_hard_delete,
    )
    db.add(org)
    await db.flush()
    roles = await add_default_org_roles(db, org)
    if principal.user_id:
        db.add(Membership(org_id=org.id, user_id=principal.user_id, role_id=roles["owner"].id, status="active"))
    await audit(
        db,
        "org.create",
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="organization",
        target_id=org.id,
        details={"creator_owner": bool(principal.user_id)},
    )
    await db.commit()
    if principal.user_id:
        memberships = await org_roles(db, principal.user_id)
        created_membership = next((item for item in memberships if item.id == org.id), None)
        if created_membership:
            return created_membership
    await db.refresh(org)
    return org_read(org)


@app.patch("/api/v1/orgs/{org_id}", response_model=OrgRead)
async def update_org(
    org_id: str,
    body: OrgUpdate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org.id)
    revoked_sessions = 0
    if body.name is not None:
        org.name = body.name
    if body.require_mfa is not None and body.require_mfa != org.require_mfa:
        org.require_mfa = body.require_mfa
        if body.require_mfa:
            revoked_sessions = await revoke_org_client_sessions_without_mfa(db, org_id=org.id)
    if body.trusted_device_mfa_bypass is not None:
        org.trusted_device_mfa_bypass = body.trusted_device_mfa_bypass
    if body.admin_step_up_mfa_required is not None:
        org.admin_step_up_mfa_required = body.admin_step_up_mfa_required
    if "session_idle_timeout_minutes" in body.model_fields_set:
        org.session_idle_timeout_minutes = body.session_idle_timeout_minutes
    if "audit_retention_days" in body.model_fields_set:
        org.audit_retention_days = body.audit_retention_days
    if body.allow_user_hard_delete is not None:
        org.allow_user_hard_delete = body.allow_user_hard_delete
    await audit(
        db,
        "org.update",
        org_id=org.id,
        actor_user_id=principal.user_id,
        target_type="organization",
        target_id=org.id,
        details={**body.model_dump(exclude_unset=True), "revoked_sessions": revoked_sessions},
    )
    await db.commit()
    await db.refresh(org)
    return org_read(org)


@app.post("/api/v1/workspaces")
async def create_workspace(
    body: WorkspaceCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    workspace = Workspace(org_id=org_id, name=body.name, slug=body.slug)
    db.add(workspace)
    await db.commit()
    return {"id": workspace.id, "org_id": workspace.org_id, "name": workspace.name, "slug": workspace.slug}


@app.get(
    "/api/v1/workspaces",
    response_model=list[WorkspaceRead],
)
async def list_workspaces(
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(Workspace).order_by(Workspace.created_at.desc())
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.where(Workspace.org_id.in_(visible_org_ids))
    result = await db.execute(query)
    return [
        WorkspaceRead(id=item.id, org_id=item.org_id, name=item.name, slug=item.slug)
        for item in result.scalars()
    ]


@app.post("/api/v1/projects")
async def create_project(
    body: ProjectCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    if body.workspace_id:
        workspace = await db.get(Workspace, body.workspace_id)
        if not workspace or workspace.org_id != org_id:
            raise HTTPException(status_code=404, detail="Workspace not found")
    project = Project(
        org_id=org_id,
        workspace_id=body.workspace_id,
        name=body.name,
        slug=body.slug,
        audience=body.audience,
    )
    db.add(project)
    await db.commit()
    return {
        "id": project.id,
        "org_id": project.org_id,
        "name": project.name,
        "slug": project.slug,
        "audience": project.audience,
    }


@app.get("/api/v1/projects", response_model=list[ProjectRead])
async def list_projects(
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(Project).order_by(Project.created_at.desc())
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.where(Project.org_id.in_(visible_org_ids))
    result = await db.execute(query)
    return [
        ProjectRead(
            id=item.id,
            org_id=item.org_id,
            workspace_id=item.workspace_id,
            name=item.name,
            slug=item.slug,
            audience=item.audience,
        )
        for item in result.scalars()
    ]


@app.post("/api/v1/roles")
async def create_role(
    body: RoleCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    role = Role(org_id=org_id, name=body.name, permissions=body.permissions)
    db.add(role)
    await db.commit()
    return {"id": role.id, "org_id": role.org_id, "name": role.name, "permissions": role.permissions}


@app.get("/api/v1/roles", response_model=list[RoleRead])
async def list_roles(
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(Role).order_by(Role.name)
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.where(Role.org_id.in_(visible_org_ids))
    result = await db.execute(query)
    return [
        RoleRead(id=item.id, org_id=item.org_id, name=item.name, permissions=item.permissions or [])
        for item in result.scalars()
    ]


@app.get("/api/v1/clients", response_model=list[ClientRead])
async def list_clients(
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuthClient).order_by(AuthClient.created_at.desc())
    if principal.org_id:
        query = query.where(or_(AuthClient.org_id == principal.org_id, AuthClient.org_id.is_(None)))
    elif principal.user_id:
        memberships = await org_roles(db, principal.user_id)
        org_ids = [org.id for org in memberships]
        query = (
            query.where(or_(AuthClient.org_id.in_(org_ids), AuthClient.org_id.is_(None)))
            if org_ids
            else query.where(AuthClient.org_id.is_(None))
        )
    result = await db.execute(query)
    return [client_read(client) for client in result.scalars()]


@app.post("/api/v1/clients")
async def create_client(
    body: ClientCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    redirect_uris = validate_url_list(body.redirect_uris, field_name="redirect_uris")
    allowed_origins = validate_url_list(body.allowed_origins, field_name="allowed_origins", origin_only=True)
    org_id = await client_create_org_id(db, principal, body.org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    secret = None
    secret_hash = None
    if not body.public:
        secret = new_opaque_token("gkcs")
        from app.security import hash_password

        secret_hash = hash_password(secret)
    client = AuthClient(
        org_id=org_id,
        name=body.name,
        description=normalize_optional_text(body.description),
        logo_url=validate_optional_url(body.logo_url, field_name="logo_url"),
        homepage_url=validate_optional_url(body.homepage_url, field_name="homepage_url"),
        privacy_policy_url=validate_optional_url(body.privacy_policy_url, field_name="privacy_policy_url"),
        terms_url=validate_optional_url(body.terms_url, field_name="terms_url"),
        publisher_name=normalize_optional_text(body.publisher_name),
        verified_at=now_utc() if body.verified else None,
        client_id=f"gkc_{new_code(12).lower()}",
        client_secret_hash=secret_hash,
        public=body.public,
        redirect_uris=redirect_uris,
        allowed_origins=allowed_origins,
        audiences=body.audiences,
        scopes=body.scopes,
        require_org_membership=body.require_org_membership,
        require_mfa=body.require_mfa,
        trusted_device_mfa_bypass=body.trusted_device_mfa_bypass,
        session_idle_timeout_minutes=body.session_idle_timeout_minutes,
        mcp_resource_uri=body.mcp_resource_uri,
    )
    db.add(client)
    await audit(
        db,
        "client.create",
        org_id=org_id,
        actor_user_id=principal.user_id,
        target_type="client",
        target_id=client.id,
    )
    await db.commit()
    payload = client_read(client).model_dump()
    if secret:
        payload["client_secret"] = secret
    return payload


@app.patch("/api/v1/clients/{client_id}", response_model=ClientRead)
async def update_client(
    client_id: str,
    body: ClientUpdate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    client = await db.get(AuthClient, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    await ensure_client_management_allowed(db, client, principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=client.org_id)
    if body.name is not None:
        client.name = body.name
    if "description" in body.model_fields_set:
        client.description = normalize_optional_text(body.description)
    if "logo_url" in body.model_fields_set:
        client.logo_url = validate_optional_url(body.logo_url, field_name="logo_url")
    if "homepage_url" in body.model_fields_set:
        client.homepage_url = validate_optional_url(body.homepage_url, field_name="homepage_url")
    if "privacy_policy_url" in body.model_fields_set:
        client.privacy_policy_url = validate_optional_url(body.privacy_policy_url, field_name="privacy_policy_url")
    if "terms_url" in body.model_fields_set:
        client.terms_url = validate_optional_url(body.terms_url, field_name="terms_url")
    if "publisher_name" in body.model_fields_set:
        client.publisher_name = normalize_optional_text(body.publisher_name)
    if body.verified is not None:
        client.verified_at = now_utc() if body.verified else None
    if body.enabled is not None:
        client.enabled = body.enabled
    if body.redirect_uris is not None:
        client.redirect_uris = validate_url_list(body.redirect_uris, field_name="redirect_uris")
    if body.allowed_origins is not None:
        client.allowed_origins = validate_url_list(
            body.allowed_origins, field_name="allowed_origins", origin_only=True
        )
    if body.audiences is not None:
        client.audiences = body.audiences
    if body.scopes is not None:
        client.scopes = body.scopes
    if body.require_org_membership is not None:
        client.require_org_membership = body.require_org_membership
    if body.require_mfa is not None:
        client.require_mfa = body.require_mfa
    if body.trusted_device_mfa_bypass is not None:
        client.trusted_device_mfa_bypass = body.trusted_device_mfa_bypass
    if "session_idle_timeout_minutes" in body.model_fields_set:
        client.session_idle_timeout_minutes = body.session_idle_timeout_minutes
    if body.mcp_resource_uri is not None:
        client.mcp_resource_uri = body.mcp_resource_uri
    await audit(
        db,
        "client.update",
        org_id=client.org_id,
        actor_user_id=principal.user_id,
        target_type="client",
        target_id=client.id,
    )
    await db.commit()
    await db.refresh(client)
    return client_read(client)


@app.post("/api/v1/clients/{client_id}/rotate-secret")
async def rotate_client_secret(
    client_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    client = await db.get(AuthClient, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    await ensure_client_management_allowed(db, client, principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=client.org_id)
    if client.public:
        raise HTTPException(status_code=400, detail="Public clients do not have secrets")
    secret = new_opaque_token("gkcs")
    from app.security import hash_password

    client.client_secret_hash = hash_password(secret)
    await audit(
        db,
        "client.secret.rotate",
        org_id=client.org_id,
        actor_user_id=principal.user_id,
        target_type="client",
        target_id=client.id,
    )
    await db.commit()
    payload = client_read(client).model_dump()
    payload["client_secret"] = secret
    return payload


@app.delete("/api/v1/clients/{client_id}")
async def delete_client(
    client_id: str,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    client = await db.get(AuthClient, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    await ensure_client_management_allowed(db, client, principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=client.org_id)
    if client.client_id == "gatekeeper-cli":
        raise HTTPException(status_code=400, detail="The default CLI client can be disabled but not deleted")
    dependent_queries = [
        select(ApiToken.id).where(ApiToken.client_id == client.id),
        select(RefreshToken.id).where(RefreshToken.client_id == client.id),
        select(DeviceGrant.id).where(DeviceGrant.client_id == client.id),
        select(OAuthAuthorizationCode.id).where(OAuthAuthorizationCode.client_id == client.id),
    ]
    for query in dependent_queries:
        dependency = await db.execute(query.limit(1))
        if dependency.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Client has issued artifacts; disable it instead")
    await audit(
        db,
        "client.delete",
        org_id=client.org_id,
        actor_user_id=principal.user_id,
        target_type="client",
        target_id=client.id,
    )
    await db.delete(client)
    await db.commit()
    return {"status": "deleted", "id": client_id}


def token_read(token: ApiToken, raw: str | None = None) -> TokenRead:
    return TokenRead(
        id=token.id,
        org_id=token.org_id,
        user_id=token.user_id,
        project_id=token.project_id,
        client_id=token.client_id,
        name=token.name,
        token_type=token.token_type,
        token_hint=token.token_hint,
        scopes=token.scopes or [],
        audiences=token.audiences or [],
        expires_at=token.expires_at,
        revoked_at=token.revoked_at,
        last_used_at=token.last_used_at,
        created_at=token.created_at,
        token=raw,
    )


def can_admin_tokens(principal: Principal) -> bool:
    return has_capability(principal.scopes, "token:*", "admin:*")


async def ensure_user_org_membership(db: AsyncSession, *, user_id: str, org_id: str) -> None:
    result = await db.execute(
        select(Membership.id).where(
            Membership.user_id == user_id,
            Membership.org_id == org_id,
            Membership.status == "active",
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="Organization membership required")


def ensure_personal_token_scopes(principal: Principal, scopes: list[str]) -> list[str]:
    requested = scopes or ["auth:read"]
    if "*" in principal.scopes or "token:*" in principal.scopes:
        return requested
    allowed = set(principal.scopes)
    if not set(requested).issubset(allowed):
        raise HTTPException(status_code=403, detail="Requested token scope is not allowed for this account")
    return requested


async def ensure_token_mutation_allowed(db: AsyncSession, *, token: ApiToken, principal: Principal) -> None:
    if can_admin_tokens(principal):
        if token.org_id and principal.org_id:
            await ensure_user_org_membership(db, user_id=principal.user_id, org_id=token.org_id)
        return
    if (
        principal.auth_type == "user"
        and principal.user_id
        and principal.session_id
        and token.token_type == "personal"
        and token.user_id == principal.user_id
    ):
        return
    raise HTTPException(status_code=403, detail="Token is not manageable by this account")


def missing_token_scopes(token_scopes: list[str], required_scopes: list[str]) -> list[str]:
    available = set(token_scopes or [])
    if "*" in available:
        return []
    missing: list[str] = []
    for scope in required_scopes:
        if scope in available:
            continue
        if ":" in scope and f"{scope.split(':', 1)[0]}:*" in available:
            continue
        missing.append(scope)
    return missing


async def token_validation_response(
    db: AsyncSession,
    *,
    token: ApiToken | None,
    request_body: TokenValidateRequest,
    reason: str | None = None,
) -> TokenValidateResponse:
    if not token:
        return TokenValidateResponse(active=False, reason=reason or "not_found")

    user = await db.get(User, token.user_id) if token.user_id else None
    org = await db.get(Organization, token.org_id) if token.org_id else None
    project = await db.get(Project, token.project_id) if token.project_id else None
    client = await db.get(AuthClient, token.client_id) if token.client_id else None
    scopes = token.scopes or []
    audiences = token.audiences or []
    missing_scopes = missing_token_scopes(scopes, request_body.required_scopes)
    audience_ok = not request_body.audience or request_body.audience in audiences
    scope_ok = not missing_scopes
    active_reason = reason
    if not active_reason and token.revoked_at:
        active_reason = "revoked"
    if not active_reason and token.expires_at and token.expires_at <= now_utc():
        active_reason = "expired"
    if not active_reason and token.user_id and not user:
        active_reason = "user_not_found"
    if not active_reason and user and user.disabled:
        active_reason = "user_disabled"
    if not active_reason and token.org_id and not org:
        active_reason = "org_not_found"
    if not active_reason and token.project_id and not project:
        active_reason = "project_not_found"
    if not active_reason and token.client_id and not client:
        active_reason = "client_not_found"
    if not active_reason and client and not client.enabled:
        active_reason = "client_disabled"
    if not active_reason and token.user_id and token.org_id:
        membership = await db.execute(
            select(Membership.id).where(
                Membership.user_id == token.user_id,
                Membership.org_id == token.org_id,
                Membership.status == "active",
            )
        )
        if not membership.scalar_one_or_none():
            active_reason = "org_membership_required"
    if not active_reason and request_body.org_id and request_body.org_id != token.org_id:
        active_reason = "org_mismatch"
    if not active_reason and request_body.project_id and request_body.project_id != token.project_id:
        active_reason = "project_mismatch"
    if not active_reason and not audience_ok:
        active_reason = "audience_mismatch"
    if not active_reason and not scope_ok:
        active_reason = "scope_mismatch"

    active = active_reason is None
    if active:
        token.last_used_at = now_utc()
        await db.commit()

    return TokenValidateResponse(
        active=active,
        reason=active_reason,
        token_id=token.id,
        token_type=token.token_type,
        token_hint=token.token_hint,
        org_id=token.org_id,
        org_name=org.name if org else None,
        org_slug=org.slug if org else None,
        user_id=token.user_id,
        user_email=user.email if user else None,
        user_display_name=user.display_name if user else None,
        project_id=token.project_id,
        project_name=project.name if project else None,
        project_audience=project.audience if project else None,
        auth_client_id=token.client_id,
        scopes=scopes,
        audiences=audiences,
        missing_scopes=missing_scopes,
        audience_ok=audience_ok,
        scope_ok=scope_ok,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
    )


@app.get("/api/v1/tokens", response_model=list[TokenRead])
async def list_tokens(
    org_id: str | None = None,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if can_admin_tokens(principal):
        query = select(ApiToken)
        selected_org_id = org_id or principal.org_id
        if selected_org_id:
            if principal.user_id:
                await ensure_user_org_membership(db, user_id=principal.user_id, org_id=selected_org_id)
            query = query.where(ApiToken.org_id == selected_org_id)
        result = await db.execute(query.order_by(ApiToken.created_at.desc()))
        return [token_read(token) for token in result.scalars()]
    if principal.auth_type != "user" or not principal.user_id or not principal.session_id:
        raise HTTPException(status_code=403, detail="Session-bound user token required")
    query = select(ApiToken).where(
        ApiToken.user_id == principal.user_id,
        ApiToken.token_type == "personal",
    )
    result = await db.execute(query.order_by(ApiToken.created_at.desc()))
    return [token_read(token) for token in result.scalars()]


@app.post("/api/v1/tokens", response_model=TokenRead)
async def create_token(
    body: TokenCreate,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if body.token_type == "personal":
        user = await require_session_user(principal, db)
        org_id = body.org_id or principal.org_id
        if org_id:
            await ensure_user_org_membership(db, user_id=user.id, org_id=org_id)
            await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
        user_id = user.id
        scopes = ensure_personal_token_scopes(principal, body.scopes)
    else:
        if not can_admin_tokens(principal):
            raise HTTPException(status_code=403, detail="Token administration scope required")
        org_id = body.org_id or principal.org_id
        if org_id and principal.user_id:
            await ensure_user_org_membership(db, user_id=principal.user_id, org_id=org_id)
        await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
        user_id = principal.user_id if body.token_type == "admin" else None
        scopes = body.scopes
    token, raw = await create_api_token(
        db,
        name=body.name,
        token_type_value=body.token_type,
        org_id=org_id,
        user_id=user_id,
        project_id=body.project_id,
        client_id=body.client_id,
        scopes=scopes,
        audiences=body.audiences,
        expires_at=body.expires_at,
    )
    await audit(
        db,
        "token.create",
        org_id=token.org_id,
        actor_user_id=principal.user_id,
        target_type="token",
        target_id=token.id,
    )
    await db.commit()
    await db.refresh(token)
    return token_read(token, raw)


@app.post("/api/v1/tokens/validate", response_model=TokenValidateResponse)
async def validate_api_token(body: TokenValidateRequest, db: AsyncSession = Depends(get_db)):
    if not body.token.startswith("gk_"):
        return TokenValidateResponse(active=False, reason="unsupported_token")
    result = await db.execute(select(ApiToken).where(ApiToken.token_hash == token_hash(body.token)))
    api_token = result.scalar_one_or_none()
    return await token_validation_response(db, token=api_token, request_body=body)


@app.delete("/api/v1/tokens/{token_id}")
async def revoke_api_token(
    token_id: str,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    token = await db.get(ApiToken, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    await ensure_token_mutation_allowed(db, token=token, principal=principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=token.org_id)
    token.revoked_at = now_utc()
    await audit(
        db,
        "token.revoke",
        org_id=token.org_id,
        actor_user_id=principal.user_id,
        target_type="token",
        target_id=token.id,
    )
    await db.commit()
    return {"status": "revoked", "id": token_id}


@app.post("/api/v1/tokens/{token_id}/rotate", response_model=TokenRead)
async def rotate_api_token(
    token_id: str,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.get(ApiToken, token_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Token not found")
    if existing.revoked_at:
        raise HTTPException(status_code=400, detail="Token is already revoked")
    await ensure_token_mutation_allowed(db, token=existing, principal=principal)
    await require_admin_step_up_for_org(db, principal=principal, org_id=existing.org_id)
    existing.revoked_at = now_utc()
    token, raw = await create_api_token(
        db,
        name=existing.name,
        token_type_value=existing.token_type,
        org_id=existing.org_id,
        user_id=existing.user_id,
        project_id=existing.project_id,
        client_id=existing.client_id,
        scopes=existing.scopes or [],
        audiences=existing.audiences or [],
        expires_at=existing.expires_at,
    )
    await audit(
        db,
        "token.rotate",
        org_id=token.org_id,
        actor_user_id=principal.user_id,
        target_type="token",
        target_id=token.id,
        details={"replaces": existing.id, "previous_hint": existing.token_hint},
    )
    await db.commit()
    await db.refresh(token)
    return token_read(token, raw)


@app.post("/api/v1/mcp/resources")
async def create_mcp_resource(
    body: McpResourceCreate,
    principal: Principal = Depends(require_scopes(["mcp:*"])),
    db: AsyncSession = Depends(get_db),
):
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    resource = McpResource(
        org_id=org_id,
        name=body.name,
        resource_uri=body.resource_uri,
        scopes=body.scopes or settings.mcp_default_scope_list,
    )
    db.add(resource)
    await db.commit()
    return {
        "id": resource.id,
        "org_id": resource.org_id,
        "resource_uri": resource.resource_uri,
        "scopes": resource.scopes,
    }


@app.get("/api/v1/mcp/resources")
async def list_mcp_resources(
    org_id: str | None = None,
    principal: Principal = Depends(require_scopes(["mcp:*"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(McpResource).order_by(McpResource.created_at.desc())
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.where(McpResource.org_id.in_(visible_org_ids))
    result = await db.execute(query)
    return [
        {
            "id": resource.id,
            "org_id": resource.org_id,
            "name": resource.name,
            "resource_uri": resource.resource_uri,
            "scopes": resource.scopes,
        }
        for resource in result.scalars()
    ]


@app.get("/api/v1/audit", response_model=list[AuditRead])
async def list_audit(
    actor_user_id: str | None = None,
    action: str | None = None,
    org_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    limit: int = Query(200, ge=1, le=500),
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    if actor_user_id:
        query = query.where(AuditEvent.actor_user_id == actor_user_id)
    if action:
        query = query.where(AuditEvent.action == action)
    visible_org_ids = await setup_resource_visible_org_ids(db, principal, org_id)
    if visible_org_ids is not None:
        query = query.where(AuditEvent.org_id.in_(visible_org_ids))
    if target_type:
        query = query.where(AuditEvent.target_type == target_type)
    if target_id:
        query = query.where(AuditEvent.target_id == target_id)
    result = await db.execute(query)
    return [audit_event_read(item) for item in result.scalars()]


@app.post("/api/v1/audit/prune", response_model=AuditPruneResponse)
async def prune_audit(
    body: AuditPruneRequest,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    org_id = await setup_resource_org_id(db, principal, body.org_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization is required")
    await require_admin_step_up_for_org(db, principal=principal, org_id=org_id)
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.audit_retention_days:
        raise HTTPException(status_code=400, detail="Audit retention policy is not configured")

    cutoff_at = now_utc() - timedelta(days=org.audit_retention_days)
    filters = [AuditEvent.org_id == org.id, AuditEvent.created_at < cutoff_at]
    if body.dry_run:
        count_result = await db.execute(select(func.count()).select_from(AuditEvent).where(*filters))
        pruned_count = int(count_result.scalar_one())
    else:
        deleted = await db.execute(delete(AuditEvent).where(*filters))
        pruned_count = int(deleted.rowcount or 0)
        await audit(
            db,
            "audit.prune",
            org_id=org.id,
            actor_user_id=principal.user_id,
            target_type="organization",
            target_id=org.id,
            details={
                "retention_days": org.audit_retention_days,
                "cutoff_at": cutoff_at.isoformat(),
                "pruned_count": pruned_count,
            },
        )
        await db.commit()

    return AuditPruneResponse(
        org_id=org.id,
        retention_days=org.audit_retention_days,
        cutoff_at=cutoff_at,
        pruned_count=pruned_count,
        dry_run=body.dry_run,
    )
