from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import Base, async_session_factory, engine, get_db
from app.deps import Principal, current_principal, optional_principal, require_scopes
from app.models import (
    ApiToken,
    AuditEvent,
    AuthClient,
    DeviceGrant,
    Identity,
    McpResource,
    Membership,
    OAuthAuthorizationCode,
    Organization,
    Project,
    RefreshToken,
    Role,
    Session,
    User,
    Workspace,
)
from app.schemas import (
    AuditRead,
    ClientCreate,
    ClientRead,
    ClientUpdate,
    DeviceAuthorizationRequest,
    DeviceAuthorizeApprove,
    EmailCodeRequest,
    EmailCodeVerify,
    LoginRequest,
    McpResourceCreate,
    OAuthAuthorizeRequest,
    OrgCreate,
    OrgRead,
    PasswordResetConfirm,
    ProjectCreate,
    ProjectRead,
    RefreshRequest,
    RoleCreate,
    RoleRead,
    SessionRead,
    SetupStatusRead,
    SignupRequest,
    TokenCreate,
    TokenRead,
    TokenResponse,
    WorkspaceCreate,
    WorkspaceRead,
)
from app.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    new_code,
    new_opaque_token,
    now_utc,
    public_jwk,
    token_hash,
    utc_after,
    verify_password,
    verify_pkce,
)
from app.services import (
    audit,
    authenticate_password,
    create_api_token,
    create_one_time_code,
    create_session_tokens,
    create_user,
    enforce_rate_limit,
    ensure_bootstrap,
    get_client_by_client_id,
    org_has_owner,
    org_roles,
    rotate_refresh_token,
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
    description="B3n self-hostable auth platform",
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


def delete_session_cookie(response: Response) -> None:
    kwargs: dict[str, object] = {}
    if settings.cookie_domain:
        kwargs["domain"] = settings.cookie_domain
    response.delete_cookie(settings.cookie_name, **kwargs)


def has_capability(values: list[str], *accepted: str) -> bool:
    value_set = set(values)
    if "*" in value_set:
        return True
    return any(value in value_set for value in accepted)


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
    access, refresh, _session, _refresh_model = await create_session_tokens(db, user, request=request)
    await db.commit()
    set_session_cookie(response, access)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope="auth:read",
        user=user_read(user),
        orgs=await org_roles(db, user.id),
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
    scopes = client.scopes if client else ["auth:read"]
    audience = client.audiences[0] if client and client.audiences else settings.issuer
    access, refresh, _session, _refresh_model = await create_session_tokens(
        db, user, request=request, client=client, scopes=scopes, audience=audience
    )
    await audit(db, "auth.login", actor_user_id=user.id, request=request)
    await db.commit()
    set_session_cookie(response, access)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
        user=user_read(user),
        orgs=await org_roles(db, user.id),
    )


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, response: Response, db: AsyncSession = Depends(get_db)):
    access, refresh_token, user, scopes = await rotate_refresh_token(db, body.refresh_token)
    memberships = await org_roles(db, user.id)
    set_session_cookie(response, access)
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
    access, refresh, _session, _refresh_model = await create_session_tokens(db, user, request=request)
    await audit(db, f"auth.email_code.{body.purpose}", actor_user_id=user.id, request=request)
    await db.commit()
    set_session_cookie(response, access)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope="auth:read",
        user=user_read(user),
        orgs=await org_roles(db, user.id),
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


def session_read(session: Session) -> SessionRead:
    return SessionRead(
        id=session.id,
        user_id=session.user_id,
        org_id=session.org_id,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        expires_at=session.expires_at,
        revoked_at=session.revoked_at,
        created_at=session.created_at,
    )


@app.get("/api/v1/sessions", response_model=list[SessionRead])
async def list_sessions(
    principal: Principal = Depends(require_scopes(["auth:read"])),
    db: AsyncSession = Depends(get_db),
):
    query = select(Session).order_by(Session.created_at.desc())
    if "*" not in principal.scopes and principal.user_id:
        query = query.where(Session.user_id == principal.user_id)
    result = await db.execute(query)
    return [session_read(session) for session in result.scalars()]


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


@app.get("/api/v1/auth/oauth/google/start")
async def google_start():
    if not settings.google_client_id:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    params = urlencode(
        {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": new_opaque_token("gkg"),
        }
    )
    return {"authorization_url": f"https://accounts.google.com/o/oauth2/v2/auth?{params}"}


@app.get("/api/v1/auth/oauth/google/callback")
async def google_callback(
    code: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    async with httpx.AsyncClient(timeout=15.0) as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.google_redirect_uri,
            },
        )
        token_response.raise_for_status()
        provider_token = token_response.json()
        userinfo = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {provider_token['access_token']}"},
        )
        userinfo.raise_for_status()
    profile = userinfo.json()
    subject = str(profile["sub"])
    email = str(profile["email"]).lower()
    identity_result = await db.execute(
        select(Identity).where(Identity.provider == "google", Identity.provider_subject == subject)
    )
    identity = identity_result.scalar_one_or_none()
    user = await db.get(User, identity.user_id) if identity else None
    if not user:
        user_result = await db.execute(select(User).where(User.email == email))
        user = user_result.scalar_one_or_none()
    if not user:
        user = await create_user(
            db,
            email=email,
            password=None,
            display_name=profile.get("name"),
            verified=bool(profile.get("email_verified")),
        )
    if not identity:
        db.add(
            Identity(
                user_id=user.id,
                provider="google",
                provider_subject=subject,
                email=email,
            )
        )
    access, refresh, _session, _refresh_model = await create_session_tokens(db, user, request=request)
    await audit(db, "auth.oauth.google", actor_user_id=user.id, request=request)
    await db.commit()
    response = RedirectResponse(f"{settings.ui_url.rstrip('/')}/account", status_code=302)
    set_session_cookie(response, access)
    response.set_cookie("gk_refresh_hint", refresh[-8:], **session_cookie_options())
    return response


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
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound authorization required")
    client = await get_client_by_client_id(db, client_id)
    validate_redirect(client, redirect_uri)
    validate_audience(client, audience)
    scopes = validate_scopes(client, scope)
    code = new_opaque_token("gkc")
    db.add(
        OAuthAuthorizationCode(
            code_hash=token_hash(code),
            client_id=client.id,
            user_id=principal.user_id,
            org_id=org_id,
            redirect_uri=redirect_uri,
            scope=" ".join(scopes),
            audience=audience,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=utc_after(minutes=10),
        )
    )
    await audit(
        db,
        "oauth.code.issue",
        org_id=org_id,
        actor_user_id=principal.user_id,
        target_type="client",
        target_id=client.id,
        request=request,
    )
    await db.commit()
    query = {"code": code}
    if state:
        query["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(query)}", status_code=302)


@app.post("/oauth/authorize")
async def oauth_authorize_post(
    body: OAuthAuthorizeRequest,
    request: Request,
    principal: Principal = Depends(current_principal),
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
        principal,
        db,
    )


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
        auth_code.used_at = now_utc()
        access, refresh, _session, _refresh_model = await create_session_tokens(
            db,
            user,
            client=client,
            org_id=auth_code.org_id,
            scopes=auth_code.scope.split(),
            audience=auth_code.audience or client.audiences or settings.issuer,
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
        access, refresh, _session, _refresh_model = await create_session_tokens(
            db,
            user,
            client=client,
            org_id=grant.org_id,
            scopes=grant.scope.split(),
            audience=grant.audience or client.audiences or settings.issuer,
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
        grant.approved_at = now_utc()
        grant.user_id = principal.user_id
        grant.org_id = body.org_id or principal.org_id
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
        active = bool(
            api_token
            and not api_token.revoked_at
            and (not api_token.expires_at or api_token.expires_at > now_utc())
        )
        return {
            "active": active,
            "scope": " ".join(api_token.scopes or []) if api_token else "",
            "client_id": api_token.client_id if api_token else None,
            "sub": api_token.user_id if api_token else None,
            "aud": api_token.audiences if api_token else [],
            "token_type": api_token.token_type if api_token else None,
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

        session_id = claims.get("session_id") or claims.get("sid")
        session = await db.get(Session, session_id) if isinstance(session_id, str) and session_id else None
        if (
            not session
            or session.user_id != subject
            or session.revoked_at
            or session.expires_at <= now_utc()
        ):
            return {"active": False, "reason": "session_revoked"}
        client_id = claims.get("azp")
        if client_id:
            client_result = await db.execute(select(AuthClient).where(AuthClient.client_id == str(client_id)))
            client = client_result.scalar_one_or_none()
            if not client or not client.enabled:
                return {"active": False, "reason": "client_disabled"}
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
    }


@app.post("/oauth/register")
async def dynamic_register():
    if not settings.enable_dynamic_client_registration:
        raise HTTPException(status_code=404, detail="Dynamic client registration is disabled")
    raise HTTPException(status_code=501, detail="Dynamic registration policy is not configured")


def client_read(client: AuthClient) -> ClientRead:
    return ClientRead(
        id=client.id,
        name=client.name,
        client_id=client.client_id,
        public=client.public,
        enabled=client.enabled,
        redirect_uris=client.redirect_uris or [],
        allowed_origins=client.allowed_origins or [],
        audiences=client.audiences or [],
        scopes=client.scopes or [],
        require_org_membership=client.require_org_membership,
        mcp_resource_uri=client.mcp_resource_uri,
    )


@app.get("/api/v1/orgs", response_model=list[OrgRead])
async def list_orgs(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)):
    if principal.user_id:
        return await org_roles(db, principal.user_id)
    result = await db.execute(select(Organization).order_by(Organization.name))
    return [OrgRead(id=o.id, name=o.name, slug=o.slug) for o in result.scalars()]


@app.post("/api/v1/orgs", response_model=OrgRead, dependencies=[Depends(require_scopes(["admin:*"]))])
async def create_org(body: OrgCreate, db: AsyncSession = Depends(get_db)):
    org = Organization(name=body.name, slug=body.slug)
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return OrgRead(id=org.id, name=org.name, slug=org.slug)


@app.post("/api/v1/workspaces", dependencies=[Depends(require_scopes(["admin:*"]))])
async def create_workspace(body: WorkspaceCreate, db: AsyncSession = Depends(get_db)):
    workspace = Workspace(org_id=body.org_id, name=body.name, slug=body.slug)
    db.add(workspace)
    await db.commit()
    return {"id": workspace.id, "org_id": workspace.org_id, "name": workspace.name, "slug": workspace.slug}


@app.get(
    "/api/v1/workspaces",
    response_model=list[WorkspaceRead],
    dependencies=[Depends(require_scopes(["auth:read"]))],
)
async def list_workspaces(org_id: str | None = None, db: AsyncSession = Depends(get_db)):
    query = select(Workspace).order_by(Workspace.created_at.desc())
    if org_id:
        query = query.where(Workspace.org_id == org_id)
    result = await db.execute(query)
    return [
        WorkspaceRead(id=item.id, org_id=item.org_id, name=item.name, slug=item.slug)
        for item in result.scalars()
    ]


@app.post("/api/v1/projects", dependencies=[Depends(require_scopes(["admin:*"]))])
async def create_project(body: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(
        org_id=body.org_id,
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


@app.get("/api/v1/projects", response_model=list[ProjectRead], dependencies=[Depends(require_scopes(["auth:read"]))])
async def list_projects(org_id: str | None = None, db: AsyncSession = Depends(get_db)):
    query = select(Project).order_by(Project.created_at.desc())
    if org_id:
        query = query.where(Project.org_id == org_id)
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


@app.post("/api/v1/roles", dependencies=[Depends(require_scopes(["admin:*"]))])
async def create_role(body: RoleCreate, db: AsyncSession = Depends(get_db)):
    role = Role(org_id=body.org_id, name=body.name, permissions=body.permissions)
    db.add(role)
    await db.commit()
    return {"id": role.id, "name": role.name, "permissions": role.permissions}


@app.get("/api/v1/roles", response_model=list[RoleRead], dependencies=[Depends(require_scopes(["auth:read"]))])
async def list_roles(org_id: str | None = None, db: AsyncSession = Depends(get_db)):
    query = select(Role).order_by(Role.name)
    if org_id:
        query = query.where(Role.org_id == org_id)
    result = await db.execute(query)
    return [
        RoleRead(id=item.id, org_id=item.org_id, name=item.name, permissions=item.permissions or [])
        for item in result.scalars()
    ]


@app.get("/api/v1/clients", response_model=list[ClientRead], dependencies=[Depends(require_scopes(["auth:read"]))])
async def list_clients(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuthClient).order_by(AuthClient.created_at.desc()))
    return [client_read(client) for client in result.scalars()]


@app.post("/api/v1/clients")
async def create_client(
    body: ClientCreate,
    principal: Principal = Depends(require_scopes(["admin:*"])),
    db: AsyncSession = Depends(get_db),
):
    redirect_uris = validate_url_list(body.redirect_uris, field_name="redirect_uris")
    allowed_origins = validate_url_list(body.allowed_origins, field_name="allowed_origins", origin_only=True)
    secret = None
    secret_hash = None
    if not body.public:
        secret = new_opaque_token("gkcs")
        from app.security import hash_password

        secret_hash = hash_password(secret)
    client = AuthClient(
        org_id=body.org_id,
        name=body.name,
        client_id=f"gkc_{new_code(12).lower()}",
        client_secret_hash=secret_hash,
        public=body.public,
        redirect_uris=redirect_uris,
        allowed_origins=allowed_origins,
        audiences=body.audiences,
        scopes=body.scopes,
        require_org_membership=body.require_org_membership,
        mcp_resource_uri=body.mcp_resource_uri,
    )
    db.add(client)
    await audit(
        db,
        "client.create",
        org_id=body.org_id,
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
    if body.name is not None:
        client.name = body.name
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


@app.get("/api/v1/tokens", response_model=list[TokenRead], dependencies=[Depends(require_scopes(["auth:read"]))])
async def list_tokens(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiToken).order_by(ApiToken.created_at.desc()))
    return [token_read(token) for token in result.scalars()]


@app.post("/api/v1/tokens", response_model=TokenRead)
async def create_token(
    body: TokenCreate,
    principal: Principal = Depends(require_scopes(["token:*"])),
    db: AsyncSession = Depends(get_db),
):
    token, raw = await create_api_token(
        db,
        name=body.name,
        token_type_value=body.token_type,
        org_id=body.org_id or principal.org_id,
        user_id=principal.user_id if body.token_type in {"personal", "admin"} else None,
        project_id=body.project_id,
        client_id=body.client_id,
        scopes=body.scopes,
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


@app.delete("/api/v1/tokens/{token_id}")
async def revoke_api_token(
    token_id: str,
    principal: Principal = Depends(require_scopes(["token:*"])),
    db: AsyncSession = Depends(get_db),
):
    token = await db.get(ApiToken, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
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
    principal: Principal = Depends(require_scopes(["token:*"])),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.get(ApiToken, token_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Token not found")
    if existing.revoked_at:
        raise HTTPException(status_code=400, detail="Token is already revoked")
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


@app.post("/api/v1/mcp/resources", dependencies=[Depends(require_scopes(["mcp:*"]))])
async def create_mcp_resource(body: McpResourceCreate, db: AsyncSession = Depends(get_db)):
    resource = McpResource(
        org_id=body.org_id,
        name=body.name,
        resource_uri=body.resource_uri,
        scopes=body.scopes or settings.mcp_default_scope_list,
    )
    db.add(resource)
    await db.commit()
    return {"id": resource.id, "resource_uri": resource.resource_uri, "scopes": resource.scopes}


@app.get("/api/v1/mcp/resources", dependencies=[Depends(require_scopes(["mcp:*"]))])
async def list_mcp_resources(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(McpResource).order_by(McpResource.created_at.desc()))
    return [
        {"id": resource.id, "name": resource.name, "resource_uri": resource.resource_uri, "scopes": resource.scopes}
        for resource in result.scalars()
    ]


@app.get("/api/v1/audit", response_model=list[AuditRead], dependencies=[Depends(require_scopes(["auth:read"]))])
async def list_audit(
    actor_user_id: str | None = None,
    action: str | None = None,
    org_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    if actor_user_id:
        query = query.where(AuditEvent.actor_user_id == actor_user_id)
    if action:
        query = query.where(AuditEvent.action == action)
    if org_id:
        query = query.where(AuditEvent.org_id == org_id)
    if target_type:
        query = query.where(AuditEvent.target_type == target_type)
    if target_id:
        query = query.where(AuditEvent.target_id == target_id)
    result = await db.execute(query)
    return [
        AuditRead(
            id=item.id,
            org_id=item.org_id,
            actor_user_id=item.actor_user_id,
            action=item.action,
            target_type=item.target_type,
            target_id=item.target_id,
            details=item.details or {},
            created_at=item.created_at,
        )
        for item in result.scalars()
    ]
