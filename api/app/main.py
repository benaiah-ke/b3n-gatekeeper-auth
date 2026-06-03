from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import Base, async_session_factory, engine, get_db
from app.deps import Principal, current_principal, require_scopes
from app.models import (
    ApiToken,
    AuditEvent,
    AuthClient,
    DeviceGrant,
    McpResource,
    OAuthAuthorizationCode,
    Organization,
    Project,
    Role,
    Session,
    User,
    Workspace,
)
from app.schemas import (
    AuditRead,
    ClientCreate,
    ClientRead,
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
    RefreshRequest,
    RoleCreate,
    SessionRead,
    SignupRequest,
    TokenCreate,
    TokenRead,
    TokenResponse,
    WorkspaceCreate,
)
from app.security import (
    create_access_token,
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
    ensure_bootstrap,
    get_client_by_client_id,
    org_roles,
    rotate_refresh_token,
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
    access, refresh, session, _refresh_model = await create_session_tokens(db, user, request=request)
    await db.commit()
    response.set_cookie(settings.cookie_name, access, httponly=True, secure=settings.cookie_secure, samesite="lax")
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
    user = await authenticate_password(db, str(body.email), body.password)
    client = await get_client_by_client_id(db, body.client_id) if body.client_id else None
    scopes = client.scopes if client else ["auth:read"]
    audience = client.audiences[0] if client and client.audiences else settings.issuer
    access, refresh, _session, _refresh_model = await create_session_tokens(
        db, user, request=request, client=client, scopes=scopes, audience=audience
    )
    await audit(db, "auth.login", actor_user_id=user.id, request=request)
    await db.commit()
    response.set_cookie(settings.cookie_name, access, httponly=True, secure=settings.cookie_secure, samesite="lax")
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
        user=user_read(user),
        orgs=await org_roles(db, user.id),
    )


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    access, refresh_token, user = await rotate_refresh_token(db, body.refresh_token)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh_token,
        expires_in=settings.access_token_ttl_seconds,
        scope="auth:read",
        user=user_read(user),
        orgs=await org_roles(db, user.id),
    )


@app.post("/api/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(settings.cookie_name)
    return {"status": "ok"}


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


@app.post("/api/v1/auth/email-code/request")
async def request_email_code(body: EmailCodeRequest, db: AsyncSession = Depends(get_db)):
    user_result = await db.execute(select(User).where(User.email == str(body.email).lower()))
    user = user_result.scalar_one_or_none()
    await create_one_time_code(
        db,
        email=str(body.email),
        purpose=body.purpose,
        user_id=user.id if user else None,
    )
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
    response.set_cookie(settings.cookie_name, access, httponly=True, secure=settings.cookie_secure, samesite="lax")
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
    result = await db.execute(select(User).where(User.email == str(body.email).lower()))
    user = result.scalar_one_or_none()
    if user:
        await create_one_time_code(
            db,
            email=str(body.email),
            purpose="reset_password",
            user_id=user.id,
        )
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
async def google_callback():
    return JSONResponse(status_code=501, content={"detail": "Google callback wiring requires provider credentials"})


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
        access, new_refresh, _user = await rotate_refresh_token(db, refresh_token)
        return {
            "access_token": access,
            "refresh_token": new_refresh,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_seconds,
            "scope": "auth:read",
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
    return {"active": True}


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


@app.post("/api/v1/roles", dependencies=[Depends(require_scopes(["admin:*"]))])
async def create_role(body: RoleCreate, db: AsyncSession = Depends(get_db)):
    role = Role(org_id=body.org_id, name=body.name, permissions=body.permissions)
    db.add(role)
    await db.commit()
    return {"id": role.id, "name": role.name, "permissions": role.permissions}


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
        redirect_uris=body.redirect_uris,
        allowed_origins=body.allowed_origins,
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
async def list_audit(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200))
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
