from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ApiToken, Membership, Role
from app.security import decode_access_token, now_utc, token_hash

bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    subject: str
    auth_type: str
    scopes: list[str]
    org_id: str | None = None
    user_id: str | None = None
    token_id: str | None = None
    claims: dict | None = None


async def current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    raw = None
    if credentials and credentials.scheme.lower() == "bearer":
        raw = credentials.credentials
    elif request.cookies.get("gk_session"):
        raw = request.cookies.get("gk_session")
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    if raw.startswith("gk_"):
        result = await db.execute(select(ApiToken).where(ApiToken.token_hash == token_hash(raw)))
        api_token = result.scalar_one_or_none()
        if (
            not api_token
            or api_token.revoked_at
            or (api_token.expires_at and api_token.expires_at <= now_utc())
        ):
            raise HTTPException(status_code=401, detail="Invalid API token")
        api_token.last_used_at = now_utc()
        await db.commit()
        return Principal(
            subject=api_token.user_id or api_token.client_id or api_token.id,
            auth_type=api_token.token_type,
            scopes=api_token.scopes or [],
            org_id=api_token.org_id,
            user_id=api_token.user_id,
            token_id=api_token.id,
        )

    try:
        claims = decode_access_token(raw)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid access token") from exc
    scope = str(claims.get("scope", "")).split()
    return Principal(
        subject=str(claims.get("sub", "")),
        auth_type=str(claims.get("token_type", "access")),
        scopes=scope,
        org_id=claims.get("org_id"),
        user_id=str(claims.get("sub", "")) if claims.get("token_type") == "user" else None,
        claims=claims,
    )


def require_scopes(required: list[str]):
    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if "*" in principal.scopes:
            return principal
        missing = [scope for scope in required if scope not in principal.scopes]
        if missing:
            raise HTTPException(status_code=403, detail=f"Missing required scopes: {', '.join(missing)}")
        return principal

    return dependency


async def require_org_role(
    org_id: str,
    allowed_roles: set[str],
    principal: Principal,
    db: AsyncSession,
) -> None:
    if "*" in principal.scopes or "admin:*" in principal.scopes:
        return
    if not principal.user_id:
        raise HTTPException(status_code=403, detail="User-bound token required")
    result = await db.execute(
        select(Membership, Role)
        .join(Role, Role.id == Membership.role_id)
        .where(Membership.org_id == org_id, Membership.user_id == principal.user_id)
    )
    row = result.first()
    if not row or row[0].status != "active" or row[1].name not in allowed_roles:
        raise HTTPException(status_code=403, detail="Organization role required")

