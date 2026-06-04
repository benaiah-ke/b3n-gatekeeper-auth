from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt


@dataclass
class Principal:
    subject: str
    scopes: list[str]
    claims: dict[str, Any]
    org_id: str | None = None
    org_slug: str | None = None
    org_role: str | None = None
    email: str | None = None
    display_name: str | None = None
    email_verified: bool | None = None
    mfa_totp_enabled: bool | None = None
    permissions: list[str] = field(default_factory=list)


@dataclass
class ApiTokenValidation:
    active: bool
    reason: str | None = None
    token_id: str | None = None
    token_type: str | None = None
    org_id: str | None = None
    org_slug: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    user_display_name: str | None = None
    project_id: str | None = None
    project_audience: str | None = None
    scopes: list[str] = field(default_factory=list)
    audiences: list[str] = field(default_factory=list)
    missing_scopes: list[str] = field(default_factory=list)


@dataclass
class ProtectedResourceMetadata:
    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": self.authorization_servers,
            "scopes_supported": self.scopes_supported,
        }


class GateKeeperVerifier:
    def __init__(self, issuer: str, audience: str, cache_seconds: int = 3600):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.cache_seconds = cache_seconds
        self._jwks: dict[str, Any] = {"keys": []}
        self._expires_at = 0.0
        self._bearer = HTTPBearer(auto_error=False)

    async def jwks(self) -> dict[str, Any]:
        if self._jwks["keys"] and self._expires_at > time.time():
            return self._jwks
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{self.issuer}/oauth/jwks.json")
            response.raise_for_status()
        self._jwks = response.json()
        self._expires_at = time.time() + self.cache_seconds
        return self._jwks

    async def verify_token(self, token: str) -> Principal:
        header = jwt.get_unverified_header(token)
        jwks = await self.jwks()
        key = next((item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")), None)
        if not key:
            self._expires_at = 0.0
            jwks = await self.jwks()
            key = next((item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")), None)
        if not key:
            raise HTTPException(status_code=401, detail="Unknown GateKeeper signing key")
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
            )
        except JWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid GateKeeper token") from exc
        permissions_claim = claims.get("permissions", [])
        permissions = permissions_claim if isinstance(permissions_claim, list) else []
        return Principal(
            subject=str(claims.get("sub", "")),
            scopes=str(claims.get("scope", "")).split(),
            claims=claims,
            org_id=claims.get("org_id"),
            org_slug=claims.get("org_slug"),
            org_role=claims.get("org_role"),
            email=claims.get("email"),
            display_name=claims.get("display_name"),
            email_verified=claims.get("email_verified"),
            mfa_totp_enabled=claims.get("mfa_totp_enabled"),
            permissions=[str(permission) for permission in permissions],
        )

    async def validate_api_token(
        self,
        token: str,
        *,
        audience: str | None = None,
        required_scopes: list[str] | None = None,
        org_id: str | None = None,
        project_id: str | None = None,
    ) -> ApiTokenValidation:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{self.issuer}/api/v1/tokens/validate",
                json={
                    "token": token,
                    "audience": audience,
                    "required_scopes": required_scopes or [],
                    "org_id": org_id,
                    "project_id": project_id,
                },
            )
            response.raise_for_status()
        payload = response.json()
        return ApiTokenValidation(
            active=bool(payload.get("active")),
            reason=payload.get("reason"),
            token_id=payload.get("token_id"),
            token_type=payload.get("token_type"),
            org_id=payload.get("org_id"),
            org_slug=payload.get("org_slug"),
            user_id=payload.get("user_id"),
            user_email=payload.get("user_email"),
            user_display_name=payload.get("user_display_name"),
            project_id=payload.get("project_id"),
            project_audience=payload.get("project_audience"),
            scopes=[str(scope) for scope in payload.get("scopes", [])],
            audiences=[str(audience) for audience in payload.get("audiences", [])],
            missing_scopes=[str(scope) for scope in payload.get("missing_scopes", [])],
        )

    def api_key_dependency(
        self,
        required_scopes: list[str] | None = None,
        *,
        audience: str | None = None,
        org_id: str | None = None,
        project_id: str | None = None,
        header_name: str = "X-API-Key",
        allow_bearer: bool = True,
    ):
        required = required_scopes or []
        expected_audience = audience or self.audience

        async def _dependency(
            api_key: str | None = Header(default=None, alias=header_name),
            authorization: str | None = Header(default=None),
        ) -> ApiTokenValidation:
            token = api_key
            if not token and allow_bearer and authorization:
                scheme, _, credential = authorization.partition(" ")
                if scheme.lower() == "bearer" and credential:
                    token = credential.strip()
            if not token:
                raise HTTPException(status_code=401, detail=f"{header_name} or Bearer token required")

            validation = await self.validate_api_token(
                token,
                audience=expected_audience,
                required_scopes=required,
                org_id=org_id,
                project_id=project_id,
            )
            if validation.active:
                return validation

            detail = validation.reason or "inactive"
            policy_failures = {"audience_mismatch", "scope_mismatch", "org_mismatch", "project_mismatch"}
            status_code = 403 if detail in policy_failures else 401
            raise HTTPException(status_code=status_code, detail=f"Invalid GateKeeper API token: {detail}")

        return _dependency

    def dependency(self, required_scopes: list[str] | None = None):
        required = required_scopes or []

        async def _dependency(
            credentials: HTTPAuthorizationCredentials | None = Depends(self._bearer),
        ) -> Principal:
            if not credentials or credentials.scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Bearer token required")
            principal = await self.verify_token(credentials.credentials)
            missing = [scope for scope in required if scope not in principal.scopes and "*" not in principal.scopes]
            if missing:
                raise HTTPException(status_code=403, detail=f"Missing scopes: {', '.join(missing)}")
            return principal

        return _dependency

    def protected_resource_metadata(
        self,
        resource: str,
        scopes: list[str] | None = None,
    ) -> ProtectedResourceMetadata:
        return ProtectedResourceMetadata(
            resource=resource,
            authorization_servers=[self.issuer],
            scopes_supported=scopes or [],
        )

    def protected_resource_response(
        self,
        resource: str,
        scopes: list[str] | None = None,
    ) -> JSONResponse:
        return JSONResponse(self.protected_resource_metadata(resource, scopes).model_dump())

    def protected_resource_router(
        self,
        resource: str,
        scopes: list[str] | None = None,
        *,
        path: str = "/.well-known/oauth-protected-resource",
    ) -> APIRouter:
        router = APIRouter()
        metadata = self.protected_resource_metadata(resource, scopes)

        @router.get(path)
        async def _metadata() -> dict[str, Any]:
            return metadata.model_dump()

        return router

    def mcp_challenge_header(
        self,
        metadata_url: str,
        scopes: list[str] | None = None,
    ) -> str:
        scope = " ".join(scopes or [])
        parts = [f'Bearer resource_metadata="{metadata_url}"']
        if scope:
            parts.append(f'scope="{scope}"')
        return ", ".join(parts)

    def mcp_dependency(
        self,
        required_scopes: list[str] | None = None,
        *,
        metadata_url: str,
    ):
        required = required_scopes or []
        protected = self.dependency(required)
        challenge = self.mcp_challenge_header(metadata_url, required)

        async def _dependency(
            credentials: HTTPAuthorizationCredentials | None = Depends(self._bearer),
        ) -> Principal:
            if not credentials or credentials.scheme.lower() != "bearer":
                raise HTTPException(
                    status_code=401,
                    detail="Bearer token required",
                    headers={"WWW-Authenticate": challenge},
                )
            try:
                return await protected(credentials)
            except HTTPException as exc:
                headers = dict(exc.headers or {})
                headers.setdefault("WWW-Authenticate", challenge)
                raise HTTPException(status_code=exc.status_code, detail=exc.detail, headers=headers) from exc

        return _dependency
