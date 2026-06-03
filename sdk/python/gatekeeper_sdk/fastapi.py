from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt


@dataclass
class Principal:
    subject: str
    scopes: list[str]
    claims: dict[str, Any]


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
        return Principal(
            subject=str(claims.get("sub", "")),
            scopes=str(claims.get("scope", "")).split(),
            claims=claims,
        )

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

