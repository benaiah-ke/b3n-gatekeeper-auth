# Product Backend Proxy Pattern

Use this pattern when a product wants to own every screen and API route while
GateKeeper remains the central auth provider. The product backend calls the
central auth API, normalizes responses for its frontend, stores product-local
records after identity is proven, and verifies GateKeeper tokens on protected
routes.

This is different from hosted OAuth. The browser talks to your product backend;
your product backend talks to GateKeeper.

## When To Use It

Choose the proxy pattern for:

- product-owned login, signup, reset, MFA, account, API-key, and session screens
- API products that need customer credentials tied to central account identity
- admin dashboards that want local policy or allowlists layered on central auth
- mobile or CLI experiences where the product controls the interaction model
- environments where hosted UI is unavailable or intentionally avoided

Hosted OAuth can still exist for other apps. Both paths issue GateKeeper tokens
and use the same sessions, memberships, roles, scopes, API tokens, and audit
events.

## Flow

1. Product frontend posts credentials or MFA codes to the product backend.
2. Product backend calls GateKeeper with server-side configuration.
3. Product backend returns a product-friendly response and stores tokens in the
   product's chosen storage model.
4. Product backend verifies every protected request by validating GateKeeper JWTs
   or introspecting opaque GateKeeper API tokens.
5. Product backend creates or updates product-local rows after `sub`, `org_id`,
   `aud`, scopes, roles, and permissions pass policy checks.

## Environment

```env
GATEKEEPER_ISSUER=https://auth.example.com
GATEKEEPER_AUDIENCE=example-api
GATEKEEPER_CLIENT_ID=example-web
GATEKEEPER_ADMIN_TOKEN=<owner-or-service-token-for-setup-only>
```

Use a short-lived owner/operator token only for setup automation. Runtime user
flows should use user sessions, OAuth tokens, client credentials, or scoped API
tokens with the narrowest permissions required.

## FastAPI Proxy Example

```python
from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI()

GATEKEEPER_ISSUER = os.environ["GATEKEEPER_ISSUER"].rstrip("/")
GATEKEEPER_CLIENT_ID = os.environ.get("GATEKEEPER_CLIENT_ID")


class LoginBody(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None
    recovery_code: str | None = None


class SignupBody(BaseModel):
    email: EmailStr
    password: str
    display_name: str | None = None


async def gatekeeper_post(path: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"{GATEKEEPER_ISSUER}{path}",
            json=payload,
            headers={"content-type": "application/json"},
        )
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@app.post("/auth/signup")
async def signup(body: SignupBody):
    payload = body.model_dump(exclude_none=True)
    if GATEKEEPER_CLIENT_ID:
        payload["client_id"] = GATEKEEPER_CLIENT_ID
    data = await gatekeeper_post("/api/v1/auth/signup", payload)
    return normalize_auth_response(data)


@app.post("/auth/login")
async def login(body: LoginBody):
    payload = body.model_dump(exclude_none=True)
    if GATEKEEPER_CLIENT_ID:
        payload["client_id"] = GATEKEEPER_CLIENT_ID
    data = await gatekeeper_post("/api/v1/auth/login", payload)
    return normalize_auth_response(data)


@app.post("/auth/refresh")
async def refresh(refresh_token: str):
    data = await gatekeeper_post(
        "/api/v1/auth/refresh",
        {"refresh_token": refresh_token},
    )
    return normalize_auth_response(data)


def normalize_auth_response(data: dict) -> dict:
    user = data.get("user") or {}
    return {
        "accessToken": data.get("access_token"),
        "refreshToken": data.get("refresh_token"),
        "expiresIn": data.get("expires_in"),
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "displayName": user.get("display_name"),
            "emailVerified": user.get("email_verified"),
        },
        "orgs": data.get("orgs", []),
    }
```

## Protect Product APIs

Use the Python verifier or equivalent JWKS verification in your runtime:

```python
from fastapi import Depends
from gatekeeper_sdk.fastapi import GateKeeperVerifier, Principal

verifier = GateKeeperVerifier(
    issuer=os.environ["GATEKEEPER_ISSUER"],
    audience=os.environ["GATEKEEPER_AUDIENCE"],
)


@app.get("/api/projects")
async def projects(principal: Principal = Depends(verifier.dependency(["api:read"]))):
    return {
        "userId": principal.subject,
        "orgId": principal.org_id,
        "role": principal.org_role,
        "permissions": principal.permissions,
    }
```

Do not decode JWTs for authorization without verifying signature, issuer,
audience, expiration, and scopes. Use decoded claims only after verification.

## Product-Local Provisioning

After token verification, create or update product-local records from stable
GateKeeper identifiers:

- `sub` for the GateKeeper user id
- `email`, `email_verified`, and `display_name` for product-local profile snapshots
- `org_id` for the selected organization
- `org_role` and `permissions` for local admin policy
- `aud` for the protected API
- `azp` for the OAuth/client id when relevant

For an API product, keep the local integrator/customer row keyed to GateKeeper
identity or organization. Do not create local credentials that bypass
GateKeeper's revocation, audit, or policy model.

## Account And API-Key Screens

Product-owned account screens can call these through the product backend:

- `GET /api/v1/auth/me`
- `PATCH /api/v1/auth/me`
- `POST /api/v1/auth/password/change`
- `GET /api/v1/auth/mfa/status`
- `POST /api/v1/auth/mfa/totp/setup`
- `POST /api/v1/auth/mfa/totp/enable`
- `POST /api/v1/auth/mfa/recovery-codes/regenerate`
- `GET /api/v1/sessions`
- `DELETE /api/v1/sessions/{session_id}`
- `GET /api/v1/tokens`
- `POST /api/v1/tokens`
- `POST /api/v1/tokens/{token_id}/rotate`
- `DELETE /api/v1/tokens/{token_id}`

Forward the user's GateKeeper access token to these calls from the backend, or
exchange product cookies for GateKeeper calls server-side if the product owns
cookie storage.

## Admin Proxy

For admin dashboards, proxy owner/operator actions with a verified admin user
token or a narrow service token. The product should still enforce local policy
such as allowlists, tenant entitlement, or feature permissions after GateKeeper
proves central identity.

Useful admin endpoints include:

- `GET /api/v1/users`
- `PATCH /api/v1/users/{user_id}`
- `PUT /api/v1/users/{user_id}/membership`
- `POST /api/v1/users/{user_id}/sessions/revoke`
- `POST /api/v1/users/{user_id}/mfa/totp/reset`
- `GET /api/v1/audit`

## Common Mistakes

- Do not treat hosted UI as mandatory. It is one integration option.
- Do not duplicate central account or API-key state in a product database unless
  it is product-local metadata.
- Do not use long-lived owner tokens for normal user flows.
- Do not authorize by unverified decoded JWT claims.
- Do not hide GateKeeper revocation by minting independent product sessions
  that never check GateKeeper session, token, or user state.
