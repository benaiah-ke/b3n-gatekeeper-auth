# Backend Token Verification

Every product backend that accepts GateKeeper bearer tokens must verify the
token itself or call a trusted validation endpoint. Do not authorize requests
from frontend SDK state alone.

## Required Checks

Backends must verify:

- `iss` equals the configured GateKeeper issuer.
- token signature matches a key from GateKeeper JWKS.
- `aud` matches the protected API audience.
- `exp` is in the future.
- required scopes are present.
- account, organization, role, and membership claims satisfy product policy.

## FastAPI Example

The Python SDK includes a FastAPI verifier:

```python
from fastapi import Depends, FastAPI
from gatekeeper_sdk.fastapi import GateKeeperVerifier, Principal

app = FastAPI()
verifier = GateKeeperVerifier(
    issuer="https://auth.example.com",
    audience="example-api",
)


@app.get("/v1/projects")
async def list_projects(
    principal: Principal = Depends(verifier.dependency(["api:read"])),
):
    return {
        "subject": principal.subject,
        "org_id": principal.org_id,
        "org_role": principal.org_role,
        "permissions": principal.permissions,
    }
```

Configure these values from environment variables in real services:

```env
GATEKEEPER_ISSUER=https://auth.example.com
GATEKEEPER_AUDIENCE=example-api
GATEKEEPER_REQUIRED_SCOPES=api:read
```

## JWKS Cache Behavior

The verifier caches JWKS for a short period and refreshes when the token `kid`
is unknown. Operators should persist signing keys across deploys and rotate keys
intentionally.

## User Token Claims

Session-bound user JWTs include:

- `sub`: GateKeeper user id.
- `email`, `email_verified`, and `display_name`.
- `session_id`: backing session id used for revocation checks.
- `mfa_totp_enabled` and `amr`: MFA enrollment and authentication-method evidence.
- `org_id`: selected organization when the token is organization-bound.
- `org_slug`, `org_role`, and `permissions`: active membership claims for the
  selected organization.
- `azp`: OAuth client id when issued for a client.
- `scope`: OAuth scopes granted to this token.

Personal-account tokens for clients that do not require organization membership
can intentionally omit `org_id`, `org_role`, and `permissions`.

## Product Policy

GateKeeper proves identity and token claims. Product backends still own
product-specific policy such as:

- account entitlement
- workspace access
- tenant allowlists
- per-resource permissions
- feature flags
- billing state
- high-risk action step-up requirements

## Opaque API Tokens

Opaque API tokens should be validated through GateKeeper:

```python
from gatekeeper_sdk.fastapi import ApiTokenValidation


@app.get("/v1/api-keys-only")
async def api_key_route(
    token: ApiTokenValidation = Depends(
        verifier.api_key_dependency(["api:read"], audience="example-api")
    ),
):
    return {"org_id": token.org_id, "project_id": token.project_id}
```

The dependency reads `X-API-Key` or `Authorization: Bearer`, calls GateKeeper's
token validation API, and returns account, organization, project, scope,
audience, and last-used metadata for product-local provisioning. Signed
GateKeeper JWTs can be verified locally by JWKS; protocol introspection also
reports signed user JWTs inactive when their backing session is revoked or
expired, and reports client-credentials JWTs inactive when the owning OAuth
client is disabled.
