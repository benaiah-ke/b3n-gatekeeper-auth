# API Keys And API Auth

API products should use GateKeeper-issued credentials tied to the same account,
organization, project, scope, audience, and audit model as human auth.

## Token Types

Current token types are:

- `personal`
- `service`
- `project`
- `admin`
- `machine`

Use the narrowest type and scope that matches the caller.

## Create A Personal Token

Any signed-in user can create personal tokens for their own account. Requested
scopes must be a subset of the user's current scopes unless the user has token
administration permissions.

```bash
curl -s https://auth.example.com/api/v1/tokens \
  -H 'authorization: Bearer <user-access-token>' \
  -H 'content-type: application/json' \
  -d '{
    "name":"My API key",
    "token_type":"personal",
    "org_id":"<org-id>",
    "scopes":["auth:read"],
    "audiences":["example-api"]
  }'
```

Personal token listing, rotation, and revocation are scoped to the current
account. A regular user cannot inspect or mutate service, project, admin, or
machine tokens owned by the organization.

## Create Service Or Project Tokens

Service, project, admin, and machine tokens require an owner/operator access
token with token administration capability.

```bash
curl -s https://auth.example.com/api/v1/tokens \
  -H 'authorization: Bearer <owner-or-token-admin-access-token>' \
  -H 'content-type: application/json' \
  -d '{"name":"Example API key","token_type":"project","scopes":["api:read"],"audiences":["example-api"]}'
```

The raw token is shown once in the `token` field. Store it immediately and never
write it to docs, logs, or tests.

## Use A Token

```bash
curl -s https://api.example.com/v1/resource \
  -H 'authorization: Bearer <gk-token>'
```

Product APIs can either validate opaque GateKeeper API tokens or verify signed
GateKeeper JWTs depending on the credential type. Prefer local JWT verification
for signed access tokens and the product validation endpoint for opaque API
tokens.

## Validate An API Token

Use the product validation endpoint when your API receives a copy-once
GateKeeper token and needs account, organization, project, scope, and audience
metadata for provisioning or authorization:

```bash
curl -s https://auth.example.com/api/v1/tokens/validate \
  -H 'content-type: application/json' \
  -d '{
    "token":"<gk-token>",
    "audience":"example-api",
    "required_scopes":["api:read"],
    "org_id":"<optional-org-id>",
    "project_id":"<optional-project-id>"
  }'
```

An active response includes the token type, token id, org metadata, user
metadata when account-bound, project metadata when project-bound, scopes,
audiences, and updated `last_used_at`. A failed policy check returns
`active:false` with a reason such as `scope_mismatch`, `audience_mismatch`,
`org_mismatch`, `project_mismatch`, `revoked`, or `expired`.

The JS SDK exposes the same check:

```ts
const validation = await gatekeeper.validateApiToken({
  token: apiKey,
  audience: 'example-api',
  requiredScopes: ['api:read'],
})
if (!validation.active) throw new Error(validation.reason || 'invalid token')
```

Signed-in product users can also manage account-bound API keys through the JS
SDK or Vue composable:

```ts
const created = await gatekeeper.createApiToken(userAccessToken, {
  name: 'Example API key',
  tokenType: 'personal',
  scopes: ['api:read'],
  audiences: ['example-api'],
})

const tokens = await gatekeeper.apiTokens(userAccessToken)
const rotated = await gatekeeper.rotateApiToken(userAccessToken, created.id)
await gatekeeper.revokeApiToken(userAccessToken, rotated.id)
```

```ts
import { useGateKeeperAuth } from 'gatekeeper-vue'

const auth = useGateKeeperAuth()
const created = await auth.createApiToken({
  name: 'Example API key',
  tokenType: 'personal',
  scopes: ['api:read'],
  audiences: ['example-api'],
})
```

The Python FastAPI helper exposes `validate_api_token(...)` and a dependency
that reads `X-API-Key` or `Authorization: Bearer`:

```python
token: ApiTokenValidation = Depends(
    verifier.api_key_dependency(["api:read"], audience="example-api")
)
```

## Product-Local Provisioning

GateKeeper proves central identity and credential policy. Your product still
owns product-local records such as billing customers, integrator workspaces,
feature flags, quotas, webhook endpoints, and domain-specific permissions.

Use stable GateKeeper identifiers as foreign keys:

- `user_id` for personal/account-bound API keys
- `org_id` and `org_slug` for organization-scoped customers
- `project_id` and `project_audience` for product/API resources
- `token_id` for audit joins and key-specific rate limits
- `user_email` and `user_display_name` for product-local profile snapshots
- `scopes` and `audiences` for product authorization decisions

Example FastAPI pattern for an API extension:

```python
from fastapi import Depends, HTTPException
from gatekeeper_sdk.fastapi import ApiTokenValidation


@app.post("/v1/extensions")
async def create_extension(
    payload: ExtensionCreate,
    token: ApiTokenValidation = Depends(
        verifier.api_key_dependency(["extensions:write"], audience="example-api")
    ),
    db: ProductDb = Depends(product_db),
):
    owner_key = token.org_id or token.user_id
    if not owner_key:
        raise HTTPException(status_code=403, detail="account or org token required")

    integrator = await db.integrators.upsert_from_gatekeeper(
        gatekeeper_owner_key=owner_key,
        gatekeeper_org_id=token.org_id,
        gatekeeper_user_id=token.user_id,
        gatekeeper_project_id=token.project_id,
        gatekeeper_token_id=token.token_id,
        email=token.user_email,
        display_name=token.user_display_name,
    )

    if not await db.entitlements.can_create_extension(integrator.id):
        raise HTTPException(status_code=403, detail="plan does not allow extensions")

    return await db.extensions.create(
        integrator_id=integrator.id,
        name=payload.name,
        created_by_gatekeeper_token_id=token.token_id,
    )
```

For machine callers using OAuth client credentials, verify the signed access
token by JWKS and key product-local service records by `azp` or the configured
audience/project. For opaque service/project tokens, keep using
`/api/v1/tokens/validate` so revocation, expiration, scope policy, and
`last_used_at` stay centralized in GateKeeper.

## Introspection

```bash
curl -s https://auth.example.com/oauth/introspect \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'token=<token>'
```

Introspection validates opaque GateKeeper API tokens and signed GateKeeper JWTs.
User JWTs issued by current GateKeeper builds carry a `session_id`, so revoked
or expired sessions are reported inactive during introspection. Introspection
also reports opaque API tokens inactive when their user, organization membership,
project, or owning OAuth client is no longer valid, and it reports
client-credentials JWTs inactive after the owning OAuth client is disabled.
Organization-bound user JWTs also carry `org_id`, `org_slug`, `org_role`, and
`permissions` claims for the selected active membership.

## Rotate Or Revoke

```bash
curl -X POST https://auth.example.com/api/v1/tokens/<token-id>/rotate \
  -H 'authorization: Bearer <owner-or-token-admin-access-token>'

curl -X DELETE https://auth.example.com/api/v1/tokens/<token-id> \
  -H 'authorization: Bearer <owner-or-token-admin-access-token>'
```

Rotation revokes the old token and returns a new one-time value.
