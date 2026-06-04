# Internal: Integrating Sentinel And Knowhere

GateKeeper replaces Clerk in Sentinel and Knowhere through a staged migration.
This is an internal B3n rollout note, not the generic self-host setup path.

## Current Source Truth

- Sentinel uses Clerk JWKS verification, authorized-party checks, organization
  membership, role enforcement, bootstrap email allowlists, and hashed admin
  tokens.
- Knowhere uses the same Clerk-shaped flow, with `/health` and `/version` as
  public verification gates.
- Both CLIs currently store manually pasted admin API tokens in local files.

## Migration Plan

1. Register Sentinel and Knowhere as GateKeeper auth clients with exact redirect
   URIs, allowed origins, allowed audiences, and required B3n org roles.
2. Register Sentinel and Knowhere APIs as protected resources with audiences
   `sentinel-api` and `knowhere-api`.
3. Replace app-local Clerk verification with GateKeeper JWKS verification and
   org/role dependencies from `sdk/python`.
4. Replace manual CLI token paste with OAuth device authorization.
5. Keep existing admin token endpoints temporarily as compatibility shims, but
   issue new tokens from GateKeeper.
6. Run local and preview smoke checks before any production auth cutover.

## Client And Resource Baseline

Use these records for the first staged verification pass. Do not publish client
secrets in docs, chat, logs, or tests.

| App | Client id | API audience | Redirect URI | Allowed origin | Initial scopes |
| --- | --- | --- | --- | --- | --- |
| Sentinel | `sentinel-control-plane` | `sentinel-api` | `https://sentinel.b3n.in/api/v1/auth/callback` | `https://sentinel.b3n.in` | `openid profile email auth:read` |
| Knowhere | `knowhere-control-plane` | `knowhere-api` | `https://knowhere.b3n.in/api/v1/auth/callback` | `https://knowhere.b3n.in` | `openid profile email auth:read` |

Protected-resource registration should expose `sentinel-api` and
`knowhere-api` as audiences. Future app-specific scopes can be added after the
first backend-owned GateKeeper smoke succeeds:

- Sentinel: `sentinel:read`, `sentinel:write`, `sentinel:admin`.
- Knowhere: `knowhere:read`, `knowhere:write`, `knowhere:admin`.

Current GateKeeper JWTs derive scopes from membership permissions but do not yet
carry stable role claims. Sentinel and Knowhere therefore enforce issuer,
audience, token type, scope, and optional org first; role claims are enforced
defensively when present.

The GateKeeper `/account` setup console should surface issuer, JWKS, SMTP mode,
current role, and first-run next actions. Use `/clients` templates only after
they are generic enough to avoid making the public product B3n-specific. Copy
confidential client secrets exactly once into the target service's secret store.
Use `/projects` to create the `sentinel-api` and `knowhere-api` audience records
before issuing project or machine credentials.

## Staged Provider Settings

Keep the backends in `CONTROL_PLANE_AUTH_PROVIDER=dual` while testing. Use
`clerk` as the rollback value and `gatekeeper` only after hosted login,
callback handling, CLI/device auth, and public smoke checks have explicit
approval.

Sentinel:

```env
CONTROL_PLANE_AUTH_PROVIDER=dual
GATEKEEPER_ISSUER=https://gatekeeper.b3n.in
GATEKEEPER_AUDIENCE=sentinel-api
GATEKEEPER_REQUIRED_SCOPES=auth:read
GATEKEEPER_REQUIRED_ROLES=admin,operator
```

Knowhere:

```env
CONTROL_PLANE_AUTH_PROVIDER=dual
GATEKEEPER_ISSUER=https://gatekeeper.b3n.in
GATEKEEPER_AUDIENCE=knowhere-api
GATEKEEPER_REQUIRED_SCOPES=auth:read
GATEKEEPER_REQUIRED_ROLES=admin,operator
```

## Non-Goals For Initial Cutover

- Do not mutate production DNS.
- Do not remove Clerk env values until GateKeeper sessions are verified in the
  running apps.
- Do not treat green docs or green CI as proof that production auth changed.
