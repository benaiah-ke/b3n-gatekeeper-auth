# Integrating Sentinel And Knowhere

GateKeeper replaces Clerk in Sentinel and Knowhere through a staged migration.

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

## Non-Goals For Initial Cutover

- Do not mutate production DNS.
- Do not remove Clerk env values until GateKeeper sessions are verified in the
  running apps.
- Do not treat green docs or green CI as proof that production auth changed.

