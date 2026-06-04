# Sentinel And Knowhere GateKeeper Integration Starter Prompt

Use this prompt to start a fresh Codex session focused on wiring B3n apps to accept GateKeeper-issued auth while GateKeeper product functionality continues to mature.

```text
/goal Integrate GateKeeper as the backend auth provider for B3n Sentinel and Knowhere while preserving current admin-token fallback and avoiding production cutover until verification is complete.

Context:
- GateKeeper repo: /Users/bensmac/dev/b3n-inc/gatekeeper
- GateKeeper live URL: https://gatekeeper.b3n.in
- GateKeeper current deployed handoff commit: 6eb9470 / full SHA 6eb94704a4451a7857468c879d58b1479daae512
- Sentinel repo: /Users/bensmac/dev/b3n-inc/b3n-sentinel at observed commit 0f6364b
- Knowhere repo: /Users/bensmac/dev/b3n-inc/b3n-knowhere at observed commit 995b029
- Current Sentinel and Knowhere auth posture:
  - Browser control-plane auth is Clerk-based.
  - Backends accept Clerk session JWTs plus existing admin API tokens.
  - UI services currently have Clerk seams in runtime config, main.ts, LoginView.vue, services/clerk.ts, router guards, and API bearer token injection.
  - Sentinel backend seam: sentinel-api/app/auth.py calls app.services.clerk_auth.verify_clerk_session after admin-token fallback.
  - Knowhere backend seam: api/app/services/security.py calls app.services.clerk_auth.verify_clerk_session after admin-token and test-auth fallback.
  - Both projects already have /api/v1/auth/me and admin-token management surfaces.

Start by syncing production truth:
- In each repo, run git status --short --branch, git fetch origin, and inspect whether local main is clean/current.
- Read GateKeeper:
  - docs/internal/session-starters/2026-06-03-gatekeeper-product-core-continuation.md
  - docs/selfhost.md
  - api/app/security.py
  - api/app/deps.py
  - api/app/main.py
  - sdk/python/gatekeeper_sdk if present
- Read Sentinel:
  - README.md
  - SELFHOST.md
  - sentinel-api/app/config.py
  - sentinel-api/app/auth.py
  - sentinel-api/app/services/clerk_auth.py
  - sentinel-api/tests/test_clerk_auth.py
  - sentinel-ui/src/services/clerk.ts
  - sentinel-ui/src/services/api.ts
  - sentinel-ui/src/main.ts
  - sentinel-ui/src/views/LoginView.vue
  - sentinel-ui/src/router/index.ts
- Read Knowhere:
  - README.md
  - SELFHOST.md
  - docs/continuity.md
  - api/app/config.py
  - api/app/services/security.py
  - api/app/services/clerk_auth.py
  - tests/test_security.py
  - ui/src/services/clerk.ts
  - ui/src/services/api.ts
  - ui/src/main.ts
  - ui/src/views/LoginView.vue
  - ui/src/router/index.ts

Primary objective:
Add GateKeeper JWT/session verification to Sentinel and Knowhere backends in a dual-provider mode so B3n can begin testing GateKeeper as the auth authority without removing Clerk or breaking admin-token automation.

Backend integration requirements:
- Add provider mode settings to each backend:
  - AUTH_PROVIDER or CONTROL_PLANE_AUTH_PROVIDER with values clerk, gatekeeper, dual.
  - GATEKEEPER_ISSUER default https://gatekeeper.b3n.in for production docs.
  - GATEKEEPER_JWKS_URL default ${GATEKEEPER_ISSUER}/oauth/jwks.json.
  - GATEKEEPER_AUDIENCE, per app: sentinel-api and knowhere-api.
  - GATEKEEPER_REQUIRED_SCOPES, likely auth:read plus app-specific admin/operator scopes once GateKeeper exposes them.
  - GATEKEEPER_REQUIRED_ROLES, default admin,operator.
  - Optional GATEKEEPER_ORG_ID or org slug once GateKeeper claims are finalized.
- Implement a GateKeeper verifier service in each backend:
  - Fetch/cache JWKS by kid.
  - Validate RS256 signature, iss, aud, exp, nbf if present, and token_type.
  - Parse scope as OAuth space-delimited claim.
  - Map claims to the existing current-user shape used by /api/v1/auth/me.
  - Enforce scopes and roles defensively. If role claims are not yet in GateKeeper JWTs, use scopes/audience first and document the role gap.
  - Return clear 401/403 errors that name missing issuer/audience/scope/role without leaking token data.
- Preserve existing auth order:
  - Admin API token remains accepted.
  - Knowhere test auth remains available only in test mode.
  - In dual mode, accept GateKeeper or Clerk.
  - In gatekeeper mode, reject Clerk except for explicitly documented rollback config.
- Add tests parallel to existing Clerk tests:
  - valid GateKeeper token accepted.
  - wrong issuer rejected.
  - wrong audience rejected.
  - expired token rejected.
  - missing scope rejected.
  - missing/wrong role rejected if role enforcement is implemented.
  - admin-token fallback still works.
  - dual mode still accepts current Clerk test cases.

Frontend integration requirements:
- Do not hard-cut the UI from Clerk until GateKeeper's hosted auth and first-run flows are reliable.
- Add runtime config keys:
  - GATEKEEPER_URL
  - GATEKEEPER_CLIENT_ID
  - GATEKEEPER_AUDIENCE
  - AUTH_PROVIDER or CONTROL_PLANE_AUTH_PROVIDER
- Add a GateKeeper browser auth client alongside the current Clerk service:
  - Redirect to GateKeeper /oauth/authorize with PKCE.
  - Handle callback route and token exchange if implementing UI login in this pass.
  - Store access/refresh tokens under app-specific keys.
  - Attach Authorization: Bearer <GateKeeper access token> in API service.
  - Attempt refresh once on 401.
  - Sign out should revoke/logout where supported and clear local tokens.
- If full UI login is too much for this pass, keep Clerk UI but add backend GateKeeper token support plus docs and CLI/API smoke paths. Do not pretend UI cutover is complete.

GateKeeper preparation:
- In GateKeeper, create or document clients:
  - Sentinel: audience sentinel-api, redirect https://sentinel.b3n.in/auth/callback or the chosen callback route, scopes auth:read plus future sentinel:* scopes.
  - Knowhere: audience knowhere-api, redirect https://knowhere.b3n.in/auth/callback or the chosen callback route, scopes auth:read plus future knowhere:* scopes.
- Confirm GateKeeper discovery and JWKS:
  - curl -fsS https://gatekeeper.b3n.in/.well-known/openid-configuration
  - curl -fsS https://gatekeeper.b3n.in/oauth/jwks.json
- Do not print client secrets or tokens in chat, logs, docs, or tests.

Docs and deployment:
- Update Sentinel and Knowhere README/SELFHOST docs with GateKeeper env vars and dual-provider rollout instructions.
- Keep Clerk rollback documented until GateKeeper cutover is explicitly approved.
- Do not mutate DNS.
- Do not remove Clerk settings or @clerk/vue in the first backend integration unless the UI replacement is implemented and verified.
- Production env changes and public cutover require explicit approval.

Verification:
- GateKeeper: verify /health, /version, discovery, JWKS.
- Sentinel local tests and build for touched backend/UI packages.
- Knowhere local tests and build for touched backend/UI packages.
- Add focused verifier unit tests in both apps.
- If any app is deployed, wait for GitHub Actions, deploy only the approved app, then verify its public /health and /version. Remember Knowhere /version is a stronger artifact truth gate; Sentinel's /version currently reports service/version/environment and may not expose the same image proof.

Expected output:
- Prefer small PR-sized commits per repo.
- Keep a clear integration matrix: Sentinel backend, Sentinel UI, Sentinel CLI, Knowhere backend, Knowhere UI, Knowhere CLI.
- At the end, state exactly what accepts GateKeeper tokens, what still uses Clerk, and what remains behind cutover approval.
```
