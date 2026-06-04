# B3n Infra GateKeeper First Setup And Integration Starter Prompt

Use this prompt to start a fresh Codex session focused on making the fresh
self-hosted GateKeeper install the real B3n auth authority across Sentinel,
Knowhere, and Reword. This is an internal B3n infra prompt, not a public
GateKeeper self-host guide.

```text
/goal Complete the B3n infrastructure auth cutover from old GateKeeper/Clerk-era primitives to the freshly reset self-hosted GateKeeper, guide the first production setup, and wire Sentinel, Knowhere, and Reword to use the new GateKeeper as the central auth provider for hosted UI auth, backend/API auth, CLI auth, and future MCP/API-extension auth.

Critical current truth:
- GateKeeper repo: /Users/bensmac/dev/b3n-inc/gatekeeper
- GateKeeper remote: git@github.com:benaiah-ke/b3n-gatekeeper-auth.git
- Latest GateKeeper source HEAD observed before this prompt: ac6bc102a36e3d695006d5fb13043af3d566ff91 on main.
- Live GateKeeper runtime image tag: 73b88ff17e855f0431169e652fa760f1f20a63c8.
- Live GateKeeper URL: https://gatekeeper.b3n.in
- GateKeeper was rebuilt ground-up as an API-first self-hosted auth provider, then the B3n production self-host was reset from scratch.
- Fresh reset tracking note: docs/internal/status/2026-06-04-production-fresh-selfhost-reset.md
- Host rollback bundle: /apps/gatekeeper/backups/fresh-reset-20260604T163332Z
- Host reset log: /apps/gatekeeper/reset-logs/20260604T163425Z-fresh-reset.txt
- Post-reset verification at handoff:
  - /health returned ok with database connected.
  - /version reported image_tag=73b88ff17e855f0431169e652fa760f1f20a63c8.
  - /signup rendered first-owner setup copy.
  - /oauth/jwks.json returned a newly generated key after the API data volume reset.
  - Fresh DB counts were users=0, organizations=1, clients=1, sessions=0.
  - Existing Chrome session redirected from /account to /login?redirect=/account, as expected after the reset.
- Sentinel CLI was intended as the infra tracking surface, but the local Sentinel session was expired and sentinel login required interactive username/OTP input. Start by restoring Sentinel CLI auth or explicitly keep a host/repo-local tracking fallback.

Repos to cover:
- GateKeeper: /Users/bensmac/dev/b3n-inc/gatekeeper
- Sentinel: /Users/bensmac/dev/b3n-inc/b3n-sentinel
  - Observed HEAD before this prompt: 4b0985a on main, commit title "Replace Clerk with backend GateKeeper auth".
- Knowhere: /Users/bensmac/dev/b3n-inc/b3n-knowhere
  - Observed HEAD before this prompt: fe74b2d on main, commit title "Replace Clerk with backend GateKeeper auth".
- Reword: /Users/bensmac/dev/reword
  - Observed branch before this prompt: design-system-redesign-v1 at 8698f6e, commit title "Add Full V1 keyed drill starter prompt".

Important interpretation:
- Sentinel and Knowhere already have some GateKeeper backend-auth work. Do not assume it is complete or compatible with the freshly reset, API-first GateKeeper. Audit it as an old or partial primitive.
- Reword has auth pages and API auth-readiness work, but should be audited against the new central GateKeeper model before cutover.
- This session should guide the first live GateKeeper setup and then replace old integration assumptions in each app with the new self-hosted provider contract.
- Avoid production-cutover claims unless live source, infra, env, app behavior, and browser/API checks all prove them.

First recon:
1. In every repo, run:
   - git status --short --branch
   - git fetch origin
   - git log -5 --oneline --decorate
2. Verify live GateKeeper:
   - curl -fsS https://gatekeeper.b3n.in/health
   - curl -fsS https://gatekeeper.b3n.in/version
   - curl -fsS https://gatekeeper.b3n.in/.well-known/openid-configuration
   - curl -fsS https://gatekeeper.b3n.in/oauth/jwks.json
   - curl -fsSI https://gatekeeper.b3n.in/signup
3. Verify production host truth through b3n-sentinel SSH if Sentinel CLI is unavailable:
   - compose ps for /apps/gatekeeper
   - current GATEKEEPER_IMAGE_TAG
   - non-secret fresh DB counts
   - reset log and backup bundle paths
4. Restore or explicitly gate Sentinel CLI tracking:
   - sentinel login
   - sentinel status
   - sentinel projects
   - sentinel services
   - sentinel deployments
   - sentinel audit
   If Sentinel CLI auth cannot be restored, keep that caveat visible and create repo-local status notes plus host-local logs for any manual infra changes.

GateKeeper first production setup:
1. Open https://gatekeeper.b3n.in/signup and create the first B3n owner account. Do not ask for or print credentials, OTPs, recovery codes, cookies, tokens, client secrets, or env secrets.
2. Confirm /account loads for the owner and shows owner state for the bootstrap org.
3. Immediately capture the setup baseline without secrets:
   - owner exists
   - issuer and JWKS URL
   - SMTP mode
   - readiness percentage and warnings
   - sessions count
   - clients/resources count
4. Configure the production safety baseline before connecting apps:
   - owner authenticator MFA
   - org MFA policy where appropriate
   - trusted-device reuse policy
   - admin step-up MFA
   - idle-timeout policy
   - audit retention policy
   - SMTP settings if password reset, email verification, invitations, or email-code login will be used
5. Create or verify GateKeeper resources for the B3n apps:
   - Protected API resources/audiences:
     - sentinel-api
     - knowhere-api
     - reword-api
   - Hosted web/control-plane OAuth clients:
     - sentinel-control-plane
     - knowhere-control-plane
     - reword-web
   - CLI/device clients:
     - sentinel-cli
     - knowhere-cli
     - reword-cli if Reword needs CLI auth in this phase
   - MCP/protected resources only for surfaces that actually exist.
6. Use exact callback and origin values from each app's current code and production domain. Do not invent callback routes. If a route does not exist, implement it or leave it explicitly pending.
7. Copy client secrets exactly once into the relevant secret store/env surface. Do not paste secrets into chat, docs, tests, shell output, or tracker notes.

Expected GateKeeper app records:
- Sentinel:
  - audience: sentinel-api
  - likely origin: https://sentinel.b3n.in
  - callback: inspect current Sentinel UI/backend routes before choosing
  - initial scopes: openid profile email auth:read sentinel:read sentinel:write sentinel:admin as supported
- Knowhere:
  - audience: knowhere-api
  - likely origin: https://knowhere.b3n.in
  - callback: inspect current Knowhere UI/backend routes before choosing
  - initial scopes: openid profile email auth:read knowhere:read knowhere:write knowhere:admin as supported
- Reword:
  - audience: reword-api
  - likely origin: https://reword.b3n.in or the current production/preview domain verified in repo/infra
  - callback candidate to inspect: apps/web/pages/auth/callback.vue
  - initial scopes: openid profile email auth:read reword:read reword:write reword:admin as supported

Integration work by product:

Sentinel:
- Read:
  - README.md
  - SELFHOST.md
  - sentinel-api/app/config.py
  - sentinel-api/app/auth.py
  - sentinel-api/app/services/gatekeeper_auth.py
  - sentinel-api/tests/test_gatekeeper_auth.py
  - sentinel-ui/src/stores/auth.ts
  - sentinel-ui/src/services/auth.ts
  - sentinel-ui/src/services/api.ts
  - sentinel-cli/sentinel_cli/auth.py
- Audit current GateKeeper auth implementation against the new live issuer, JWKS, claims, session behavior, audience, scopes, org claims, and API-token semantics.
- Replace or harden any old primitive that assumes Clerk-shaped claims, stale GateKeeper tokens, manual admin-token paste, or non-revocable sessions.
- Preserve admin-token fallback only as a documented rollback/automation path until GateKeeper CLI/device auth and hosted UI login are verified.
- Ensure backend auth verifies issuer, audience, signature, exp/nbf, token type, scopes, org/account claims, and session-bound revocation semantics where applicable.
- Ensure UI hosted login uses GateKeeper authorize + PKCE or a product-owned API flow, not stale Clerk UI assumptions.
- Ensure CLI auth uses GateKeeper device authorization or clearly documents the remaining admin-token fallback gap.

Knowhere:
- Read:
  - README.md
  - SELFHOST.md
  - docs/continuity.md if present
  - api/app/config.py
  - api/app/services/security.py
  - api/app/services/gatekeeper_auth.py if present
  - tests/test_gatekeeper_auth.py
  - tests/test_security.py
  - knowhere-cli/knowhere_cli/auth.py
  - UI auth service/router/login files found during recon
- Audit current GateKeeper auth implementation against the new live provider.
- Keep /health and /version as required live truth gates; /version must prove the running artifact before claiming deployment completion.
- Replace old auth assumptions with the same central GateKeeper model used by Sentinel.
- Preserve only intentional rollback fallbacks and document exactly when they can be removed.

Reword:
- Read:
  - README.md
  - docs/launch-blockers.md
  - docs/release-readiness.md
  - docs/implementation/verification/auth-readiness-drill.md
  - apps/web/pages/auth/login.vue
  - apps/web/pages/auth/callback.vue
  - apps/web/pages/auth/logout.vue
  - apps/web/middleware/auth.global.ts
  - services/api/app/core/auth.py
  - services/api/app/core/authorization.py
  - services/api/app/security/authorization.py
  - services/api/tests/security/test_auth_readiness_drill.py
  - services/api/tests/security/test_launch_auth_and_hardening.py
- Determine whether Reword should use hosted GateKeeper auth, product-owned API auth screens, or a hybrid.
- Wire Reword web login/callback/logout to the fresh GateKeeper client and exact Reword callback.
- Wire Reword API verification to issuer, JWKS, reword-api audience, scopes, org/account claims, and revocation-compatible behavior.
- If Reword has API-extension/product API surfaces, use GateKeeper API keys/service/project tokens tied to the same account model.
- Keep Reword launch-readiness docs honest: do not mark auth ready until browser login, callback, API verification, logout/session behavior, and live deploy checks pass.

Infra and env management:
- Use Sentinel as the intended infra tracking/control surface once authenticated.
- Use masked/key-name-only env audits. Never print full env, secrets, tokens, cookies, client secrets, recovery codes, SMTP secrets, DB URLs, or private keys.
- For each app, record which env surface owns:
  - GATEKEEPER_ISSUER
  - GATEKEEPER_JWKS_URL
  - GATEKEEPER_AUDIENCE
  - GATEKEEPER_CLIENT_ID
  - GATEKEEPER_CLIENT_SECRET if confidential
  - GATEKEEPER_REQUIRED_SCOPES
  - GATEKEEPER_REQUIRED_ROLES or permissions if supported
  - AUTH_PROVIDER / CONTROL_PLANE_AUTH_PROVIDER
  - Clerk rollback values if still present
- Keep GitHub deployment auth separate from app runtime auth where Knowhere/Sentinel env management expects that separation.
- Do not mutate DNS, remove Clerk production values, delete rollback credentials, or rotate secrets without explicit approval.

Implementation posture:
- Prefer small, auditable commits per repo.
- Keep product-specific migration notes internal.
- Use GateKeeper SDKs/helpers where they fit, but verify their behavior against the live provider.
- If one app already has a partial GateKeeper verifier, fix it instead of rewriting blindly.
- Do not collapse API auth, hosted web auth, CLI auth, and service-token auth into one token path. They are distinct surfaces tied to the same central account/session/audit model.

Verification expectations:
- GateKeeper first setup:
  - first owner can sign in
  - /account shows owner state and setup/readiness signals
  - MFA/policy baseline configured or explicitly deferred with reason
  - clients/resources/audiences created for Sentinel, Knowhere, and Reword
  - no secrets printed
- GateKeeper public provider:
  - /health ok
  - /version reports image tag
  - OIDC discovery ok
  - JWKS ok
  - hosted signup/login/account routes render
- Sentinel:
  - focused backend auth tests
  - UI build if UI changed
  - CLI auth smoke if CLI changed
  - local or deployed /health and auth/me smoke
  - live deploy only after CI and explicit approval
- Knowhere:
  - focused backend auth/security tests
  - UI build if UI changed
  - CLI auth smoke if CLI changed
  - /health and /version after deploy; /version must match the deployed artifact
- Reword:
  - focused API auth tests
  - web build/typecheck
  - browser login/callback/logout smoke
  - launch-readiness/auth-readiness docs updated
- Cross-product:
  - one B3n account can authenticate to the intended apps or the remaining blocker is explicit
  - API tokens/service tokens validate for intended audiences/scopes
  - session revoke/logout behavior is proven for at least one web app and one CLI path if CLI is in scope
  - all remaining Clerk/admin-token fallbacks are listed with removal gates

Required closeout:
- Update repo-local internal status notes with:
  - GateKeeper first setup state
  - app/resource/client IDs without secrets
  - env keys changed without values
  - Sentinel/Knowhere/Reword integration matrix
  - verification commands and results
  - deploy URLs and artifact SHAs
  - rollback path
  - remaining blockers
- If Sentinel CLI tracking is restored, reconcile project/deployment/audit entries there too.
- End with local and remote git status for every touched repo.
- State exactly:
  - what is fully on new GateKeeper
  - what is dual-provider
  - what still uses old Clerk/admin-token/manual auth
  - what needs user approval before final production cutover
```
