# GateKeeper Product-Core Continuation Starter Prompt

Use this prompt to start a fresh Codex session focused on making GateKeeper feel like a real auth product after the first successful hosted deploy.

```text
/goal Continue GateKeeper from the deployed production-core baseline and turn the authenticated control plane into a usable self-hosted auth product.

Context:
- Repo: /Users/bensmac/dev/b3n-inc/gatekeeper
- Remote: git@github.com:benaiah-ke/b3n-gatekeeper-auth.git
- Current deployed commit at handoff: 6eb9470 / full SHA 6eb94704a4451a7857468c879d58b1479daae512
- Live URL: https://gatekeeper.b3n.in
- Current stack: FastAPI, Vue 3, Tailwind v4, Postgres, Docker Compose, shared Sentinel Caddy proxy.
- Current public smoke checks were green for /health, /version, OIDC discovery, JWKS, /login, /signup, and JS/CSS assets.
- Live browser observation after a reported signup: navigating to https://gatekeeper.b3n.in/account redirected to /login?redirect=/account. Treat this as a product/DX issue to investigate first, not as proof the user did anything wrong.
- Important backend behavior: signup creates a membership in the bootstrap org, but only grants owner if the email matches BOOTSTRAP_ADMIN_EMAIL; otherwise the user becomes viewer. This can make first setup feel broken on self-hosted installs.

Start by syncing truth:
- git status --short --branch
- git fetch origin and confirm main is current before edits
- Inspect recent commits: 6eb9470, 596ec37, 3b69351
- Check live https://gatekeeper.b3n.in/account with the current browser session if available, but do not ask for secrets or print tokens.
- Read first:
  - README.md
  - docs/selfhost.md
  - api/app/main.py
  - api/app/services.py
  - api/app/security.py
  - ui/src/router/index.ts
  - ui/src/services/api.ts
  - ui/src/views/SignupView.vue
  - ui/src/views/LoginView.vue
  - ui/src/views/AccountView.vue
  - ui/src/views/ClientsView.vue
  - ui/src/views/TokensView.vue
  - ui/src/views/RolesView.vue

Primary objective:
Make the post-signup and authenticated operator flow obvious, secure, and useful enough that a self-hosted operator knows exactly what to do next without Clerk.

Critical product fixes:
- Fix first-owner bootstrapping. A fresh self-host install needs an explicit first-owner path:
  - If no owner exists, the first successful signup should become owner, or the UI must require/match BOOTSTRAP_ADMIN_EMAIL before presenting signup as setup.
  - Add a clear setup state if the current user is viewer and cannot create clients/tokens.
  - Add tests for first user, bootstrap admin email, subsequent user, and duplicate email.
- Fix session continuity after signup/login:
  - Confirm tokens are saved, refresh works, cookies are correct for production, and /account does not bounce unexpectedly.
  - Keep access-token refresh retry behavior.
  - Add route-level and API-level tests where practical.
- Replace the thin account page with a real setup console:
  - Current user, org, role, scopes, token expiry, session state.
  - Next actions: create app client, create service token, register MCP resource, approve CLI device login.
  - Show why an action is unavailable instead of letting users hit opaque 403s.
- Build a real first-run wizard:
  - Owner confirmation.
  - Org/workspace/project creation or confirmation.
  - Register Sentinel and Knowhere clients with good defaults.
  - Create CLI/device client if absent.
  - Verify issuer, JWKS, and SMTP/email mode.
  - End with concrete integration snippets.
- Improve clients:
  - List, create, disable/enable, rotate secret, delete where safe.
  - Public vs confidential client choice.
  - Redirect URI validation and allowed origins preview.
  - Templates for GateKeeper UI, Sentinel, Knowhere, CLI, MCP, generic OAuth app.
  - One-time secret display with copy action and audit event.
- Improve tokens:
  - Token types: personal, service, project, admin, machine.
  - Audience picker from projects/clients/resources.
  - Scope picker instead of freeform text only.
  - Expiry, revoke, rotate, last used, owner, token hint.
  - Clear copy-once UX for generated token values.
- Improve org/workspace/project/RBAC:
  - Add useful list endpoints and UI if missing.
  - Do not leave roles as static copy once API data exists.
  - Role assignment and membership invitation can be v1 if email delivery is ready; otherwise document the missing surface honestly.
- Improve audit and sessions:
  - Filter audit by actor/action/resource.
  - Session revoke current/other sessions.
  - Friendly empty/loading/error states with readable API errors.
- Improve operator DX:
  - Add docs for "after signup, do this next".
  - Add a self-host checklist in UI and docs.
  - Add sample env for Sentinel/Knowhere integration using GateKeeper.
  - Do not print secrets in logs/docs/tests.

Security constraints:
- Keep opaque refresh/device/API tokens hashed at rest.
- Keep JWT signing asymmetric and JWKS-backed.
- Preserve refresh rotation/replay protections.
- Validate issuer, audience, expiry, scopes, redirect URIs, and org role boundaries.
- Dynamic client registration remains disabled by default.
- Do not expose passkey/WebAuthn UI unless you implement and test the full secure flow.
- Do not mutate DNS or cut over Sentinel/Knowhere without explicit approval.

Verification:
- pnpm build
- uv --cache-dir .uv-cache run --extra dev pytest
- uv --cache-dir .uv-cache run --extra dev ruff check app tests
- docker build -t gatekeeper-ui:ci-smoke -f ui/Dockerfile .
- docker build -t gatekeeper-api:ci-smoke ./api
- docker compose config checks with B3N_ENV_FILE=.env.example.selfhost
- Browser smoke for /signup, /login, /account, /clients, /tokens, /roles on desktop and mobile.
- If deployed: wait for GitHub Actions image job, repin /apps/gatekeeper/.env to the green full SHA, pull/up containers, verify /health, /version, discovery, JWKS, hosted pages/assets, and Sentinel /health plus /version.

Expected output:
- Implement functionality, tests, and docs. Do not stop at a proposal.
- Commit progressively with focused messages.
- Push to main only after local verification is green.
- If deployment is included, report the exact image SHA and public smoke evidence.
```

