# GateKeeper API-First OSS Auth Provider Starter Prompt

Use this prompt to start a fresh Codex session focused on turning GateKeeper
from a B3n-internal control-plane auth app into an API-first, OSS-first,
self-hosted auth provider. The hosted UI matters, but it is not the first
primitive. The first primitive is that any product backend can integrate
GateKeeper directly by API and get a complete central auth system.

```text
/goal Transform GateKeeper into an API-first, OSS-first, self-hosted auth provider that product backends can integrate directly for signup, signin, reset, 2FA, social auth, account management, admin, roles, API keys, API auth, session/device management, CLI auth, MCP auth, and optional hosted UI auth, while preserving current security primitives and avoiding unapproved production cutovers.

Repo and source truth:
- Repo: /Users/bensmac/dev/b3n-inc/gatekeeper
- Remote: git@github.com:benaiah-ke/b3n-gatekeeper-auth.git
- Product-core batch verified during the June 4, 2026 recon: `ae49c3ce3e2301b65db023687d570c1cd37e9b04` on `main`.
- Older deployed baseline mentioned in the original handoff: `6eb94704a4451a7857468c879d58b1479daae512`.
- Live URL: https://gatekeeper.b3n.in
- Stack: FastAPI, Vue 3, Tailwind v4, Postgres, Docker Compose, Caddy/shared Sentinel proxy, JS/Vue packages, Python FastAPI verifier, Typer CLI.
- Before continuing, re-run `git fetch origin`, `git status --short --branch`, and `git log -5 --oneline --decorate`; do not rely on this snapshot if newer commits exist.
- June 4, 2026 post-deploy recon found `main...origin/main` clean at `ae49c3c`, CI run `26959065847` successful for API/UI/images, production `GATEKEEPER_IMAGE_TAG=ae49c3ce3e2301b65db023687d570c1cd37e9b04`, API/UI containers running that tag, `/health` healthy, OIDC discovery and JWKS live, and `/login`, `/signup`, and `/account` returning the SPA shell with HTTP 200.
- `/version` originally reported product version/environment/issuer only, so deploy proof relied on production image metadata. A follow-up release-metadata patch adds optional `image_tag` and `git_sha` fields when the API container has `GATEKEEPER_IMAGE_TAG` or `GIT_SHA`.

User/problem context:
- The current logged-in experience does not explain how GateKeeper is supposed to work as a normal auth provider.
- It feels like a B3n control-plane setup console, not a general self-hosted auth product.
- Public self-host docs and internal docs expose B3n infrastructure details directly and indirectly. Keep public OSS docs generic and isolate B3n-specific migration notes.
- The intended product is a central auth provider B3n can self-host and use across apps, API products, CLIs, MCP servers, and hosted UI auth, similar to how Payd Auth centralizes auth across Payd Labs products, but cleaner, better documented, safer, and more OSS-ready.
- Treat the reported `https://gatekeeper.b3n.in/account` -> `/login?redirect=/account` behavior after signup as a product/DX issue to investigate first, not as proof the user did something wrong.

Product surfaces, in priority order:
1. API-only product backend integration:
   - Signup, signin, reset, verification, 2FA, social auth as configured, account/profile management, admin actions, roles/permissions, organization/account management, API keys, API auth for API extensions/products, device management, sessions, session rules, token refresh, logout, revocation, and audit.
   - Products should be able to own their own frontend/backend UX while using GateKeeper as the central auth authority.
2. Hosted auth and frontend SDK integration:
   - GateKeeper-hosted login/signup/reset/verification/device/account/admin UI where needed.
   - Vue and Nuxt surfaces for auth state, login redirect, callback handling, refresh, guarded routes, account/session components, and API-key/admin components where appropriate.
   - Hosted UI should use the same API primitives as API-only integration.
3. CLI and MCP auth:
   - Device or OTP login, local credential storage, refresh, logout, CLI profile switching, automation token override, device/session visibility, and revocation.
   - MCP protected-resource metadata, resource-bound tokens, scopes, and shared account/session management.

Payd Auth comparison context from local code review:
- Payd Auth core is API-first: REST/gRPC auth APIs for login, logout, verify token, request OTP, verify OTP, renew session, onboarding/users, password reset, organizations/accounts/roles, API keys, and KYC profile data.
- Payd Web under `/Users/bensmac/dev/payd/ui-migrate/payd-ui-v2` owns product auth screens and calls Payd Auth APIs directly for login, OTP, refresh, signup, activation, reset, profile, and API keys. Product request clients inject tokens and refresh on 401.
- Stables under `/Users/bensmac/dev/payd/payd-labs-stables-v1` proves API-product auth needs account-bound API credentials, validation against central auth, product-local integrator provisioning, callback secrets, hosted profile tokens, and an admin auth proxy.
- Sentinel under `/Users/bensmac/dev/payd/payd-labs-sentinel` proves admin products may proxy central login/OTP/refresh, while CLI and MCP use the same central account through local refreshable credentials.
- Knowhere under `/Users/bensmac/dev/payd/payd-labs-ui-server` proves product backends layer local admin policy and allowlists on central identity, and CLI auth follows the same central flow.
- Preserve Payd Auth strengths: API-first use, staged login/OTP, refresh lifecycle, account/role claims, account-bound API keys, product-owned UX, CLI/MCP reuse, and product-local provisioning.
- Improve Payd Auth weaknesses: scattered docs, inconsistent token/header conventions, unsafe decode-only JWT patterns, duplicated product proxy code, unclear API-key/service-key model, product-specific CLI stores, and lack of OSS self-host ergonomics.

B3n/Reword design context:
- Use the B3n/Reword visual language: dark operational surface, compact layout, hairline borders, small dense controls, cobalt for functional action, mono labels, restrained serif display only where it helps, and actual work surfaces first.
- Check `/Users/bensmac/dev/b3n-inc/b3n-inc-landing` for B3n design tokens and `/Users/bensmac/dev/reword/docs/design-system.md` plus Reword app surfaces for the recent product/control-plane feel.
- Do not build a marketing landing page for the app. Build a precise operator/developer console: apps, APIs, users, roles, keys, sessions/devices, policy, audit, issuer/JWKS, and integration snippets.

First, verify current truth:
1. Run `git status --short --branch`, `git fetch origin`, `git log -5 --oneline --decorate`.
2. Review any user/agent changes before edits and do not overwrite unrelated dirty work.
3. Read these newly created direction and integration docs:
   - `docs/product/api-first-auth-provider.md`
   - `docs/internal/product/payd-auth-comparison.md`
   - `docs/getting-started.md`
   - `docs/concepts.md`
   - `docs/integrations/api-only.md`
   - `docs/integrations/product-backend-proxy.md`
   - `docs/integrations/backend.md`
   - `docs/integrations/web-app.md`
   - `docs/integrations/vue-nuxt.md`
   - `docs/integrations/api-keys.md`
   - `docs/integrations/cli.md`
   - `docs/integrations/mcp.md`
   - `docs/reference/api-surface.md`
   - `README.md`
   - `docs/selfhost.md`
4. Check whether live https://gatekeeper.b3n.in is on source HEAD by using `/version`, CI/image metadata, and deployment metadata available in the repo/host. Do not claim deploy parity without proof.
5. If using the user's Chrome session for live UX inspection, do not ask for or print secrets/tokens. Treat redirects, viewer states, missing setup cues, or confusing flows as product signals.
6. Browser automation note from the active session: Chrome extension automation worked for authenticated live/local QA, including safe form entry. Do not inspect or print secrets/tokens. In-app Browser narrow-viewport QA later worked for public `/signup` and `/login`; authenticated narrow-viewport control-plane QA still needs a logged-in browser or local seeded install before claiming full mobile polish.

Current GateKeeper capability inventory from prior code review:
- Backend already has useful auth-provider primitives:
  - OIDC discovery, OAuth authorization server metadata, JWKS.
  - Authorization-code + PKCE, refresh rotation, client credentials, device authorization, revocation, introspection.
  - Hosted login/signup/reset/email-code/device pages backed by the Vue app.
  - Users, orgs, workspaces, projects, roles, memberships, auth clients, sessions, refresh tokens, API tokens, MCP resources, audit events, rate limits.
  - First successful signup becomes owner if no active owner exists; bootstrap admin is also owner when it signs up.
  - Python FastAPI JWT verifier exists and validates issuer, audience, JWKS, and scopes.
  - CLI uses device authorization.
- Product gap:
  - These primitives are not assembled into a clear provider experience.
  - API-only product backend integration is not the public center of gravity.
  - `/account` now has a first-pass developer/operator workbench with owner/JWKS/SMTP state, first-run checks, setup completion percentage, production-readiness blockers/warnings, operator shortcuts, next actions, copyable API backend, hosted auth, Vue/Nuxt, API-key, CLI, and MCP integration blocks, self-service profile/password/email-change/export/deactivation controls, plus account-level authenticator 2FA setup/enable/disable controls. `/policy` now exposes org MFA status, trusted-device MFA reuse, admin step-up MFA, idle-timeout controls, user hard-delete policy, and a recommended baseline checklist/action that applies org MFA, trusted-device reuse, safe idle timeout, and MFA-aware admin step-up remediation. `/users` now exposes SCIM-style user provisioning plus policy-gated hard-delete preview and email-confirmed execution. `/audit` now has first-pass event category summaries, quick filters, and organization audit retention/prune controls over the existing audit API. It still needs broader desktop/mobile visual QA across richer seeded data.
  - `docs/integrations/api-only.md` now has a concrete runbook for "operator setup -> product backend integrates by API -> product verifies tokens -> product creates API keys -> product manages sessions/devices"; it includes self-service profile/password/email-change/linked-identity/export/deactivation examples, explicit session-bound provider linking, install-owner OIDC/social provider setup, configured provider discovery/start examples, custom provisioning, SCIM v2 Users/Groups compatibility with pagination, common sorting, write-only user password operations, SCIM Bulk, and membership-scoped Enterprise User fields, self-service personal API keys, operator-managed service/project/admin/machine tokens, product API-token validation with scope/audience/org/project checks, product-local provisioning pointers, authenticator TOTP API examples, recovery codes, client-level MFA policy, org-wide MFA policy for registered app/device sessions, trusted-device MFA reuse policy, admin step-up MFA policy for sensitive organization mutations, org/client idle-timeout policy, user hard-delete policy, session device label/trust examples, admin reset, admin connected-app grant review/revocation, and invitations. `docs/integrations/api-keys.md` now includes a concrete FastAPI provisioning pattern for API extensions that key product-local records to stable GateKeeper identifiers. These docs still need updates when custom account-linking policy or custom SCIM enterprise extension policy lands.
  - `docs/integrations/product-backend-proxy.md` now documents the central-auth proxy pattern where a product backend owns auth routes/screens, calls GateKeeper server-side, normalizes responses for its UI, verifies tokens on protected routes, and provisions product-local records after GateKeeper identity and claims are verified.
  - `docs/reference/api-surface.md` maps health/discovery, direct auth/account, MFA, sessions/grants, invitations, OAuth/device/machine flows, setup/policy, API tokens, users, and audit endpoints by intended surface: provider API, OAuth/OIDC, hosted backing API, operator API, MCP/OAuth, or operations.
- User admin now has API/UI coverage for custom provisioning, SCIM v2 Users/Groups compatibility with pagination, common sorting, write-only user password operations, SCIM Bulk, and membership-scoped Enterprise User fields, listing users, profile/verification state, suspension, role/status assignment, last-owner protection, disabled-user token invalidation, MFA state, admin TOTP reset, invitations, per-user session revocation, and policy-gated hard-delete preview/execution. Self-service email change now has API/UI coverage with verified-code confirmation and other-session revocation. Self-service linked identities now have API/UI/SDK coverage with last-sign-in-method protection and explicit session-bound provider linking. Configured OIDC/social providers now have generic provider metadata/start/callback APIs, install-owner database-managed provider CRUD with encrypted client-secret storage, `/providers` control-plane UI, hosted login/signup buttons, signed callback state, verified-email linking policy, Google compatibility aliases, and JS/Vue helpers. Self-service account export/deactivation now has API/UI/SDK coverage, last-owner protection, and revocation cleanup. Organization audit retention/pruning and user hard-delete policy now have API/UI coverage. Remaining work: custom SCIM enterprise extension policy, custom account-linking policy, and richer audit investigation views.
- Invitations now have backend API coverage for create/list/revoke/accept, copy-once invitation tokens, dev-mode token return, optional SMTP delivery with hosted accept links, existing-account password/TOTP checks, membership assignment, audit events, `/invitations` admin UI, and `/accept-invite` hosted UI.
- Authenticator TOTP now has backend API coverage for status/setup/enable/disable/admin-reset, encrypted secret storage, password-login enforcement, copy-once recovery codes, recovery-code login, recovery-code regeneration, client/org-level MFA enforcement for login/OAuth/device/refresh flows, hosted OAuth `step_up=mfa` redirects for password-only browser sessions, trusted-device MFA reuse policy for active trusted sessions, admin step-up MFA policy for sensitive organization mutations, `mfa_totp_enabled` and persisted `amr` token claims, regression coverage, login-form/recovery-code entry, `/account` controls, Clients/Policy-page controls, and Users-page reset controls. Session/device management now has label/trust metadata with API/UI/SDK coverage plus org/client idle-timeout policy enforcement. Remaining work: adaptive risk signals and richer hosted enrollment/remediation polish.
  - Direct owner signup/login/email-code sessions now derive scopes from active organization memberships when no registered client narrows the token. This fixed an API-first setup regression where an owner could sign in but could not call `admin:*` setup APIs such as workspace/project/client creation until after a refresh. Regression coverage was added in `test_cookie_auth_and_refresh_preserve_owner_scope`.
  - Cookie-backed session auth now reads `settings.cookie_name` instead of a hard-coded `gk_session`, so self-hosted installs that override `COOKIE_NAME` do not create a cookie that the API then ignores. The owner-scope cookie regression test now runs under a custom cookie name.
  - Hosted browser sessions now set a real HttpOnly refresh cookie (`REFRESH_COOKIE_NAME`, default `gk_refresh`) alongside the short-lived access cookie, `/api/v1/auth/refresh` can rotate from that cookie with an empty JSON body, logout clears both cookies, and the Vue router preserves safe login/signup redirects back to `/oauth/authorize` with a full backend navigation for already-authenticated users. Regression coverage was added in `test_refresh_can_rotate_from_browser_refresh_cookie`, plus the login/refresh/logout cookie assertions in `test_signup_login_refresh_and_replay_detection` and `test_logout_revokes_current_session_and_refresh_token`.
  - Local API-first setup smoke against a fresh temp DB succeeded after the owner-scope fix: owner login had `*`, setup status reported owner existence, workspace/project/client creation worked, org MFA policy could be enabled, a personal token could be created, and sessions listed successfully.
  - Client/app management now scopes list, create, update, secret rotation, and delete operations to the current organization for org-bound operators. Created clients default to the active organization, cross-org client mutation returns not found, clients can carry hosted consent metadata for app logo/description/homepage/privacy/terms plus publisher/verified trust metadata, and org-membership OAuth/device flows resolve org-owned clients to the client organization.
  - Workspace, project/API-audience, and role setup APIs now use the same current-organization isolation model: org-bound operators list only current-org resources, cross-org create/list attempts are denied, and projects cannot attach to a workspace from another organization.
  - User admin, invitations, MCP resources, and audit reads now use the same current-organization visibility model: org-bound operators only see current-org users/memberships/invitations/resources/events, cross-org list attempts are denied, and cross-org by-id admin mutations are hidden as not found.
  - SDK parity is still incomplete but materially better: JS/Vue now cover PKCE hosted auth, callback exchange, token storage, direct product-owned signup/signin/invitation/email-code/password-reset helpers, refresh, `/me`, profile update, password change, sessions, session device controls, social provider discovery/start/admin-management helpers, user and admin connected-app grants, API-token validation and list/create/rotate/revoke helpers, server-runtime JWKS verification, and Nuxt runtime-config wiring. The Vue package now also exposes `useGateKeeperAccount`, `useGateKeeperSessions`, `useGateKeeperApiTokens`, `useGateKeeperConnectedApps`, and `useGateKeeperConnectedAppsAdmin` view-model composables for product-owned account, device/session, API-key, connected-app, and operator grant-review pages; `useGateKeeperHydration` and `gateKeeperLoginRedirectPath` for Nuxt/client route hydration; and optional `GateKeeperAccountCard`, `GateKeeperSessionList`, `GateKeeperApiTokenList`, and `GateKeeperConnectedAppsList` components for apps that want drop-in account controls. The Python FastAPI helper now validates opaque API tokens through GateKeeper, exposes an `api_key_dependency(...)` for API products, and includes MCP protected-resource metadata/challenge helpers. The CLI now has `gatekeeper doctor` for install readiness, directly rotates API tokens with copy-once output, and validates API tokens with audience/scope/org/project policy checks. Deeper component coverage for provider/admin setup and more framework examples still need work.

Important code/product seams to investigate and fix where appropriate:
- `/oauth/authorize` should validate client, redirect URI, audience, and scopes before redirecting unauthenticated users to hosted login/signup, then return to the original authorize request. Signed-in users should see the hosted `/authorize` approval screen before code issuance. Re-test this flow before changing it further.
- GateKeeper now has a lightweight hosted authorization page with app identity, optional app logo/description/homepage/privacy/terms metadata, publisher/verified trust badge, redirect origin, audience, account/org scope, and scopes. It supports explicit org selection for multi-org users, rejects forged org IDs, binds issued authorization codes to the resolved organization, leaves non-org clients unbound unless they request a valid org, remembers approved OAuth grants, skips consent when an active grant covers the request, exposes user connected-app grant listing/revocation, and exposes org-scoped admin grant review/revocation. Remaining work: richer consent policy beyond operator-managed app trust badges and richer multi-tenant role/permission claims.
- Login/signup redirect handling now uses a shared safe internal-redirect helper. OAuth authorize redirects survive password/social login, signup, and already-authenticated visits to `/login?redirect=/oauth/authorize...`; MFA-required OAuth authorize requests redirect password-only browser sessions through `/login?step_up=mfa` and then return to the original authorize request after TOTP/recovery-code login. Continue adding browser-level QA and richer hosted error states.
- `/oauth/introspect` now validates signed GateKeeper JWTs, returns inactive for invalid non-opaque tokens, reports user JWTs inactive when their backing session is revoked/expired/idle-timed-out or their active organization membership is lost, reuses opaque API-token live validation semantics, and reports opaque client-bound tokens plus client-credentials JWTs inactive when the owning OAuth client is disabled.
- Logout and session revocation now mark DB sessions revoked, revoke refresh tokens for revoked sessions, invalidate current user JWTs carrying `session_id`, support revoking other sessions, support sign-out-everywhere, and expose app-aware session inventory with OAuth client metadata, assurance methods, device labels, trusted-device metadata, last-seen timestamps, and a current-session marker. Direct org switching now exists at `POST /api/v1/auth/session/switch-org`, and org creation seeds default roles plus an owner membership for the creating session user. Org/client idle-timeout policy now revokes idle sessions and refresh tokens, trusted-device MFA reuse is policy-gated across active org/client MFA policies, admin step-up MFA protects sensitive org mutations, and the CLI now refreshes local access tokens, accepts automation token overrides, can run install readiness checks, can list/switch orgs, and can list/revoke/label/trust/untrust sessions. Keep regression coverage and extend this into adaptive risk signals.
- `require_org_membership`, allowed origins, org selection, and role claims need continued review across authorize/token issuance and verifier expectations. The authorize/context/code issuance path now uses shared org resolution, org-owned clients that require membership resolve to the client organization, setup resources are current-org isolated, and org-bound user JWTs now include `org_slug`, `org_role`, and `permissions` for the selected active membership. Next work should extend cross-org claim strategy and verifier examples rather than re-solving basic app/client/setup-resource org isolation.
- WebAuthn table exists without product endpoints; either document as future work or implement intentionally.
- Dynamic client registration is advertised only when enabled but returns 501; keep disabled by default and document policy clearly.

B3n/internal leakage to clean up:
- README, self-host docs, env examples, Caddy examples, compose examples, config defaults, UI templates, tests, package metadata, CLI defaults, and SDK metadata have been scrubbed toward generic OSS defaults in the active worktree; re-scan before claiming this is complete.
- Earlier UI defaults hardcoded B3n branding and first-run milestones for Sentinel and Knowhere; current UI should be re-scanned and browser-checked before assuming the product experience is clean.
- NPM package names have been moved away from the initial `@b3n/gatekeeper-*` namespace; decide whether unscoped names are final or whether the project should adopt a public npm org.
- Internal docs and session starters now live under `docs/internal/`; keep B3n-specific migration notes there and do not present them as the public self-host path.

Target product model:
- GateKeeper is the central authorization server, identity store, session/device manager, API-key manager, and audit authority.
- Product backends can call GateKeeper APIs directly for every auth lifecycle step.
- Users sign in once through either product-owned API-driven screens or GateKeeper hosted UI.
- Web apps can redirect to GateKeeper with OAuth/OIDC authorization-code + PKCE and receive code/state at their callback.
- Backends/APIs verify GateKeeper JWTs by issuer, audience, expiration, JWKS key, scopes, permissions, and account/org claims.
- API-first products can use API keys, service tokens, personal tokens, project tokens, or client credentials depending on caller type.
- CLIs use device/OTP authorization and store refreshable credentials locally.
- MCP HTTP servers publish protected-resource metadata and challenge clients to obtain resource-bound tokens.
- Admins/operators use the dashboard to create apps/resources, configure redirect URIs/audiences/scopes, manage users/orgs/roles/tokens/sessions/devices, configure policies, and audit events.

Workstreams:
1. API-first docs and information architecture
   - Keep `README.md`, `docs/selfhost.md`, `docs/product/api-first-auth-provider.md`, and `docs/internal/product/payd-auth-comparison.md` current.
   - Keep and expand the public guide set:
     - `docs/getting-started.md`
     - `docs/concepts.md`
     - `docs/integrations/api-only.md`
     - `docs/integrations/product-backend-proxy.md`
     - `docs/integrations/web-app.md`
     - `docs/integrations/backend.md`
     - `docs/integrations/vue-nuxt.md`
     - `docs/integrations/api-keys.md`
     - `docs/integrations/cli.md`
     - `docs/integrations/mcp.md`
     - `docs/reference/api-surface.md`
     - `docs/security.md` or link/update SECURITY.md
   - `docs/integrations/api-only.md` now includes copy-paste examples for direct signup/signin/reset, social provider setup/list/start, explicit session-bound provider linking, email codes, refresh/logout, setup status, workspace/project/client creation, linked identity listing/unlinking, API token create/validate/introspect/rotate/revoke, client credentials, sessions/devices, session label/trust controls, backend verification, and product-backend proxy routing.
   - `docs/integrations/product-backend-proxy.md` now provides a concrete FastAPI proxy example and common mistakes for product-owned auth UX.
   - `docs/reference/api-surface.md` now maps the available endpoints by surface and calls out deliberate incompleteness such as dynamic registration, custom account-linking policy, adaptive risk signals, and WebAuthn/passkey endpoints.
   - Continue adding or expanding copy-paste examples for:
     - custom account-linking policy once implemented
     - custom SCIM enterprise extension policy if product integrations need attributes beyond the common Enterprise User fields
     - OAuth authorize URL and callback exchange polish
     - adaptive risk signals and richer CLI/MCP policy helpers
     - richer MCP server examples beyond the FastAPI protected-resource helper
   - Keep B3n/Sentinel/Knowhere migration notes under `docs/internal/` or another clearly marked internal path. Do not let them be the default OSS quickstart.

2. API/provider correctness
   - Keep the endpoint map accurate as routes change, and use it to decide what is public provider API, operator/admin API, hosted UI backing API, OAuth protocol endpoint, or internal-only.
   - Implement or document gaps for signup, signin, reset, 2FA, social auth, account management, roles, API keys, API auth, sessions, devices, rules, admin, and audit.
   - Keep introspection behavior aligned with API-token validation, session revocation, client disablement, and any future risk/session policy rules.
   - Verify session revocation and refresh-token behavior against revoked sessions.
   - Extend client `require_org_membership` behavior into cross-org role policy beyond app/client isolation, verifier examples, and richer grant policy.
   - Keep access-token claim policy and verifier examples current as richer multi-tenant role policy lands. Current user JWTs include `email`, `email_verified`, `display_name`, `session_id`, MFA assurance fields, `azp`, audience, and selected-org role/permission claims when organization-bound.
   - Review logout semantics and refresh-token family/session cleanup.
   - Keep dynamic client registration disabled unless a real policy and tests are added.
   - Add focused tests for each behavior touched.

3. Product UX cleanup
   - Continue the `/account` developer/operator workbench so it answers:
     - What is my issuer?
     - What is my JWKS URL?
     - Is SMTP configured?
     - What app/API should I create first?
     - What exact values do I copy into my backend or Vue/Nuxt app?
     - What sessions/devices/API keys exist and how do I revoke them?
     - What policy gaps remain before this install is production ready?
     - Which users, roles, connected apps, and audit events need attention?
   - `/account` now includes setup completion, production-readiness health rows, blockers/warnings, and operator shortcuts; `/policy` includes a recommended production baseline action and user hard-delete policy; `/users` includes hard-delete preview and email-confirmed execution; `/audit` includes first-pass category summaries, quick filters, and audit retention/prune controls. Continue broader seeded-data visual QA rather than recreating those primitives.
   - Replace Sentinel/Knowhere first-run steps with generic first-run steps:
     - create first owner
     - configure issuer/JWKS/SMTP
     - protect first API
     - create first API key
     - create first web app
     - configure session/2FA policy
     - create CLI/device client if needed
     - create MCP resource if needed
   - Replace client templates with generic templates:
     - API-only product backend
     - Single-page app
     - Server-rendered web app
     - Backend/API resource
     - CLI/device app
     - MCP server
     - Machine-to-machine service
   - API-token management now distinguishes account-owned personal keys from operator-managed service/project/admin/machine credentials: regular session-bound users can create/list/rotate/revoke only their own personal tokens with non-escalating scopes, while token admins/operators manage org credentials. The token issuer UI offers product API scopes (`api:read`, `api:write`) so the API-key flow can match the backend integration snippets.
   - Client registration now has `require_mfa`; organizations now have `require_mfa`; login with `client_id`, hosted OAuth authorization-code issuance/exchange, device approval/exchange, and refresh preserve/enforce `amr` so app/org-level MFA policy is auditable. Enabling org MFA revokes stale org-bound client sessions without MFA assurance.
   - Integration snippets now use the actual selected client/audience/scope for the main API/backend, hosted auth, Vue/Nuxt, API-key, CLI, and MCP surfaces; continue polishing exact product-backend proxy examples and server verification snippets.
   - Make public branding configurable/generic. If B3n branding remains for the live B3n instance, make it runtime config, not hardcoded OSS default.

4. Hosted auth flow parity
   - Implement or harden authorize -> login/signup -> authorize return -> callback behavior.
   - Add safe redirect handling for OAuth authorize requests, preserving `state`.
   - Add a lightweight app authorization/consent screen if appropriate.
   - Build richer consent and grant policy on top of the current remembered grant records.
   - Add tests for unauthenticated authorize redirect, login return, callback code issuance, invalid redirects, and state preservation.

5. SDK/CLI/product integration
   - JS SDK now includes helpers for PKCE generation, authorization URL creation, callback exchange, direct signup/signin/invitation/email-code/password-reset, OAuth refresh, client-credentials tokens, `/me`, password change, protected-resource metadata, browser token storage, API-token validation and list/create/rotate/revoke, sessions, session device updates, social provider discovery/start/admin management, user and admin connected-app grants, and server-runtime JWKS verification helpers.
   - Vue package now provides auth state, token storage, direct product-owned signup/signin/invitation/email-code/password-reset helpers, login redirect helpers, callback handling, refresh, logout, user loading, profile update, password change, API-token list/create/rotate/revoke, sessions, user/admin grants, Nuxt runtime-config wiring, route hydration helpers, account/session/API-token/connected-app/admin-grant-review view-model composables, and optional drop-in account/session/API-token/connected-app components. Continue with richer provider/admin setup components only where they remove real integration work.
   - Python SDK now includes FastAPI JWT/API-key verification plus MCP protected-resource metadata/challenge helpers; consider generic ASGI helpers.
   - CLI should default to configured/local issuer or require explicit issuer setup; keep `gatekeeper.b3n.in` out of the built-in OSS default. Current CLI coverage includes device login, refresh, org switch, session/device label/trust/revoke, API-token create/list/rotate/revoke/validate, client creation, and MCP resource registration.
   - Add product-backend proxy examples so products can own their auth UI while delegating auth to GateKeeper APIs.
   - Confirm or document package namespace strategy so OSS consumers do not see a private tenant/operator as the default.

6. Deployment/self-host cleanup
   - Make public self-host defaults generic:
     - `auth.example.com`, `admin@example.com`, `Example Org`, `example-api`.
   - Keep B3n production host specifics out of public defaults.
   - Provide local Docker Compose quickstart and production Docker Compose instructions separately.
   - Document persistent JWT key handling, backups/restores, SMTP, CORS/cookie domains, reverse proxy, and upgrade verification.
   - Do not mutate DNS, Caddy, production env, Sentinel, Knowhere, or other apps without explicit user approval.

Suggested review commands:
- `rg -n "B3n|b3n|Sentinel|Knowhere|gatekeeper\\.b3n\\.in|admin@b3n\\.in|@b3n|b3n-gatekeeper|benaiah|Cloudflare|droplet|/apps|sentinel|knowhere"`
- `rg --files`
- `sed -n '1,260p' README.md docs/selfhost.md docs/architecture.md docs/mcp-auth.md docs/product/api-first-auth-provider.md docs/internal/product/payd-auth-comparison.md docs/integrations/product-backend-proxy.md docs/reference/api-surface.md`
- `sed -n '1,260p' api/app/config.py api/app/main.py api/app/services.py api/app/deps.py api/app/security.py api/app/models.py api/app/schemas.py`
- `sed -n '1,260p' ui/src/App.vue ui/src/views/AccountView.vue ui/src/views/ClientsView.vue ui/src/views/LoginView.vue ui/src/views/SignupView.vue ui/src/services/api.ts`
- `sed -n '1,260p' packages/js/src/index.ts packages/vue/src/index.ts sdk/python/gatekeeper_sdk/fastapi.py cli/gatekeeper_cli/*.py`

Verification expectations:
- Run focused backend tests for touched API behavior, then full API tests when feasible.
- Run UI typecheck/build for UI/package changes.
- Run SDK/package builds if package APIs change.
- Run docs/link/leakage scans for documentation changes.
- Run B3n leakage scan and make sure any remaining B3n strings are intentional, marked internal, or maintainer/legal metadata.
- If frontend UX changes are made, run the local app and inspect desktop/mobile with Browser or Chrome as appropriate.
- Verification already performed during the product-core build-up session: focused linked-identity API tests passed, focused session-device trust tests passed, focused configured social-provider API/callback tests passed, full API tests passed after the configured social-provider patch (`32 passed`), package/UI build passed after the JS/Vue/UI changes, Ruff passed, `git diff --check` passed, public leakage scan was clean for public docs/deploy/API/UI/package surfaces, Docker Compose self-host/existing-proxy config checks passed, focused custom-cookie regression passed after the patch, focused self-service profile/password/email-change regression passed, focused account export/deactivation policy regression passed, and a local GateKeeper-signed JWT/JWKS fixture verified successfully through the compiled JS SDK while rejecting a missing required scope. After the admin connected-app grant review slice, the focused admin grant regression passed, full API tests passed (`35 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, and the public leakage scan was clean. After the org-scoped client management slice, focused multi-org/client-isolation regressions passed and full API tests passed (`36 passed`). After the setup-resource isolation slice, focused multi-org workspace/project/role regressions passed and full API tests passed (`37 passed`). After the admin visibility isolation slice, focused users/invitations/MCP/audit regressions passed and full API tests passed (`38 passed`). After the account readiness/local-dev slice, SQLite migrations applied from an empty temp DB through head, local API/UI dev servers ran with the Vite proxy, a seeded owner could sign in through Chrome and render `/account` with readiness/policy-health/operator-shortcut UI, full API tests passed (`43 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, and the public leakage scan was clean. After the direct SDK auth slice, `pnpm build` passed, `git diff --check` passed, the public leakage scan was clean, and a compiled JS SDK mock-fetch smoke confirmed direct `login()` includes configured `client_id` plus MFA fields and `signup()` sends the expected display-name payload. After the Python MCP helper slice, an SDK smoke verified `ProtectedResourceMetadata` export, metadata payload generation, and exact MCP `WWW-Authenticate` challenge formatting. After the CLI token helper slice, `gatekeeper --help` ran successfully through `uv --with-editable .`, CLI Ruff passed, `git diff --check` passed, and the public leakage scan was clean. After the hosted consent metadata slice, focused metadata/authorize-context tests passed (`2 passed, 43 deselected`), full API tests passed (`45 passed`), Ruff passed, `pnpm build` passed, SQLite Alembic upgrade applied through `20260604_0014`, `git diff --check` passed, and the public leakage scan was clean. After the Vue component SDK slice, `GateKeeperAccountCard`, `GateKeeperSessionList`, `GateKeeperApiTokenList`, and `GateKeeperConnectedAppsList` were present in the built JS bundle and `dist/index.d.ts`, `pnpm build` passed, `git diff --check` passed, the public leakage scan was clean, and the stale optional-component gap scan returned no matches. After the product-local provisioning docs slice, `docs/integrations/api-keys.md` gained a FastAPI provisioning example, `docs/integrations/api-only.md` links to it from token validation, `git diff --check` passed, and the public leakage scan was clean. After the CLI doctor slice, `gatekeeper --help` and `gatekeeper doctor --help` showed the new command, CLI Ruff passed, `gatekeeper doctor --url http://127.0.0.1:9` returned a clean readiness table with blockers instead of a traceback, `pnpm build` passed after fixing the `/account` CLI copy snippet, `git diff --check` passed, the stale CLI command scan was clean, and the public leakage scan was clean. After the hosted MFA step-up slice, focused MFA regression passed, full API tests passed (`45 passed`), Ruff passed, `pnpm build` passed, stale hosted-challenge wording scan was clean, and the public leakage scan was clean. After the Policy/Audit remediation slice, `pnpm build` passed, `git diff --check` passed, stale policy-remediation wording scan was clean, public leakage scan was clean, SQLite migrations applied on a throwaway temp DB, Chrome desktop QA rendered `/policy` and `/audit`, `/policy` apply-baseline updated org MFA/trusted-device/idle-timeout while leaving admin step-up open until owner MFA enrollment, and `/audit` categorized the resulting `org.update` event correctly. After the audit retention/prune slice, focused regression passed, full API tests passed (`46 passed`), Ruff passed, `pnpm build` passed, SQLite Alembic upgrade applied through `20260604_0015`, `git diff --check` passed, stale retention-gap wording scan only found intentional hard-delete/account-policy gaps, and the public leakage scan was clean. After the client trust metadata slice, focused authorize-context regression passed, full API tests passed (`46 passed`), Ruff passed, `pnpm build` passed after fixing the client metadata text-value helper, SQLite Alembic upgrade applied through `20260604_0016`, `git diff --check` passed, stale app-trust wording scan only found intentional publisher/verified-app text, and the public leakage scan was clean. After the account deletion policy slice, focused admin hard-delete regression passed, full API tests passed (`47 passed`), Ruff passed, `pnpm build` passed, SQLite Alembic upgrade applied through `20260604_0017`, `git diff --check` passed, stale hard-delete gap wording scan only found intentional implemented-policy text, public leakage scan was clean, and Chrome desktop QA rendered the `/policy` account-lifecycle card plus `/users` hard-delete controls against a throwaway local SQLite install. Authenticated mobile viewport QA remained open at that point because the Chrome fallback did not expose viewport emulation.
- After the SCIM-style provisioning slice, the focused provisioning regression passed, full API tests passed (`48 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale provisioning-gap wording scan was clean, the public leakage scan was clean, and Chrome desktop QA rendered the `/users` provisioning panel against a throwaway local SQLite install.
- After the ownership-aware introspection slice, the focused disabled-client introspection regression passed, nearby introspection/API-token validation regressions passed (`3 passed`), Ruff passed, and `git diff --check` passed. Opaque API-token introspection now reuses live validation semantics, and client-credentials JWT introspection reports disabled owning clients inactive.
- After the account-display claim slice, user JWT issuance/refresh include `display_name`, JWT introspection returns common account/profile claims, opaque API-token validation returns `user_display_name`, and JS/Python SDK types expose the new metadata. Focused claim/introspection/API-token validation tests passed, full API tests passed (`49 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale gap wording scan was clean, and the public leakage scan was clean.
- After the SCIM v2 Users compatibility slice, GateKeeper exposes SCIM service metadata plus `/scim/v2/Users` list/filter/create/read/replace/patch/delete for a selected organization. SCIM `active` maps to selected-org membership, role values map to GateKeeper role names, and deprovisioning revokes stale sessions. Focused SCIM regression passed, full API tests passed (`50 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale SCIM-gap wording scan was clean, and the public leakage scan was clean.
- After the SCIM v2 Groups compatibility slice, GateKeeper exposes role-backed `/scim/v2/Groups` list/filter/create/read/replace/patch plus explicit unsupported delete. SCIM group `displayName` maps to a GateKeeper role name, member add/remove changes org membership role/status, and affected sessions are revoked. Focused SCIM Users/Groups regressions passed, full API tests passed (`51 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale SCIM-gap wording scan was clean, and the public leakage scan was clean.
- After the SCIM list pagination/sorting slice, GateKeeper advertises SCIM sorting support and supports `sortBy`/`sortOrder` for common User and role-backed Group fields while preserving `startIndex`/`count` pagination. Focused SCIM list regression passed, paired SCIM Users/Groups/list regressions passed, full API tests passed (`52 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale SCIM wording scan was clean, and the public leakage scan was clean.
- After the SCIM password operations slice, GateKeeper advertises SCIM password-change support and accepts write-only `password` on `/scim/v2/Users` create, replace, and patch. Password updates use the normal GateKeeper password hash, are never returned in SCIM resources, and revoke the user's existing sessions. Focused SCIM password regression passed, paired SCIM regressions passed (`4 passed`), full API tests passed (`53 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale SCIM password-gap scan was clean, and the public leakage scan was clean.
- After the SCIM Bulk slice, GateKeeper advertises SCIM Bulk support and exposes `POST /scim/v2/Bulk` for common user and role-backed group operations, including `bulkId:` references in request bodies and follow-up paths. Focused SCIM Bulk regression passed, paired SCIM regressions passed (`5 passed`), full API tests passed (`54 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale SCIM bulk-gap scan was clean, and the public leakage scan was clean.
- After the SCIM Enterprise User mapping slice, GateKeeper stores SCIM `externalId` plus Enterprise User `employeeNumber`, `costCenter`, `organization`, `division`, `department`, and `manager` on the selected organization membership, advertises the Enterprise User schema, and returns those fields from SCIM user resources. Focused enterprise mapping regression passed, paired SCIM regressions passed (`6 passed`), full API tests passed (`55 passed`), Ruff passed, `pnpm build` passed, SQLite Alembic upgrade through `20260604_0018` passed, `git diff --check` passed, stale enterprise-gap scan was clean except intentional custom-policy wording, and the public leakage scan was clean.
- After the explicit account-linking slice, logged-in users can start a signed, current-session-bound OAuth provider linking flow through `/api/v1/auth/identities/{provider_id}/link/start`; callbacks reject missing/mismatched GateKeeper sessions, reject provider subjects already linked to another account, honor provider verified-email requirements, and attach/update the identity without replacing the current session. JS/Vue helpers and the `/account` linked-identity panel expose the flow. Focused account-linking regression passed, nearby linked-identity/social-provider regressions passed (`5 passed`), full API tests passed (`56 passed`), Ruff passed, `pnpm build` passed, `git diff --check` passed, stale account-linking gap scan was clean after internal wording updates, and the public leakage scan was clean.
- After the first-owner local product setup QA slice, Chrome extension automation against a throwaway SQLite install created `owner@example.com`, verified `/account` redirected cleanly from signup, route-walked `/account`, `/users`, `/invitations`, `/grants`, `/sessions`, `/tokens`, `/clients`, `/providers`, `/policy`, `/projects`, `/roles`, and `/audit` with no local app console errors, created a workspace/project API audience, registered a hosted web client, issued a service token with `api:read`, and validated that token active for the product audience through `/api/v1/tokens/validate`. `/account` advanced from `38% blocked` to `75% needs review`, with API backend, hosted auth, Vue/Nuxt SDK, API-key, and CLI/MCP integration surfaces ready. The token issuer UI was patched to expose `api:read` and `api:write`. `pnpm build`, `git diff --check`, API Ruff, SQLite Alembic upgrade through `20260604_0018`, and full API tests (`56 passed`) passed.
- After the June 4 production recon, the live Chrome profile opened `https://gatekeeper.b3n.in/account` without redirecting, rendered the setup console for an owner account, and showed concrete readiness warnings instead of the old unclear control-plane copy. In-app Browser narrow-viewport QA at 390x844 rendered public `/signup` and `/login` without horizontal overflow and with visible primary form controls. Authenticated mobile control-plane QA remains the main visual evidence gap.
- If deployment is requested and approved, wait for CI/image build, deploy the approved SHA, and verify `/health`, `/version`, OIDC discovery, JWKS, hosted auth pages, assets, and a real API/OAuth flow.

Definition of done for this goal:
- A self-hosted operator can read the public README/docs and understand what GateKeeper is, how to run it, how to integrate a product backend by API, how to protect APIs, how hosted auth works when needed, how Vue/Nuxt integration works, how API keys work, how CLI/MCP auth works, and what to do after first signup.
- A product backend can integrate without hosted UI and still get the full auth lifecycle.
- Hosted UI is polished and useful, but clearly optional.
- CLI and MCP auth share the same app-aware account/session/device story.
- The product UI no longer defaults to Sentinel/Knowhere/B3n mental models.
- The public setup path is generic OSS-first, with B3n integration docs isolated from the default path.
- Core provider flows and token-validation behavior are correct, tested, and documented.
- The repo has a clear list of remaining parity gaps if any cannot be completed in one session.
```
