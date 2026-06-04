# Payd Auth Comparison And GateKeeper Gap Map

This comparison uses the Payd Auth integrations across Payd products as a
working baseline for what a useful central auth provider must give a product
team. Payd Auth is not a perfect model, but it proves the first primitive:
products need API-first auth they can integrate directly into their own
backends, dashboards, API surfaces, CLIs, and MCP servers.

## Source Checkpoints Reviewed

The comparison is grounded in the current local Payd tree, especially:

- `payd-backend/payd-auth/internal/handlers/v2/session/session.go`: staged
  login, OTP request/verify, refresh, logout, and token verification.
- `payd-backend/payd-auth/internal/handlers/v1/api_keys/api_keys.go`: account
  API-key creation, lookup, and credential validation.
- `ui-migrate/payd-ui-v2/src/services/authService.ts` and
  `src/services/sessionService.ts`: product-owned login/signup/reset screens
  calling central auth APIs directly.
- `ui-migrate/payd-ui-v2/src/utils/requests/requests.ts`: product request
  clients injecting central auth tokens and refreshing on `401`.
- `payd-labs-stables-v1/app/services/auth.py`: API-product Basic Auth against
  Payd credentials, cached validation, and product-local integrator
  provisioning.
- `payd-labs-stables-v1/app/api/admin/auth.py`: admin backend proxy for
  login -> request OTP -> verify OTP -> refresh -> profile.
- `payd-labs-sentinel/sentinel-ui/src/stores/auth.ts` and
  `sentinel-cli/sentinel_cli/auth.py`: admin UI and CLI reuse of the staged
  central auth flow with local refreshable credentials.
- `payd-labs-sentinel/sentinel-cli/sentinel_cli/mcp_server.py` and
  `payd-labs-ui-server/knowhere-cli/knowhere_cli/mcp_server.py`: MCP tools
  consume the same CLI credential store.
- `payd-labs-ui-server/api/app/services/security.py`: product-local admin
  allowlists layered on central Payd Auth profile checks.

## Baseline Observations

| Surface | What Payd Auth Provides Today | GateKeeper Lesson |
| --- | --- | --- |
| Payd Auth core | REST/gRPC auth APIs for login, logout, token verification, OTP request/verify, refresh, user onboarding, password reset, accounts, organizations, roles, API keys, and KYC-related profile data. | GateKeeper needs complete public API docs for the full identity/session/account/API-key lifecycle, not only OIDC and hosted UI docs. |
| Payd Web app | Product UI calls auth APIs directly for login, signup, activation, reset, OTP, refresh, logout, user profile, and API keys. Tokens are injected into API requests and refreshed by product-side logic. | A product should be able to own all auth screens and still use GateKeeper centrally. Vue/Nuxt helpers should make this ergonomic. |
| Stables API product | Integrator API auth uses Payd API credentials validated against Payd Auth, then auto-provisions product-local integrator records. Admin login proxies Payd Auth login -> OTP -> verify -> refresh. Hosted product profile tokens are product-specific. | API products need account-bound API keys/credentials, validation APIs, product-local provisioning guidance, admin proxy examples, and callback secret rotation. |
| Sentinel | Product backend proxies Payd Auth admin login, OTP, verify, refresh, and profile. CLI performs one-time OTP login and stores refreshable credentials. MCP server reuses CLI credentials. | CLI and MCP auth should be first-class GateKeeper surfaces with shared device/session visibility and revocation. Product backends may proxy central auth rather than redirecting to hosted UI. |
| Knowhere | Product backend proxies Payd Auth, validates admin JWT claims, applies local allowlists, and exposes CLI login using the same central account flow. | GateKeeper should support product-local policy layered on central identity: issuer/audience/scope verification, admin claims, allowlists, and app-specific permissions. |

## Strengths To Preserve

Payd Auth succeeds because it is used as infrastructure, not just a login page:

- Products can call central auth APIs directly.
- Login can be staged: password/session first, OTP verification second, access
  and refresh tokens after verification.
- Refresh tokens let products avoid unnecessary OTP prompts while keeping short
  access-token lifetimes.
- Account, organization, role, and admin claims travel with tokens.
- API keys are tied to accounts and can be validated by API products.
- Product backends can proxy central auth to preserve product-owned UX.
- CLIs and MCP servers can reuse the same central account model.
- Product-local records can be created after central identity is verified.

This is why GateKeeper now has a dedicated
[product backend proxy guide](../../integrations/product-backend-proxy.md) in
addition to hosted OAuth docs.

## Weaknesses To Improve

GateKeeper should not copy Payd Auth's rough edges:

- Documentation is too scattered and internal. A new product has to infer flows
  from code, protobufs, and product-specific implementations.
- Header names, token names, and response shapes vary across products.
- Some products decode JWTs locally for claims and then compensate with profile
  fetches or allowlists. GateKeeper integrations should provide clear
  cryptographic verification helpers.
- API keys, service keys, callback secrets, product tokens, and hosted tokens
  are not presented as one coherent provider surface.
- Product backends duplicate login/OTP/refresh proxy code.
- CLI and MCP credential stores are product-specific instead of a shared
  provider pattern.
- Self-host and OSS setup are not first-class concerns.

## GateKeeper Delta

GateKeeper already has promising provider primitives:

- OIDC discovery and JWKS.
- Authorization-code + PKCE.
- Client credentials.
- Device authorization.
- Refresh rotation, revocation, and introspection endpoints.
- Users, organizations, workspaces, projects, memberships, roles, permissions,
  auth clients, API tokens, MCP resources, sessions, and audit events.
- Hosted login/signup/reset/device pages.
- JS, Vue, Python, and CLI packages.

The product gap is that these pieces are not yet presented as a complete
API-first auth product:

- API-only product integration now has a concrete runbook and install-owner
  social provider setup through API and control-plane UI, but full API-product
  parity still depends on custom account-linking policy, SCIM-style
  provisioning policy, richer hosted MFA enrollment/remediation, and more
  framework examples.
- Signup, signin, reset, account profile/password management, self-service
  personal API keys, operator-managed service/project credentials, API auth,
  product API-token validation, 2FA, sessions, devices, invitations, and admin
  operations are now partially connected in one lifecycle; remaining work is
  policy depth, product-local API provisioning examples, custom account-linking
  policy, retention/deletion policy, and product-ready SDK surfaces.
- Hosted UI feels like the primary product, while API products need to be the
  primary primitive.
- CLI and MCP flows now tie into the core session revocation and org-switching
  story, trusted-device metadata, admin step-up MFA, and policy controls, but
  still need richer device metadata and adaptive risk signals.
- Remaining tenant-specific assumptions should stay isolated to internal
  migration docs, explicit design context, or a deliberate package namespace
  strategy.
- SDKs now cover the basic hosted browser OAuth loop and FastAPI verification,
  but Nuxt, guarded routes, UI components, richer CLI/MCP helpers, and server
  runtime verification ergonomics still need parity work.

## Target Primitive

The first base primitive GateKeeper must satisfy is:

> A self-hosted product backend can integrate GateKeeper purely by API, without
> hosted UI, and receive the full auth lifecycle: signup, signin, reset, 2FA,
> social auth as configured, account management, admin, roles, API keys, API
> auth, sessions, devices, policy, and audit.

Hosted auth, frontend SDKs, CLI auth, and MCP auth should then reuse the same
provider model, token rules, account graph, device/session management, and audit
surface.

## Better-Than-Clerk Direction

GateKeeper can beat a hosted-first provider by combining:

- OSS self-hosting with generic public defaults.
- Complete direct auth APIs for products that own their own UX.
- Standard OAuth/OIDC/JWKS for web apps.
- Account-bound API keys and service credentials for API products.
- Central session and device management across web, API, CLI, and MCP.
- First-class CLI/device and MCP protected-resource auth.
- Provider SDKs for Vue, Nuxt, FastAPI, JS server runtimes, CLI, and MCP.
- A compact operator console for apps, APIs, users, roles, keys, sessions,
  devices, policy, and audit.

The Clerk-like hosted UI should be excellent, but it should be optional. The
core product is the provider API and the central account/security graph.
