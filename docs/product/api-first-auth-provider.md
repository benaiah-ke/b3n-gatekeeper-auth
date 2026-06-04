# API-First Auth Provider Surface

GateKeeper's first primitive is not a hosted login page. It is a central auth
API that product backends can integrate directly for identity, sessions, roles,
API auth, account management, and audit. Hosted UI, frontend SDKs, CLI auth, and
MCP auth are surfaces on top of the same provider contract.

## Product Thesis

A self-hosted team should be able to run GateKeeper once and use one account
across:

- Web and mobile products that own their own frontend and backend experience.
- API products where customers authenticate with API keys, service tokens, or
  machine credentials tied to the same account model.
- Admin dashboards and control planes.
- CLIs that need interactive login, local credential storage, refresh, and
  logout.
- MCP servers that need protected-resource metadata and resource-bound tokens.
- Hosted auth pages only when the product wants GateKeeper to own the login,
  signup, reset, device, or account-management UI.

## Required API Primitives

### Identity And Account API

GateKeeper should expose clear APIs and SDK helpers for:

- Signup and account creation.
- Signin with password, social identity, passkey, or passwordless factors as the
  product matures.
- Email and phone verification.
- Password reset and password change.
- Authenticator TOTP enrollment, challenge, recovery codes, and enforcement
  policy.
- Profile, account, organization, workspace, and project membership.
- Roles, permissions, scopes, and organization selection.
- Admin user management, invitations, suspension, deletion, and audit.

### Session And Device API

Sessions are product infrastructure, not a UI afterthought. GateKeeper should
support:

- Staged login sessions for OTP/2FA flows.
- Access and refresh tokens with rotation and replay handling.
- Logout, session revocation, refresh-family revocation, and global signout.
- Device inventory, current-device metadata, and remote device/session removal.
- Session rules such as TTL, idle timeout, MFA requirement, trusted devices, and
  product-specific risk policy.
- End-to-end session events in audit logs.

### API Auth And API Keys

API products need first-class auth, not one-off service keys per app.

GateKeeper should support:

- Personal access tokens, service tokens, project tokens, admin tokens, and
  client-credentials tokens.
- API keys scoped to account, organization, project, audience, environment, and
  permissions.
- Key creation, reveal-once, validation, rotation, revocation, last-used
  tracking, and audit.
- API-key exchange or validation APIs that let a product backend tie product
  records to the same GateKeeper account.
- Callback signing secrets and rotation for products that send webhooks.
- Introspection and JWKS verification guidance for every token class.

### Product Backend Integration

The expected default integration is:

1. Product backend creates or identifies the application/resource in GateKeeper.
2. Product frontend or backend calls GateKeeper APIs for signup, signin, reset,
   2FA, account, session, and API-key flows.
3. Product backend validates GateKeeper JWTs by issuer, audience, expiration,
   JWKS key, scopes, and account or organization claims.
4. Product backend calls GateKeeper admin APIs for user, role, session, API-key,
   and audit operations when allowed.
5. Product-specific records are provisioned or linked after GateKeeper identity
   and account claims are verified.

Hosted UI is optional in this model. A product can own all screens and still use
GateKeeper as the central auth authority.

### Hosted UI And Frontend SDKs

Hosted UI should exist for teams that want GateKeeper-owned screens:

- Login, signup, reset, verification, device login, 2FA, account, API keys,
  sessions/devices, and organization selection.
- OAuth/OIDC authorization-code + PKCE redirect flows.
- Safe authorize -> login/signup -> authorize return -> callback behavior.
- Client identity, consent review, remembered app grants, and user-controlled
  connected-app revocation where appropriate.
- Admin connected-app grant review and revocation for organization operators.
- Vue and Nuxt SDKs that provide auth state, login redirect helpers, callback
  handling, token refresh, guarded routes, and account/session components.

Hosted UI should not be the only path to a complete integration.

### CLI And MCP

GateKeeper should make non-browser surfaces first-class:

- CLI device login or interactive OTP login.
- Local credential storage, refresh, logout, and account profile switching.
- Environment-token override for automation.
- MCP protected-resource metadata.
- Resource-bound MCP tokens with scopes and audience validation.
- Shared session/device visibility so operators can see and revoke CLI and MCP
  sessions from the same account surface.

## Better Than Hosted-First Providers

GateKeeper should preserve what works in central internal auth platforms while
improving the parts that are hard to operate or reuse:

- API-first documentation instead of scattered internal knowledge.
- Standard OIDC/JWKS verification plus product SDKs, not unsafe decode-only
  patterns.
- API-product auth and API keys as first-class provider primitives.
- Consistent token names, header conventions, response shapes, and refresh
  behavior.
- Central session and device management across hosted UI, API integrations, CLI,
  and MCP.
- Self-hosted OSS defaults that do not expose private operator infrastructure.
- A clean operator console that helps a new team create an app, protect an API,
  create keys, verify sessions, and audit usage without knowing a private
  operator context.

## UI Direction

The control plane should feel dark, compact, precise, and operational. It should
open on the actual work surface, not a marketing page.

Expected first-run surfaces:

- Issuer, JWKS URL, SMTP status, and owner state.
- Copyable API backend integration values.
- Copyable hosted OAuth, Vue/Nuxt, API-key, CLI, and MCP integration blocks
  derived from the current clients, audiences, issuer, and resource records.
- Create first web app.
- Protect first API resource.
- Create first API key or service token.
- Configure 2FA/session policy.
- Add CLI/device auth only when needed.
- Add MCP resource only when needed.
- View and manage users, roles, sessions/devices, API keys, and audit events.
- View and revoke connected app grants.

Avoid tenant-specific defaults, product-migration templates as the public path,
generic large-card dashboards, and copy that explains private infrastructure
instead of the auth-provider model.

## Current GateKeeper Gaps To Close

- Public API-only docs now include a concrete product-backend runbook for
  operator setup, direct signup/signin/reset, self-service profile/password
  management, account/session APIs, self-service personal API keys,
  operator-managed service/project/admin/machine token lifecycle, account
  export/deactivation, authenticator TOTP, client/org-level MFA policy,
  trusted-device MFA reuse policy, admin step-up MFA policy, org/client
  idle-timeout policy, client credentials, introspection, backend verification,
  API-token validation with scope/audience checks, invitations, and MFA
  recovery codes.
  They now include install-owner social provider setup by API and control-plane
  UI, SCIM-style user provisioning, and SCIM v2 Users/Groups compatibility
  endpoints with pagination, common sorting, write-only password operations, and
  SCIM Bulk, plus membership-scoped Enterprise User fields. They still need
  expansion once custom SCIM enterprise extension policy and richer MFA
  enrollment remediation exist.
- The `/account` control plane now has a first-pass API-first setup workbench
  with live copy blocks for API backend, hosted auth, Vue/Nuxt, API keys,
  CLI/MCP surfaces, self-service profile/password controls, and authenticator
  2FA, plus setup completion, production-readiness health signals, and
  operator shortcuts into users, invitations, sessions, policy, providers, and
  audit; `/policy` now exposes org MFA, trusted-device MFA reuse, admin step-up
  MFA, idle-timeout controls, user hard-delete policy, and a recommended
  baseline checklist/action that applies org MFA, trusted-device reuse, safe
  idle timeout, and MFA-aware admin step-up remediation. `/users` exposes
  policy-gated hard-delete preview and email-confirmed execution. `/audit` now
  has first-pass event category summaries and quick filters over the existing
  audit API plus explicit organization audit retention/prune controls. It still
  needs broader desktop/mobile visual QA across richer seeded data.
- User administration now covers SCIM-style user provisioning, SCIM v2
  Users/Groups compatibility, listing users, profile/verification state,
  suspension, role/status assignment, last-owner protection, per-user session
  revocation, MFA state, admin TOTP reset, and invitations. Self-service
  account export, deactivation, linked identity listing/unlinking, and explicit
  session-bound provider linking now have last-owner/sign-in-method protection,
  revocation cleanup where applicable, and UI/API/SDK coverage; policy-gated
  admin hard delete now has API/UI/JS helper coverage; configured OIDC/social
  provider login now has generic provider APIs, install-owner provider
  management UI/API with encrypted secret storage, hosted login/signup buttons,
  signed callback state, verified email linking policy, and JS/Vue helper
  coverage. Remaining admin gaps are SCIM custom enterprise extension policy
  and custom account-linking policy.
- JS/Vue SDKs now cover the core hosted OAuth browser loop, token storage,
  direct product-owned signup/signin/invitation/email-code/password-reset
  helpers, refresh, `/me`, password change, sessions, session device
  labeling/trust controls, social provider discovery/start/admin-management
  helpers, connected-app grants, API-token validation and
  list/create/rotate/revoke helpers, server-runtime JWKS verification helpers,
  and Nuxt runtime-config wiring. The Vue package now includes account,
  session/device, connected-app grant, admin grant-review, and API-token
  view-model composables for product-owned pages plus a Nuxt-friendly
  hydration/route-guard helper and optional drop-in components for account,
  session/device, API-key, and connected-app surfaces.
- API-key and token management now separates account-owned personal keys from
  operator-managed service/project/admin/machine credentials, and exposes
  product API-token validation with account/org/project metadata, required
  scope checks, audience checks, last-used tracking, a Python FastAPI API-key
  dependency, product-local provisioning examples for API extensions and
  machine callers, and admin user provisioning helpers.
- Workspace, project/audience, and role setup APIs now share the same
  current-organization isolation as clients, including cross-org list/create
  denial and project-workspace org consistency checks.
- Client/app management now scopes list, create, update, secret rotation, and
  delete operations to the operator's current organization, stores hosted
  consent metadata for app logo/description/homepage/privacy/terms plus
  publisher/verified trust metadata for hosted consent, and org-membership
  OAuth/device flows resolve org-bound clients to the client organization.
- User admin, invitations, MCP resource setup, and audit reads now share the
  same current-organization visibility boundary, with cross-org list and by-id
  mutations denied for org-bound admins.
- CLI and MCP flows now share app-aware session inventory, trusted-device
  metadata, trusted-device MFA reuse policy, client/org-level MFA enforcement,
  admin step-up MFA policy, org/client idle-timeout enforcement, and the core
  session revocation surface. The provider API now supports org-bound session
  switching, and the Python SDK now includes FastAPI helpers for MCP
  protected-resource metadata and `WWW-Authenticate` challenges. The CLI now
  supports install readiness checks with `gatekeeper doctor`, copy-once
  API-token rotation, and API-token validation with audience, scope, org, and
  project checks. Adaptive risk signals and richer policy controls still need
  work.
- Hosted browser sessions now use HttpOnly access and refresh cookies, and the
  Vue router preserves safe login/signup redirects back to OAuth authorize
  requests instead of dropping already-authenticated users on `/account`.
  OAuth requests that require MFA now redirect password-only browser sessions
  through hosted `step_up=mfa` login before returning to the original
  authorization request.
- Public self-host docs and defaults should remain generic; tenant-specific
  rollout notes should stay in an internal path.
- Some provider-correctness seams need review before claiming parity: richer
  consent policy beyond operator-managed app trust badges, cross-org role claim
  strategy beyond client/app isolation, adaptive risk/device rules, and
  organization membership policy.
