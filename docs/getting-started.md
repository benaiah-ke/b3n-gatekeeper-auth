# Getting Started

This guide is the generic public path for a new GateKeeper operator. It starts
with an API-first product integration, then adds hosted UI, CLI, and MCP only
when those surfaces are needed.

Use `https://auth.example.com` as a placeholder for your GateKeeper issuer.

## 1. Run GateKeeper

Follow [selfhost.md](selfhost.md) until these endpoints return `200`:

```bash
curl -sf https://auth.example.com/health
curl -sf https://auth.example.com/version
curl -sf https://auth.example.com/.well-known/openid-configuration
curl -sf https://auth.example.com/oauth/jwks.json
```

## 2. Create The First Owner

Open `https://auth.example.com/signup` and create the first account. On a fresh
database, the first successful signup becomes owner because no active owner
exists yet. Later signups join the bootstrap organization as viewers until an
owner grants broader access.

If `/account` loads but shows `viewer`, signup worked. The account simply does
not have setup privileges.

## 3. Protect Your First API

Create a project or protected resource with an audience such as `example-api`.
Your product backend should then verify every bearer JWT with:

- issuer: `https://auth.example.com`
- JWKS: `https://auth.example.com/oauth/jwks.json`
- audience: `example-api`
- expiration and signature
- required scopes such as `api:read`
- account or organization claims required by the product

See [integrations/api-only.md](integrations/api-only.md).

If your product wants to own every auth route and screen, proxy GateKeeper from
your backend and normalize responses for your frontend. See
[integrations/product-backend-proxy.md](integrations/product-backend-proxy.md).

## 4. Add Product Login

The simplest API-owned login uses the direct auth endpoints:

```bash
curl -s https://auth.example.com/api/v1/auth/signup \
  -H 'content-type: application/json' \
  -d '{"email":"owner@example.com","password":"correct horse battery","display_name":"Owner"}'

curl -s https://auth.example.com/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@example.com","password":"correct horse battery"}'
```

The response includes `access_token`, `refresh_token`, `expires_in`, user data,
and organization memberships. Products that own their own UI can build signup,
signin, reset, sessions, and API-key screens directly on this API.

## 5. Add Hosted Auth When Needed

For a hosted UI web app, create an OAuth client with exact redirect URIs,
allowed origins, audiences, and scopes. Then use authorization-code + PKCE.

See [integrations/web-app.md](integrations/web-app.md) and
[integrations/vue-nuxt.md](integrations/vue-nuxt.md).

## 6. Add API Keys

API products should issue scoped API tokens or keys tied to the same account,
organization, project, audience, and audit model.

See [integrations/api-keys.md](integrations/api-keys.md).

## 7. Add CLI And MCP

CLIs should use device authorization or another user-bound login flow, store
refreshable credentials locally, switch organization context through GateKeeper,
and share the same session/device controls as browser apps. MCP HTTP servers
should publish protected resource metadata and require resource-bound tokens.

See [integrations/cli.md](integrations/cli.md) and
[integrations/mcp.md](integrations/mcp.md).

## Current Parity Notes

GateKeeper already has direct auth APIs, OAuth/OIDC, JWKS, refresh rotation,
authenticator TOTP with recovery codes, client and organization MFA policy,
trusted-device MFA reuse policy, admin step-up MFA policy, client credentials,
database-managed social provider setup through API and UI, device
authorization, sessions, connected-app grants, API tokens, MCP resources, and
SCIM-style user provisioning, SCIM v2 Users/Groups compatibility endpoints with
pagination, common sorting, write-only password operations, SCIM Bulk, and
membership-scoped Enterprise User fields, and an operator UI with account
lifecycle policy and audit retention/prune controls.

The product still needs more work before claiming full parity with mature auth
providers: custom account-linking policy, adaptive risk signals, custom SCIM
enterprise extension policy, richer hosted consent policy, and deeper
SDK/framework ergonomics. The baseline provider API can
already issue a fresh token for a selected organization through
`POST /api/v1/auth/session/switch-org`, and the CLI can store and switch local
organization context.
