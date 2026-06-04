# GateKeeper

GateKeeper is an API-first, self-hostable auth provider for product backends,
web apps, API products, CLIs, and MCP servers. It gives teams a central identity,
session, role, token, and audit system that can be integrated directly through
APIs, with hosted auth UI and SDKs available when a product needs them.

## What It Provides

- Direct auth APIs for signup, signin, reset, verification, sessions, account
  management, organization membership, roles, API keys, admin actions, and audit
  trails.
- OAuth 2.1 / OIDC provider endpoints with authorization-code + PKCE, client
  credentials, device authorization, refresh rotation, revocation,
  introspection, JWKS, and discovery.
- OIDC/social provider setup by API and control-plane UI, with read-only env
  bootstrap providers and encrypted database-managed client secrets for
  self-hosted installs.
- API-product auth for bearer JWTs, personal access tokens, service keys,
  project keys, admin tokens, API-key validation, scopes, and audiences tied to
  the same account and project model.
- Authenticator MFA with recovery codes, org/client MFA policy,
  trusted-device MFA reuse policy, admin step-up MFA policy, and session/device
  management.
- Hosted auth pages for sign in, sign up, verification, reset, device login,
  org selection, account/session management, client management, token
  management, and audit logs.
- Multi-tenant organizations, workspaces, projects, roles, permissions, and
  audit events with explicit organization retention and prune controls.
- MCP authorization support using protected-resource metadata, resource-bound
  access tokens, scopes, and discovery-compatible challenges.
- CLI and SDK packages for product backends, Vue/Nuxt apps, API clients, and MCP
  servers.

## Repository Layout

```text
api/            FastAPI auth server, migrations, tests
ui/             Vue 3 hosted auth/admin UI
cli/            GateKeeper CLI using OAuth device login
packages/js/    Framework-agnostic browser/server helpers
packages/vue/   Vue provider and composables
sdk/python/     FastAPI verification helpers
deploy/         Docker Compose, Caddy, self-host env templates
docs/           Architecture, self-host, MCP, and integration guides
```

## Product Direction

GateKeeper is intended to be usable without hosted UI: a product backend should
be able to call GateKeeper's APIs for signup, signin, reset, 2FA, sessions,
roles, account management, API keys, and API auth, then expose its own product
experience. Hosted UI, Vue/Nuxt SDKs, CLI auth, and MCP auth build on those same
provider primitives.

- [API-first provider surface](docs/product/api-first-auth-provider.md)
- [Getting started](docs/getting-started.md)
- [Concepts](docs/concepts.md)
- [API-only integration](docs/integrations/api-only.md)
- [Product backend proxy pattern](docs/integrations/product-backend-proxy.md)
- [Backend verification](docs/integrations/backend.md)
- [Hosted web app integration](docs/integrations/web-app.md)
- [Vue and Nuxt integration](docs/integrations/vue-nuxt.md)
- [API keys and API auth](docs/integrations/api-keys.md)
- [CLI auth](docs/integrations/cli.md)
- [MCP integration](docs/integrations/mcp.md)
- [API surface map](docs/reference/api-surface.md)
- [Architecture](docs/architecture.md)
- [Self-hosting](docs/selfhost.md)
- [Security policy](SECURITY.md)
- [MCP authorization](docs/mcp-auth.md)

## Local Development

```bash
cp .env.example .env
docker compose -f docker-compose.yml up -d postgres
cd api && uv run alembic upgrade head && uv run uvicorn app.main:app --reload
cd ui && pnpm install && pnpm dev
```

Default local URLs:

- API: `http://localhost:8000`
- UI: `http://localhost:5173`
- OpenAPI: `http://localhost:8000/docs`

The Vite dev server proxies `/.well-known`, `/api`, `/oauth`, `/health`, and
`/version` to the local API so the hosted UI can use same-origin requests during
development.

## First Setup

After the API and UI are running:

1. Open `/signup` and create the first account. If no active owner exists in
   the bootstrap org, this successful signup becomes owner. The
   `BOOTSTRAP_ADMIN_EMAIL` account is also granted owner when it signs up.
2. Open `/account` and follow the setup console. A viewer account can inspect
   state, but an owner is required to create clients, projects, roles, and
   tokens.
3. Register OAuth clients for your web app, backend/API resource, CLI/device
   login, MCP resources, and local development callback URLs.
4. Create scoped API tokens or keys for services, projects, API products, CLIs,
   or MCP servers.
5. Verify discovery and signing keys before cutover:

```bash
curl -sf http://localhost:8000/.well-known/openid-configuration
curl -sf http://localhost:8000/oauth/jwks.json
```

If `/account` shows a viewer state on a self-hosted install, do not assume the
signup failed. It means the current account can read the bootstrap org but does
not have setup privileges; use an owner account or the configured bootstrap
admin account.

## Verification

```bash
make test-api
make build-ui
GATEKEEPER_ENV_FILE=.env.example.selfhost docker compose -f deploy/docker-compose.selfhost.yml config -q
GATEKEEPER_ENV_FILE=.env.example.selfhost docker compose -f deploy/docker-compose.existing-proxy.yml config -q
```

No production DNS or application cutover is performed by this repository.
Product-specific migration plans should stay separate from the generic
self-host setup path.
