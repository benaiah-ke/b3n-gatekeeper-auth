# GateKeeper

GateKeeper is B3n's self-hostable, open-source auth platform for control planes,
project apps, CLIs, service tokens, and MCP servers. It replaces hosted auth
vendors with a FastAPI, Vue 3, Tailwind, and Postgres stack that B3n can run on
its own infrastructure and the community can deploy for their own orgs.

## What It Provides

- Hosted auth pages for sign in, sign up, verification, reset, device login,
  org selection, account/session management, client management, token
  management, and audit logs.
- OAuth 2.1 / OIDC provider endpoints with authorization-code + PKCE, client
  credentials, device authorization, refresh rotation, revocation,
  introspection, JWKS, and discovery.
- API auth for personal access tokens, service keys, project keys, admin tokens,
  and bearer JWTs.
- Multi-tenant organizations, workspaces, projects, roles, permissions, and
  audit events.
- MCP authorization support using protected-resource metadata, resource-bound
  access tokens, scopes, and discovery-compatible challenges.
- CLI and SDK packages for B3n tools such as Sentinel, Knowhere, and future
  control-plane services.

## Repository Layout

```text
api/            FastAPI auth server, migrations, tests
ui/             Vue 3 hosted auth/admin UI
cli/            GateKeeper CLI using OAuth device login
packages/js/    Framework-agnostic browser/server helpers
packages/vue/   Vue provider and embeddable components
sdk/python/     FastAPI verification helpers
deploy/         Docker Compose, Caddy, self-host env templates
docs/           Architecture, self-host, MCP, and integration guides
```

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

## First Setup

After the API and UI are running:

1. Open `/signup` and create the first account. If no active owner exists in
   the bootstrap org, this successful signup becomes owner. The
   `BOOTSTRAP_ADMIN_EMAIL` account is also granted owner when it signs up.
2. Open `/account` and follow the setup console. A viewer account can inspect
   state, but an owner is required to create clients, projects, roles, and
   tokens.
3. Register OAuth clients for Sentinel, Knowhere, CLI/device login, MCP
   resources, and any local development callback URLs.
4. Create scoped API tokens for services, projects, CLIs, or MCP servers.
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
B3N_ENV_FILE=.env.example.selfhost docker compose -f deploy/docker-compose.selfhost.yml config -q
B3N_ENV_FILE=.env.example.selfhost docker compose -f deploy/docker-compose.existing-proxy.yml config -q
```

No production DNS, B3n Sentinel, or B3n Knowhere cutover is performed by this
repository. See [docs/integrating-sentinel-knowhere.md](docs/integrating-sentinel-knowhere.md)
for the staged migration plan.
