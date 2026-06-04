# Self-Hosting GateKeeper

GateKeeper can run as a standalone auth provider for a single product, an
internal platform, or a collection of products that share one account system.
The default public setup path should not require private infrastructure,
tenant-specific hostnames, or existing product migrations.

Use placeholders such as `auth.example.com`, `admin@example.com`, and
`Example Org` while preparing your own environment.

## Host Shape

- Linux host or VM with Docker Engine and the Compose plugin.
- Ports 80 and 443 open if GateKeeper terminates public TLS on the host.
- A persistent Postgres volume or an external Postgres database.
- A persistent API data volume for signing keys when `JWT_KEY_DIR` is used.
- A reverse proxy such as Caddy, Traefik, Nginx, or an existing platform proxy.

## Bootstrap

Create an application directory and Docker network on the host:

```bash
sudo mkdir -p /opt/gatekeeper
sudo docker network create proxy
sudo chown -R "$USER:$USER" /opt/gatekeeper
```

Copy these files to the host and adapt them for your domain:

- `deploy/docker-compose.selfhost.yml` as `docker-compose.yml`
- `deploy/.env.example.selfhost` as `.env`
- `deploy/Caddyfile.bootstrap` as `Caddyfile`, or your own reverse-proxy config

Edit `.env` before first boot. Do not print secrets in logs, chat, or support
threads.

At minimum, replace:

- `ISSUER_URL` and public UI/API URLs with your auth domain.
- `PUBLIC_BASE_URL` or equivalent UI runtime URL settings.
- `GATEKEEPER_API_IMAGE`, `GATEKEEPER_UI_IMAGE`, and `GATEKEEPER_IMAGE_TAG`
  for the images you publish or build.
- `SECRET_KEY`.
- `POSTGRES_PASSWORD` or the external `DATABASE_URL`.
- `BOOTSTRAP_ADMIN_EMAIL`.
- SMTP settings before relying on email verification, reset, or invitations.

By default, `JWT_KEY_DIR=/data/keys` makes the API generate and persist an RSA
signing keypair in the `gatekeeper-api-data` Docker volume. Operators who manage
keys outside Docker can instead set `JWT_PRIVATE_KEY_PEM` and
`JWT_PUBLIC_KEY_PEM`.

## Social Providers

Social sign-in can be configured from `/providers` or the control-plane API
after the install owner signs in. This is the normal self-host path because
secrets are encrypted in GateKeeper's database and admin reads only return
`client_secret_configured`:

```bash
curl -s -X POST "https://auth.example.com/api/v1/auth/oauth/providers/admin" \
  -H "authorization: Bearer <install-owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "provider_id":"example",
    "name":"Example Login",
    "client_id":"...",
    "client_secret":"...",
    "authorization_url":"https://login.example.com/oauth/authorize",
    "token_url":"https://login.example.com/oauth/token",
    "userinfo_url":"https://login.example.com/userinfo",
    "scopes":["openid","email","profile"]
  }'
```

Environment providers are still supported as read-only bootstrap config for
immutable deployments. The legacy Google variables still work:

```env
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://auth.example.com/api/v1/auth/oauth/google/callback
```

For other bootstrap providers, set `OAUTH_PROVIDERS_JSON` to a JSON array or
object. GateKeeper uses the authorization URL, token URL, and userinfo URL, then
links the external identity to a verified email address:

```env
OAUTH_PROVIDERS_JSON='[
  {
    "id": "example",
    "name": "Example Login",
    "client_id": "...",
    "client_secret": "...",
    "authorization_url": "https://login.example.com/oauth/authorize",
    "token_url": "https://login.example.com/oauth/token",
    "userinfo_url": "https://login.example.com/userinfo",
    "redirect_uri": "https://auth.example.com/api/v1/auth/oauth/example/callback",
    "scopes": ["openid", "email", "profile"]
  }
]'
```

Use `GET /api/v1/auth/oauth/providers` to confirm which providers are visible
to hosted and product-owned auth screens. Use
`GET /api/v1/auth/oauth/providers/admin` as an install owner to see both
database-managed providers and read-only env-managed providers without
returning secrets. Public setup should not include provider secrets in docs,
screenshots, issue reports, or support chats.

For local validation from a checkout:

```bash
GATEKEEPER_ENV_FILE=.env.example.selfhost \
  docker compose -f deploy/docker-compose.selfhost.yml config -q
```

## Start

```bash
docker compose --env-file .env pull
docker compose --env-file .env up -d
curl -sf https://auth.example.com/health
curl -sf https://auth.example.com/version
```

If you build images locally instead of pulling from a registry, tag them to
match `GATEKEEPER_API_IMAGE:GATEKEEPER_IMAGE_TAG` and
`GATEKEEPER_UI_IMAGE:GATEKEEPER_IMAGE_TAG` before starting Compose.

Verify public provider metadata before connecting applications:

```bash
curl -sf https://auth.example.com/.well-known/openid-configuration
curl -sf https://auth.example.com/oauth/jwks.json
```

## First Setup

After `/version` returns 200:

1. Open `https://auth.example.com/signup` and create the first account. On a
   fresh install, the first successful signup becomes owner because no active
   owner exists yet.
2. Sign in as the configured `BOOTSTRAP_ADMIN_EMAIL` as well if you want that
   address to be an owner. Later non-admin signups join the bootstrap org as
   viewers until an owner grants broader access.
3. Open `https://auth.example.com/account` and confirm the owner state, issuer,
   JWKS URL, SMTP mode, and setup checklist.
4. Create your first protected API resource with an audience such as
   `example-api`.
5. Create your first web app client with exact redirect URIs and allowed
   origins. Store confidential client secrets outside chat, logs, and tests.
6. Create scoped API keys or service tokens only for the audiences each caller
   needs. Token values are displayed once.
7. Add CLI/device and MCP resources only when those product surfaces exist.

If `/account` redirects to login, check whether `GATEKEEPER_URL`, `UI_URL`,
`CORS_ORIGINS`, `COOKIE_SECURE`, and `COOKIE_DOMAIN` match the public origin
that completed signup. Hosted browser sessions use HttpOnly access and refresh
cookies, so a mismatched domain or scheme can make a valid signup look logged
out. If `/account` loads but shows `viewer`, signup succeeded but the account
cannot perform setup actions. Use an owner account or the configured bootstrap
admin account; do not work around this by sharing tokens.

## Setup Checklist

- `/account` shows an owner role for the bootstrap org.
- `/clients` contains enabled clients for the web, backend, CLI, and MCP
  surfaces you actually need.
- `/projects` or protected resources contain audiences such as `example-api`.
- `/tokens` contains only scoped, time-bounded credentials needed for the next
  integration step.
- `/audit` shows client, token, user, and session events, and the organization
  retention policy is set before pruning old events.
- SMTP is configured before relying on email verification, reset, invitation, or
  email-code login flows. Authenticator TOTP does not require SMTP.
- JWKS and OIDC discovery are reachable from every product backend that will
  verify GateKeeper tokens.

## API Product Baseline

For API-first products, GateKeeper should be treated as the central identity and
authorization API, not only as a hosted login page.

```env
GATEKEEPER_ISSUER=https://auth.example.com
GATEKEEPER_JWKS_URL=https://auth.example.com/oauth/jwks.json
GATEKEEPER_AUDIENCE=example-api
GATEKEEPER_REQUIRED_SCOPES=api:read
```

Product backends should verify issuer, audience, expiration, signing key,
scopes, and account or organization claims before serving requests. API
extensions and machine callers should use scoped API keys, service tokens, or
client-credentials tokens tied to the same account and audit model.

## Backups

Back up before upgrades:

- The deployment `.env`.
- Reverse-proxy configuration.
- GateKeeper Postgres volume or logical dump.
- GateKeeper API data volume containing signing keys when `JWT_KEY_DIR` is used.
- Reverse-proxy data and config volumes if the proxy terminates TLS.

Prove restore on a non-production host before relying on a backup strategy.

## Product-Specific Migrations

Product-specific migrations can live in separate docs, but they should not be
the default self-host setup path. Keep those notes clearly marked as internal or
deployment-specific so a new operator can follow the generic quickstart without
private infrastructure context.
