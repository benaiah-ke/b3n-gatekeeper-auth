# Self-Hosting GateKeeper

Default production domain: `gatekeeper.b3n.in`.

## Host Shape

- Ubuntu droplet with Docker Engine and Compose plugin.
- Root SSH only for bootstrap; a scoped `deploy` user performs day-to-day
  upgrades.
- Ports 80 and 443 open.
- Cloudflare DNS with staged cutovers.
- Persistent Docker volumes for Postgres and Caddy.

## Bootstrap

```bash
sudo mkdir -p /apps/gatekeeper
sudo docker network create proxy
sudo chown -R deploy:deploy /apps/gatekeeper
```

Copy these files to `/apps/gatekeeper`:

- `deploy/docker-compose.selfhost.yml` as `docker-compose.yml`
- `deploy/.env.example.selfhost` as `.env`
- `deploy/Caddyfile.bootstrap` as `Caddyfile`

Edit `.env` on the server. Do not print secrets in logs or chat.

`SECRET_KEY` and `POSTGRES_PASSWORD` must be replaced before first boot. By
default, `JWT_KEY_DIR=/data/keys` makes the API generate and persist an RSA
signing keypair in the `gatekeeper-api-data` Docker volume. Operators who manage
keys outside Docker can instead set `JWT_PRIVATE_KEY_PEM` and
`JWT_PUBLIC_KEY_PEM`.

For local validation from a checkout:

```bash
B3N_ENV_FILE=.env.example.selfhost \
  docker compose -f deploy/docker-compose.selfhost.yml config -q
```

## Existing Caddy Proxy

On B3n hosts that already run a shared `caddy-proxy` on the external Docker
network named `proxy`, do not start GateKeeper's `caddy-proxy` service. Copy
`deploy/docker-compose.existing-proxy.yml` as `/apps/gatekeeper/docker-compose.yml`
and append `deploy/Caddyfile.existing-proxy.gatekeeper` to the shared Caddyfile.

If `gatekeeper.b3n.in` is not pointed at the host yet, append
`deploy/Caddyfile.existing-proxy.http-bootstrap` instead for HTTP-only
Host-header smoke checks. Replace it with
`deploy/Caddyfile.existing-proxy.gatekeeper` after DNS resolves to the host so
Caddy can issue the production TLS certificate.

Validate both pieces before applying:

```bash
B3N_ENV_FILE=.env.example.selfhost \
  docker compose -f deploy/docker-compose.existing-proxy.yml config -q

docker exec caddy-proxy caddy validate --config /etc/caddy/Caddyfile
docker exec caddy-proxy caddy reload --config /etc/caddy/Caddyfile
```

## Start

```bash
docker compose --env-file .env pull
docker compose --env-file .env up -d
curl -sf https://gatekeeper.b3n.in/health
curl -sf https://gatekeeper.b3n.in/version
```

## First Setup

After `/version` returns 200:

1. Open `https://gatekeeper.b3n.in/signup` and create the first account. On a
   fresh install, the first successful signup becomes owner because no active
   owner exists yet.
2. Sign in as the configured `BOOTSTRAP_ADMIN_EMAIL` as well if you want that
   address to be an owner. Later non-admin signups join the bootstrap org as
   viewers until an owner grants broader access.
3. Open `https://gatekeeper.b3n.in/account` and use the setup console to confirm
   the owner state, issuer, JWKS URL, SMTP mode, and next actions.
4. Create clients for Sentinel, Knowhere, the GateKeeper CLI, and any local
   development callback URLs. Confidential client secrets are displayed once;
   store them outside chat, logs, and tests.
5. Create scoped service, project, CLI, or MCP tokens only for the audiences each
   caller needs. Token values are displayed once.
6. Verify issuer metadata before pointing protected services at GateKeeper:

```bash
curl -sf https://gatekeeper.b3n.in/.well-known/openid-configuration
curl -sf https://gatekeeper.b3n.in/oauth/jwks.json
```

## Setup Checklist

- `/account` shows an owner role for the bootstrap org.
- `/clients` contains enabled clients for Sentinel, Knowhere, and CLI/device
  login.
- `/projects` contains audiences such as `sentinel-api` and `knowhere-api`.
- `/tokens` contains only scoped, time-bounded credentials needed for the next
  integration step.
- `/audit` shows client and token creation events.
- SMTP is configured before relying on email verification, reset, or invitation
  flows. If SMTP is not configured, keep the missing delivery surface explicit in
  the operator handoff.

If `/account` redirects to login, check whether the browser has the same session
that completed signup. If `/account` loads but shows `viewer`, signup succeeded
but the account cannot perform setup actions. Use an owner account or the
configured bootstrap admin account; do not work around this by sharing tokens.

## Sentinel And Knowhere Env Baseline

Use dual-provider or preview-only settings until the protected apps verify
GateKeeper sessions end to end:

```env
GATEKEEPER_ISSUER=https://gatekeeper.b3n.in
GATEKEEPER_JWKS_URL=https://gatekeeper.b3n.in/oauth/jwks.json
GATEKEEPER_AUDIENCE=sentinel-api
GATEKEEPER_REQUIRED_SCOPES=auth:read
```

For Knowhere, change `GATEKEEPER_AUDIENCE` to `knowhere-api`. DNS changes and
production auth cutovers require explicit approval.

## Required DNS

```text
gatekeeper.b3n.in    A    <gatekeeper-droplet-ip>
```

DNS changes and B3n control-plane cutovers require explicit approval.

## Backups

Back up before upgrades:

- `/apps/gatekeeper/.env`
- `/apps/gatekeeper/Caddyfile`
- GateKeeper Postgres volume or logical dump
- Caddy data and config volumes

Prove restore on a non-production host before relying on a backup strategy.
