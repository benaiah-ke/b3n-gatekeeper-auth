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
