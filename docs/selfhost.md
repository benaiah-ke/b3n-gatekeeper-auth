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

For local validation from a checkout:

```bash
B3N_ENV_FILE=.env.example.selfhost \
  docker compose -f deploy/docker-compose.selfhost.yml config -q
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

