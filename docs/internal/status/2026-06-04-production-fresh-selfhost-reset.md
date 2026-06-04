# GateKeeper Production Fresh Self-Host Reset

Date: 2026-06-04
Live URL: https://gatekeeper.b3n.in
Image tag: `73b88ff17e855f0431169e652fa760f1f20a63c8`

## Summary

Production GateKeeper was reset from the existing self-host data set to a fresh
self-host install while preserving the public domain, compose shape, and current
new GateKeeper image tag.

The reset intentionally recreated these persistent Docker volumes:

- `gatekeeper_gatekeeper-postgres-data`
- `gatekeeper_gatekeeper-api-data`

This cleared existing users, sessions, clients created after bootstrap, tokens,
audit data, and signing keys. Old browser sessions and previously issued tokens
are no longer valid.

## Rollback Bundle

A host-local rollback bundle was created before the destructive reset:

`/apps/gatekeeper/backups/fresh-reset-20260604T163332Z`

The bundle contains:

- `.env`
- `docker-compose.yml`
- `postgres.sql`
- `api-data.tgz`
- `reset-manifest.txt`

Do not copy or print the bundle contents into chat or public docs; it includes
secrets and production data.

## Reset Log

The host-local non-secret reset log is:

`/apps/gatekeeper/reset-logs/20260604T163425Z-fresh-reset.txt`

Recorded action:

```text
action=compose_down_remove_postgres_and_api_data_volumes_compose_up
source_sha=73b88ff17e855f0431169e652fa760f1f20a63c8
backup_dir=/apps/gatekeeper/backups/fresh-reset-20260604T163332Z
sentinel_cli_tracking=blocked_local_session_expired
```

## Verification

Post-reset checks:

- `/health`: `{"service":"gatekeeper-api","database":"connected","status":"ok"}`
- `/version`: reports `image_tag=73b88ff17e855f0431169e652fa760f1f20a63c8`
- `/signup`: HTTP 200 and browser-rendered first-owner setup copy
- `/oauth/jwks.json`: HTTP 200 with a newly generated key
- Compose: API and Postgres healthy, UI up
- Fresh database counts:
  - users: `0`
  - organizations: `1`
  - clients: `1`
  - sessions: `0`
- Existing Chrome session check: `/account` redirects to `/login?redirect=/account`
  after the reset, as expected for a fresh install.

## Tracking Caveat

The Sentinel CLI was the intended infra tracking surface, but the local Sentinel
session was expired and `sentinel login` required interactive username/OTP
input. No Sentinel project/deployment/audit entry was created from this session.

After Sentinel login is restored, add or reconcile an infra entry for this reset
using the reset log and rollback bundle paths above.
