# Security Policy

GateKeeper stores identity, sessions, API tokens, and authorization policy. Treat
all defects as potentially security relevant.

## Supported Versions

GateKeeper is pre-1.0. Security fixes target `main` until the first stable
release line exists.

## Reporting

Report vulnerabilities through the private maintainer contact for the project
or deployment. Include impact, affected version or commit, reproduction steps,
and whether any secret material may have been exposed. Do not open a public
issue with secrets, exploit details, or live tenant data.

## Defaults

- Passwords are hashed with Argon2id.
- Opaque tokens are stored as SHA-256 hashes with one-time display.
- Refresh tokens rotate and replay detection revokes the token family.
- OAuth authorization codes and device codes are single-use.
- Access tokens are audience/resource bound.
- Audit events are recorded for auth, token, client, role, and MCP changes.
- Production docs intentionally gate DNS and service cutovers behind approval.
