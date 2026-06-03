# Architecture

GateKeeper is an authorization server, identity store, token issuer, and
verification toolkit.

## Runtime Components

- `gatekeeper-api`: FastAPI service exposing hosted-auth APIs, OAuth/OIDC,
  token verification, admin APIs, MCP metadata, health, and version endpoints.
- `gatekeeper-ui`: Vue 3 application served by Caddy for hosted auth pages and
  admin control-plane views.
- `gatekeeper-postgres`: primary database for users, orgs, clients, tokens,
  sessions, grants, roles, permissions, and audit events.
- `caddy-proxy`: public reverse proxy for API, OAuth, well-known, health,
  version, and UI routes.

## Auth Model

GateKeeper separates identity from authorization policy:

- Users own identities, credentials, sessions, refresh-token families, and
  personal tokens.
- Organizations contain workspaces, projects, memberships, roles, permissions,
  auth clients, MCP resources, service keys, and audit events.
- Auth clients define allowed origins, redirect URIs, allowed audiences,
  token lifetimes, and whether organization membership is required.
- Tokens are either signed JWT access tokens or opaque values stored only as
  hashes.

## Token Rules

- Access JWTs include `iss`, `sub`, `aud`, `azp`, `scope`, `org_id`,
  `workspace_id`, `project_id`, `token_type`, `jti`, `iat`, and `exp`.
- Refresh, device, email, service, personal, and admin tokens are never stored
  in plaintext.
- Refresh token replay revokes the entire token family.
- OAuth authorization codes are single-use and PKCE-bound.
- Client credentials tokens are service-bound and never create browser
  sessions.

## MCP

Registered MCP resources expose protected-resource metadata and resource-bound
tokens. HTTP MCP servers should respond to unauthorized requests with a
`WWW-Authenticate` challenge that points clients to the metadata URL and lists
the required scopes.

