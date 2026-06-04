# Concepts

GateKeeper is the central authority for identity, sessions, account membership,
API auth, and audit.

For a route-by-route breakdown of provider, OAuth, hosted backing, and operator
APIs, see [reference/api-surface.md](reference/api-surface.md).

## Issuer

The issuer is the public GateKeeper base URL, such as
`https://auth.example.com`. Product backends use it to discover OIDC metadata
and signing keys.

## User

A user is a person or account subject. Users own credentials, sessions, refresh
tokens, personal tokens, and profile data.

## Organization

Organizations group users, workspaces, projects, roles, clients, API tokens, MCP
resources, and audit events. The bootstrap organization is created during first
startup.

## Workspace And Project

Workspaces group projects. Projects usually map to protected product APIs and
carry a stable audience such as `example-api`.

## Client

An auth client describes an application or machine caller:

- public browser or native app
- confidential server app
- machine-to-machine service
- CLI/device app
- MCP server or related protected resource

Clients define redirect URIs, allowed origins, audiences, scopes, token
lifetimes, and organization membership requirements.

## Audience

The audience is the API or resource a token is meant for. Backends should reject
tokens whose `aud` does not match the protected API.

## Scope And Permission

Scopes are token-level strings such as `api:read` or `mcp:tools`. Permissions
are role or membership capabilities used by GateKeeper and product policy. A
product should define the smallest scopes it needs for each API surface.

## Session And Device

A session represents a user-bound login. Device inventory and session rules are
part of the target product surface: operators should be able to see, revoke, and
policy-control browser, CLI, and MCP sessions from one account view.

## API Token Or Key

API tokens are opaque GateKeeper credentials for personal, service, project,
admin, or machine use. They are stored hashed, shown once, scoped to audiences,
and audited.

## Hosted UI

Hosted UI is optional. It is useful when a product wants GateKeeper to own the
login, signup, reset, device approval, account, session, or API-key screens. A
product can also build all of those screens itself by calling the APIs directly.
