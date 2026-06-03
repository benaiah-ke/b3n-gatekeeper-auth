# MCP Authorization

GateKeeper follows the MCP Authorization specification for HTTP transports.
STDIO MCP servers should retrieve credentials from the local environment or CLI
credential store instead of running a browser OAuth flow.

## Protected Resource Metadata

Each MCP resource exposes metadata at:

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-protected-resource/{resource-path}
```

The metadata includes:

- `resource`: canonical MCP resource URI
- `authorization_servers`: GateKeeper issuer URL
- `scopes_supported`: least-privilege scopes for the resource

## Challenge Header

An MCP server protecting `https://sentinel.b3n.in/mcp` should return:

```text
WWW-Authenticate: Bearer resource_metadata="https://sentinel.b3n.in/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"
```

## Token Validation

MCP servers must validate:

- issuer matches GateKeeper
- audience/resource matches the canonical MCP server URI
- token is unexpired and not revoked
- required scopes are present
- user or machine binding is appropriate for the tool

Tool-level checks remain application policy and should be audited by the MCP
server or by GateKeeper when issuing scoped tokens.

