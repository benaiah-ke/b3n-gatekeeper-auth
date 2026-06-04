# MCP Integration

GateKeeper supports MCP HTTP authorization with protected-resource metadata and
resource-bound access tokens.

## Register A Resource

Create an MCP resource with:

- name: `Example MCP`
- resource URI: `https://api.example.com/mcp`
- scopes: `mcp:tools`

## Publish Metadata

Your MCP server should expose protected-resource metadata at:

```text
https://api.example.com/.well-known/oauth-protected-resource/mcp
```

The metadata should point clients to GateKeeper as the authorization server and
list the scopes required by the resource.

## Challenge Unauthorized Requests

```text
WWW-Authenticate: Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"
```

## Validate Tokens

MCP servers must validate issuer, audience/resource, expiration, signature,
required scopes, and user or machine binding. Tool-level authorization remains
application policy and should be audited.

## FastAPI Helper

The Python SDK can publish metadata and return MCP-compatible challenges:

```python
from fastapi import Depends, FastAPI
from gatekeeper_sdk import GateKeeperVerifier, Principal

app = FastAPI()
mcp_resource = "https://api.example.com/mcp"
mcp_scopes = ["mcp:tools"]
mcp_metadata_url = "https://api.example.com/.well-known/oauth-protected-resource/mcp"

verifier = GateKeeperVerifier(
    issuer="https://auth.example.com",
    audience=mcp_resource,
)


@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata():
    return verifier.protected_resource_metadata(mcp_resource, mcp_scopes).model_dump()


@app.post("/mcp/tools/call")
async def call_tool(
    principal: Principal = Depends(
        verifier.mcp_dependency(mcp_scopes, metadata_url=mcp_metadata_url)
    ),
):
    return {"subject": principal.subject}
```

`mcp_dependency(...)` validates the GateKeeper bearer token and returns a
`WWW-Authenticate` challenge with `resource_metadata` and `scope` when the
request is missing or has invalid credentials.

See [../mcp-auth.md](../mcp-auth.md) for the protocol-specific reference.
