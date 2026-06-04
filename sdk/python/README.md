# GateKeeper Python SDK

FastAPI helpers for GateKeeper JWT verification and opaque API-key validation.

## JWT Access Tokens

```python
from fastapi import Depends, FastAPI
from gatekeeper_sdk import GateKeeperVerifier, Principal

app = FastAPI()
verifier = GateKeeperVerifier(
    issuer="https://auth.example.com",
    audience="example-api",
)


@app.get("/v1/projects")
async def list_projects(
    principal: Principal = Depends(verifier.dependency(["api:read"])),
):
    return {"subject": principal.subject, "org_id": principal.org_id}
```

## Opaque API Keys

Accept customer API keys in `X-API-Key` or `Authorization: Bearer` and validate
them through GateKeeper:

```python
from fastapi import Depends
from gatekeeper_sdk import ApiTokenValidation


@app.get("/v1/payments")
async def list_payments(
    token: ApiTokenValidation = Depends(
        verifier.api_key_dependency(["payments:read"], audience="payments-api")
    ),
):
    return {"org_id": token.org_id, "project_id": token.project_id}
```

The dependency returns token type, account, organization, project, scope,
audience, and last-used metadata. Policy mismatches such as missing scopes or a
wrong audience raise `403`; revoked, expired, missing, or unsupported tokens
raise `401`.

## MCP Protected Resources

MCP HTTP servers can publish protected-resource metadata and return the correct
`WWW-Authenticate` challenge from the same verifier:

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


@app.post("/mcp/tools/list")
async def list_tools(
    principal: Principal = Depends(
        verifier.mcp_dependency(mcp_scopes, metadata_url=mcp_metadata_url)
    ),
):
    return {"subject": principal.subject, "tools": []}
```

`mcp_dependency(...)` validates the bearer JWT and adds an MCP-compatible
`WWW-Authenticate` header when credentials are missing or invalid.
