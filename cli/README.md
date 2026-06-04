# GateKeeper CLI

The CLI authenticates through OAuth device authorization and stores tokens in
the OS keyring when available, falling back to a `0600` local credentials file.
It refreshes expired access tokens with the stored refresh token and accepts
`GATEKEEPER_TOKEN` or `GATEKEEPER_ACCESS_TOKEN` for automation.

```bash
gatekeeper doctor --url https://auth.example.com
gatekeeper login --url https://auth.example.com
gatekeeper whoami
gatekeeper org list
gatekeeper org switch <org-id> --client-id <client-id> --audience example-api --scope api:read
gatekeeper session list
gatekeeper session label <session-id> "Work laptop"
gatekeeper session revoke <session-id>
gatekeeper token list
gatekeeper token create "Local dev key" --scope auth:read --audience gatekeeper-api
gatekeeper token rotate <token-id>
gatekeeper token validate gk_xxx --audience gatekeeper-api --scope auth:read
```

`gatekeeper doctor` checks public health, OIDC discovery, JWKS, owner/setup
state, SMTP/dev-mode, management capabilities, and visible clients, projects,
tokens, and sessions.

If `--url` is omitted, the CLI reads `GATEKEEPER_URL` and otherwise defaults to
`http://localhost:8000` for local development.
