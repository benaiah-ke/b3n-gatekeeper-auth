# B3n GateKeeper CLI

The CLI authenticates through OAuth device authorization and stores tokens in
the OS keyring when available, falling back to a `0600` local credentials file.
It refreshes expired access tokens with the stored refresh token and accepts
`B3N_GATEKEEPER_TOKEN` or `B3N_GATEKEEPER_ACCESS_TOKEN` for automation.

```bash
b3n-gatekeeper doctor --url https://auth.example.com
b3n-gatekeeper login --url https://auth.example.com
b3n-gatekeeper whoami
b3n-gatekeeper org list
b3n-gatekeeper org switch <org-id> --client-id <client-id> --audience example-api --scope api:read
b3n-gatekeeper session list
b3n-gatekeeper session label <session-id> "Work laptop"
b3n-gatekeeper session revoke <session-id>
b3n-gatekeeper token list
b3n-gatekeeper token create "Local dev key" --scope auth:read --audience gatekeeper-api
b3n-gatekeeper token rotate <token-id>
b3n-gatekeeper token validate gk_xxx --audience gatekeeper-api --scope auth:read
```

`b3n-gatekeeper doctor` checks public health, OIDC discovery, JWKS, owner/setup
state, SMTP/dev-mode, management capabilities, and visible clients, projects,
tokens, and sessions.

If `--url` is omitted, the CLI reads `B3N_GATEKEEPER_URL` and otherwise defaults to
`http://localhost:8000` for local development.

## Client Creation

Operators can register public browser/CLI clients or confidential backend/API
clients from the CLI:

```bash
b3n-gatekeeper client create "Example web" \
  https://app.example.com/auth/callback \
  example-api \
  --url https://auth.example.com \
  --client-id example-web \
  --public \
  --origin https://app.example.com \
  --scope "openid profile email auth:read"
```

Confidential clients return a copy-once secret. To avoid printing that secret
to terminal history, logs, or automation output, the CLI requires an explicit
new output file and redacts the JSON response:

```bash
b3n-gatekeeper client create "Example backend" \
  https://api.example.com/auth/callback \
  example-api \
  --url https://auth.example.com \
  --client-id example-backend \
  --confidential \
  --origin https://api.example.com \
  --scope "openid profile email auth:read" \
  --secret-output /path/to/private/example-backend.client-secret
```

The secret output file is created with `0600` permissions and must not already
exist. Move its contents into the relevant secret store, then remove the local
copy.

Generic `GATEKEEPER_*` names are intentionally not read by this B3n package so
local automation cannot accidentally reuse credentials from another GateKeeper
installation.
