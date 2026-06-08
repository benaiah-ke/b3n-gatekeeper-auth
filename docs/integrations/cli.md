# CLI Auth

CLIs should use GateKeeper device authorization or another user-bound flow and
store refreshable credentials locally with restrictive permissions.

## Device Authorization

```bash
curl -s https://auth.example.com/oauth/device_authorization \
  -H 'content-type: application/json' \
  -d '{"client_id":"example-cli","scope":"openid profile email cli:read","audience":"example-api"}'
```

The response includes:

- `device_code`
- `user_code`
- `verification_uri`
- `verification_uri_complete`
- `expires_in`
- `interval`

The CLI shows the verification URI and user code. The user approves the request
in the browser.

## Poll For Tokens

```bash
curl -s https://auth.example.com/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'client_id=example-cli' \
  -d 'device_code=<device-code>'
```

If authorization is still pending, GateKeeper currently returns an
authorization-pending response. After approval, the response includes access and
refresh tokens.

## Credential Store

The GateKeeper CLI stores:

- issuer
- account/user summary
- access token
- refresh token
- selected organization context
- visible memberships returned by auth responses

Use `0600` file permissions or a platform keychain. Support an environment
variable override for automation tokens with `B3N_GATEKEEPER_TOKEN` or
`B3N_GATEKEEPER_ACCESS_TOKEN`.

## GateKeeper CLI Commands

```bash
b3n-gatekeeper doctor --url https://auth.example.com
b3n-gatekeeper login --url https://auth.example.com --client-id example-cli --scope "openid profile email cli:read"
b3n-gatekeeper whoami --url https://auth.example.com

b3n-gatekeeper org list --url https://auth.example.com
b3n-gatekeeper org switch <org-id> \
  --url https://auth.example.com \
  --client-id example-cli \
  --audience example-api \
  --scope cli:read

b3n-gatekeeper session list --url https://auth.example.com
b3n-gatekeeper session label <session-id> "Work laptop" --url https://auth.example.com
b3n-gatekeeper session trust <session-id> --url https://auth.example.com
b3n-gatekeeper session revoke <session-id> --url https://auth.example.com
b3n-gatekeeper session revoke-all --other-only --url https://auth.example.com

b3n-gatekeeper token create "Local extension token" \
  --url https://auth.example.com \
  --scope api:read \
  --audience example-api

b3n-gatekeeper token rotate <token-id> --url https://auth.example.com

b3n-gatekeeper token validate gk_xxx \
  --url https://auth.example.com \
  --audience example-api \
  --scope api:read
```

Run `b3n-gatekeeper doctor` before and after first setup. It checks public API
reachability, OIDC discovery, JWKS, authenticated owner/setup state, SMTP or
email dev-mode, client/project/token capabilities, and visible clients,
audiences, credentials, and sessions.

The CLI refreshes expired access tokens automatically when a refresh token is
available. `b3n-gatekeeper logout` revokes the current GateKeeper session when it
can reach the issuer, then removes local credentials.

`token rotate` uses GateKeeper's copy-once rotation endpoint and prints the
replacement token value once. `token validate` is useful for API products and
support workflows because it applies audience, scope, organization, and project
policy checks through the same validation endpoint product backends should use.

## Shared Session Controls

GateKeeper exposes shared session visibility through `/api/v1/sessions`.
Browser, CLI, and MCP sessions can be reviewed with app/client metadata, revoked
one at a time, revoked as "other sessions", or revoked with a full
sign-out-everywhere call through `/api/v1/sessions/revoke-all`.

Trusted-device flags on sessions can satisfy client or organization MFA policy
only when the matching trusted-device bypass policy is enabled.
