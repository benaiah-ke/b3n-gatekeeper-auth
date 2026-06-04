# Hosted Web App Integration

Use hosted auth when you want GateKeeper to own login, signup, reset, device
approval, or account screens. Web apps should use OAuth authorization-code +
PKCE.

## Register A Client

Create a client with:

- name: `Example Web`
- client type: public for browser-only apps, confidential for server apps
- hosted consent metadata: description, logo URL, homepage, privacy policy, and
  terms URLs when you use GateKeeper-hosted authorization
- trust metadata: publisher name and verified status after the operator reviews
  redirects, origins, and public links
- redirect URI: `https://app.example.com/auth/callback`
- allowed origin: `https://app.example.com`
- audience: `example-api`
- scopes: `openid profile email api:read`

## Authorization Request

Generate a PKCE verifier and challenge, then redirect the browser:

```text
https://auth.example.com/oauth/authorize?response_type=code&client_id=example-web&redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback&code_challenge=<challenge>&code_challenge_method=S256&scope=openid%20profile%20email%20api%3Aread&audience=example-api&state=<opaque-state>
```

The callback receives `code` and `state`.

## Token Exchange

```bash
curl -s https://auth.example.com/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=example-web' \
  -d 'redirect_uri=https://app.example.com/auth/callback' \
  -d 'code=<code>' \
  -d 'code_verifier=<verifier>'
```

The response includes access and refresh tokens.

## Hosted-Flow Notes

`/oauth/authorize` validates the client, redirect URI, audience, and scopes
before redirecting unauthenticated users through hosted login. After login or
signup, the UI performs a real browser navigation back to the OAuth request.
Signed-in users are shown a hosted authorization screen that identifies the app
name, optional logo, optional description, configured homepage/privacy/terms
links, publisher, verified/unverified badge, redirect origin, audience, account
scope, and requested scopes. When the
client requires organization membership, GateKeeper resolves the selected
organization from the signed-in user's active memberships and binds the issued
authorization code to that organization. Clients that do not require
organization membership can issue personal-account tokens unless an explicit
valid `org_id` is supplied. Approval returns to `/oauth/authorize` with an
explicit approval flag and then issues the authorization code.

When the requested client or selected organization requires MFA and the current
GateKeeper browser session only proves password authentication,
`/oauth/authorize` redirects to hosted login with `step_up=mfa`. The hosted
login page asks for an authenticator or recovery code, creates a fresh
client-bound session using the same OAuth `client_id`, `scope`, and `audience`,
then navigates back to the original authorization request.

Configured OIDC/social providers appear on the hosted login and signup screens.
When a hosted OAuth authorization request redirects to login first, provider
start URLs carry signed state so the provider callback can return to the
original `/oauth/authorize` request after GateKeeper creates the session.
Hosted browser sessions set HttpOnly access and refresh cookies, and the UI
tries a cookie refresh before deciding that `/account` or `/authorize` should
return to login.

## Remembered Grants

Approval creates a durable OAuth grant for the signed-in user, client, selected
organization or personal account, audience, and approved scopes. A later
authorization request that is covered by an active grant skips the hosted
authorization screen and issues a new authorization code directly.

Users can list active connected apps:

```bash
curl -s https://auth.example.com/api/v1/oauth/grants \
  -H 'authorization: Bearer <access-token>'
```

Users can revoke a grant:

```bash
curl -X DELETE https://auth.example.com/api/v1/oauth/grants/<grant-id> \
  -H 'authorization: Bearer <access-token>'
```

Revoking a grant does not revoke already-issued sessions or refresh tokens. Use
session revocation for active session cleanup.

Organization owners and admins can also review and revoke connected-app grants
for their current organization:

```bash
curl -s "https://auth.example.com/api/v1/oauth/grants/admin?org_id=<org-id>&include_revoked=true" \
  -H 'authorization: Bearer <owner-access-token>'

curl -X DELETE https://auth.example.com/api/v1/oauth/grants/admin/<grant-id> \
  -H 'authorization: Bearer <owner-access-token>'
```

Org-bound admin tokens can only review or revoke grants in their current
organization. Remaining hosted-flow gaps include deeper app branding and richer
consent policy.
