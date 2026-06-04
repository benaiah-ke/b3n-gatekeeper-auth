# API-Only Product Integration

Use this path when your product owns its own frontend and backend UX. GateKeeper
still remains the central identity, session, token, role, API-key, and audit
authority.

The product pattern is:

1. An owner creates an organization/project audience and app clients in
   GateKeeper.
2. The product backend calls GateKeeper APIs for signup, signin, reset,
   sessions, API keys, and admin actions.
3. The product backend verifies GateKeeper JWTs by issuer, JWKS, audience,
   scopes, expiration, and account or organization claims.
4. Product-local records are provisioned only after GateKeeper identity and
   claims are verified.

Hosted UI is optional in this model.

If the browser should never call GateKeeper directly, put the same calls behind
your product backend. See
[product-backend-proxy.md](product-backend-proxy.md) for the central-auth proxy
pattern.

## Configure The Product

Create a protected API audience such as `example-api`, then configure the
product backend:

```env
GATEKEEPER_ISSUER=https://auth.example.com
GATEKEEPER_JWKS_URL=https://auth.example.com/oauth/jwks.json
GATEKEEPER_AUDIENCE=example-api
GATEKEEPER_REQUIRED_SCOPES=api:read
```

Use the owner access token from first signup or owner login for setup calls:

```bash
export GATEKEEPER_ISSUER=https://auth.example.com
export OWNER_EMAIL=owner@example.com
export OWNER_PASSWORD='correct horse battery'

OWNER_LOGIN=$(curl -s "$GATEKEEPER_ISSUER/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASSWORD\"}")

OWNER_ACCESS_TOKEN=$(printf '%s' "$OWNER_LOGIN" | jq -r '.access_token')
ORG_ID=$(printf '%s' "$OWNER_LOGIN" | jq -r '.orgs[0].id')
```

If `/account` shows a viewer account, signup worked but the account cannot run
setup. Use an owner account.

## Operator Setup By API

Create a workspace and project audience:

```bash
WORKSPACE=$(curl -s "$GATEKEEPER_ISSUER/api/v1/workspaces" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Default workspace\",\"slug\":\"default\"}")

WORKSPACE_ID=$(printf '%s' "$WORKSPACE" | jq -r '.id')

PROJECT=$(curl -s "$GATEKEEPER_ISSUER/api/v1/projects" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"org_id\":\"$ORG_ID\",\"workspace_id\":\"$WORKSPACE_ID\",\"name\":\"Example API\",\"slug\":\"example-api\",\"audience\":\"example-api\"}")
```

Workspace, project/audience, role, and client setup APIs are scoped to the
operator token's current organization. If an owner belongs to multiple
organizations, call `POST /api/v1/auth/session/switch-org` and use the returned
access token before configuring the other organization's setup graph.

Register a public browser app for hosted OAuth or frontend SDK flows:

```bash
WEB_CLIENT=$(curl -s "$GATEKEEPER_ISSUER/api/v1/clients" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Example web app",
    "client_id":"example-web",
    "org_id":"'"$ORG_ID"'",
    "description":"Example web app uses GateKeeper for account access.",
    "logo_url":"https://app.example.com/logo.png",
    "homepage_url":"https://app.example.com",
    "privacy_policy_url":"https://app.example.com/privacy",
    "terms_url":"https://app.example.com/terms",
    "publisher_name":"Example Inc",
    "verified":true,
    "public":true,
    "redirect_uris":["https://app.example.com/auth/callback"],
    "allowed_origins":["https://app.example.com"],
    "audiences":["example-api"],
    "scopes":["openid","profile","email","api:read"],
    "require_org_membership":true,
    "require_mfa":true
  }')

WEB_CLIENT_ID=$(printf '%s' "$WEB_CLIENT" | jq -r '.client_id')
```

If `client_id` is omitted, GateKeeper generates a `gkc_*` value. Operators can
provide a stable `client_id` for deployment-managed clients such as
`example-web` or `example-cli`. Stable IDs must be 3-160 lowercase letters,
digits, dots, dashes, or underscores, and the `gkc_` prefix is reserved for
generated IDs.

`publisher_name` and `verified` drive GateKeeper's hosted authorization trust
badge. Keep unreviewed apps unverified until the operator has checked redirects,
origins, and public links.

Org-bound operator sessions can only create and manage clients in their current
organization. If `org_id` is omitted, GateKeeper assigns the new client to that
current organization. Switch organization context with
`POST /api/v1/auth/session/switch-org` before registering another org's apps.

Register a confidential backend/API client for client-credentials or server app
flows. The `client_secret` is shown once:

```bash
API_CLIENT=$(curl -s "$GATEKEEPER_ISSUER/api/v1/clients" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Example backend client",
    "client_id":"example-backend",
    "org_id":"'"$ORG_ID"'",
    "public":false,
    "redirect_uris":[],
    "allowed_origins":[],
    "audiences":["example-api"],
    "scopes":["api:read"],
    "require_org_membership":true,
    "require_mfa":false
  }')

API_CLIENT_ID=$(printf '%s' "$API_CLIENT" | jq -r '.client_id')
API_CLIENT_SECRET=$(printf '%s' "$API_CLIENT" | jq -r '.client_secret')
```

## Product-Owned Signup

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/signup" \
  -H 'content-type: application/json' \
  -d '{
    "email":"user@example.com",
    "password":"correct horse battery",
    "display_name":"Example User"
  }'
```

The response includes `access_token`, `refresh_token`, `expires_in`, `scope`,
`user`, and `orgs`. On a fresh install, the first successful signup becomes
owner when no active owner exists. Later signups join the bootstrap org as
viewers until an owner changes access.

Frontend products that intentionally call GateKeeper directly can use the JS or
Vue SDK helpers instead of hand-rolling these requests:

```ts
import { useGateKeeperAuth } from 'gatekeeper-vue'

const auth = useGateKeeperAuth()

await auth.signup({
  email: 'user@example.com',
  password: 'correct horse battery',
  displayName: 'Example User',
})

await auth.loginWithPassword({
  email: 'user@example.com',
  password: 'correct horse battery',
  totpCode: '123456',
})
```

Products that keep GateKeeper behind their own backend should expose equivalent
product routes and call the same GateKeeper endpoints server-side.

## Organization Creation And Switching

Owners can create product organizations through the API. GateKeeper seeds the
standard `owner`, `admin`, `operator`, and `viewer` roles and makes the session
user owner of the new organization.

```bash
NEW_ORG=$(curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/orgs" \
  -H "authorization: Bearer <owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"name":"Second Product","slug":"second-product"}')

NEW_ORG_ID=$(printf '%s' "$NEW_ORG" | jq -r '.id')
```

Switch the active organization context by requesting a fresh token response.
For product APIs, include the product client, scope, and audience you want the
new access token to carry.

```bash
SWITCHED=$(curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/auth/session/switch-org" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "org_id":"'"$NEW_ORG_ID"'",
    "client_id":"<client-id>",
    "scope":"api:read",
    "audience":"example-api"
  }')

ACCESS_TOKEN=$(printf '%s' "$SWITCHED" | jq -r '.access_token')
```

## Product-Owned Social Signin

Install owners can configure OIDC-style social providers through `/providers`
or by API. Environment providers still work as read-only bootstrap config;
database-managed providers are the normal self-host control-plane path.

```bash
curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/auth/oauth/providers/admin" \
  -H "authorization: Bearer <install-owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "provider_id":"example",
    "name":"Example Login",
    "client_id":"example-client-id",
    "client_secret":"example-client-secret",
    "authorization_url":"https://login.example.com/oauth/authorize",
    "token_url":"https://login.example.com/oauth/token",
    "userinfo_url":"https://login.example.com/userinfo",
    "scopes":["openid","email","profile"],
    "allow_email_linking":true,
    "require_verified_email":true
  }'
```

Admin reads never return the provider secret. Rotate a secret by sending a new
`client_secret`, clear it with `null`, or disable a provider without deleting it:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/auth/oauth/providers/admin/example" \
  -H "authorization: Bearer <install-owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"enabled":false}'
```

List configured OIDC/social providers:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/oauth/providers"
```

Start a provider redirect from your product-owned auth screen:

```bash
SOCIAL_START=$(curl -s "$GATEKEEPER_ISSUER/api/v1/auth/oauth/example/start" \
  --get \
  --data-urlencode 'redirect=/account')

printf '%s' "$SOCIAL_START" | jq -r '.authorization_url'
```

The provider callback links by external subject first. If no identity exists,
GateKeeper can link by verified email when that provider allows email linking,
or create a new federated account when the provider email is verified.

## Product-Owned Signin

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{
    "email":"user@example.com",
    "password":"correct horse battery",
    "client_id":"'"$WEB_CLIENT_ID"'",
    "scope":"openid profile email api:read",
    "audience":"example-api"
  }'
```

`client_id` is optional for direct login. When supplied, GateKeeper uses the
client's configured scopes and first audience by default, which makes the
returned token match the product API. Pass `scope` and `audience` when the
product wants a narrower session for a specific API surface; GateKeeper rejects
values outside the registered client policy.

If the user has authenticator 2FA enabled, include a current TOTP code:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{
    "email":"user@example.com",
    "password":"correct horse battery",
    "client_id":"'"$WEB_CLIENT_ID"'",
    "totp_code":"123456"
  }'
```

Successful TOTP logins add `mfa_totp_enabled=true` and `amr=["pwd","otp"]` to
the user access token.

When a registered client has `"require_mfa":true`, GateKeeper refuses
client-bound login, hosted OAuth authorization-code issuance, and device
approval unless the user has authenticator MFA enrolled and the current
session/token proves MFA through `amr=["pwd","otp"]` or `["pwd","recovery"]`.
If a hosted OAuth request reaches `/oauth/authorize` with an existing
password-only session, GateKeeper redirects back to hosted login with
`step_up=mfa` so the user can enter a TOTP or recovery code and resume the same
authorization request.
Owners can also require MFA across organization-owned clients:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/orgs/$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"require_mfa":true}'
```

Enabling org MFA revokes existing org-bound client sessions that do not already
carry MFA assurance, and future client-bound login, hosted OAuth, device
approval, and refresh flows must preserve MFA `amr`.

Trusted devices can satisfy a client or organization MFA rule only after the
user has enrolled authenticator MFA and marked a current session trusted. Every
active MFA policy must explicitly allow trusted-device reuse:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/clients/$CLIENT_ROW_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"trusted_device_mfa_bypass":true}'

curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/orgs/$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"trusted_device_mfa_bypass":true}'
```

If both the client and organization require MFA, both toggles must be enabled.
GateKeeper still rejects password-only login for users without authenticator MFA
enrollment, and it stops accepting `amr=["pwd","trusted_device"]` after trust
expires or the relevant policy is disabled.

Owners can also require MFA assurance before sensitive organization mutations:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/orgs/$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"admin_step_up_mfa_required":true}'
```

After this is enabled, changes to organization policy, clients/secrets,
database-managed social providers, users, memberships, invitations, roles,
workspaces, API resources, API tokens, and MCP resources require a user session
with MFA assurance. Password-only owner sessions and service/API tokens cannot
perform those mutations until a user signs in with TOTP or an accepted trusted
device session.

If the authenticator is unavailable, submit one unused recovery code instead of
`totp_code`:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{
    "email":"user@example.com",
    "password":"correct horse battery",
    "client_id":"'"$WEB_CLIENT_ID"'",
    "recovery_code":"ABCDE-23456"
  }'
```

## Authenticator 2FA

Product-owned account UIs can enroll and manage TOTP directly through the API:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/mfa/status" \
  -H "authorization: Bearer <access-token>"

TOTP_SETUP=$(curl -s "$GATEKEEPER_ISSUER/api/v1/auth/mfa/totp/setup" \
  -H "authorization: Bearer <access-token>" \
  -X POST)

TOTP_SECRET=$(printf '%s' "$TOTP_SETUP" | jq -r '.secret')
TOTP_URI=$(printf '%s' "$TOTP_SETUP" | jq -r '.otpauth_uri')
```

Show `otpauth_uri` as a QR code or show `secret` for manual entry. After the
user enters a code from their authenticator app, enable TOTP. The response
returns copy-once recovery codes:

```bash
TOTP_ENABLED=$(curl -s "$GATEKEEPER_ISSUER/api/v1/auth/mfa/totp/enable" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"code":"123456"}')

printf '%s' "$TOTP_ENABLED" | jq -r '.recovery_codes[]'
```

Regenerate recovery codes with a current authenticator code. Old unused codes
are retired:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/mfa/recovery-codes/regenerate" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"code":"123456"}'
```

Disabling TOTP requires a current authenticator code when TOTP is enabled:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/mfa/totp/disable" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"code":"123456"}'
```

Current scope: account-level authenticator TOTP enrollment, login enforcement,
status, recovery codes, recovery-code login, recovery-code regeneration,
client-level MFA policy, org-wide MFA policy for registered app/device
sessions, trusted-device MFA reuse policy, admin step-up MFA policy for
sensitive organization mutations, disable, admin reset, audit events, session
revocation, and token claims. Richer adaptive risk signals and hosted challenge
polish remain future provider work.

## Current Account

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/me" \
  -H "authorization: Bearer <access-token>"

curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/auth/me" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"display_name":"Example User"}'

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/auth/email/change/request" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "new_email":"new-user@example.com",
    "current_password":"correct horse battery"
  }'

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/auth/email/change/confirm" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "new_email":"new-user@example.com",
    "code":"ABC12345",
    "revoke_other_sessions":true
  }'

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/auth/password/change" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "current_password":"correct horse battery",
    "new_password":"better horse battery",
    "revoke_other_sessions":true
  }'

curl -s "$GATEKEEPER_ISSUER/api/v1/orgs" \
  -H "authorization: Bearer <access-token>"
```

Self-service profile and password changes require a session-bound user token.
Verified email changes require a code sent to the new address and keep the
current session active by default while revoking other active sessions plus
their refresh tokens. Password changes use the same current-session-kept
revocation model.

Linked identity management is also a direct account API:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/identities" \
  -H "authorization: Bearer <access-token>"

curl -s "$GATEKEEPER_ISSUER/api/v1/auth/identities/example/link/start?redirect=/account" \
  -H "authorization: Bearer <session-bound-access-token>"

curl -s -X DELETE "$GATEKEEPER_ISSUER/api/v1/auth/identities/<identity-id>" \
  -H "authorization: Bearer <access-token>"
```

GateKeeper refuses to unlink the last sign-in method from a federated-only
account. Product-owned account screens should guide the user to add another
factor or password method before removing the final external identity. Link
starts generate a signed OAuth state bound to the current session; the callback
will reject missing or mismatched GateKeeper sessions, reject provider subjects
already linked to another account, and honor the provider's verified-email
requirement before attaching the identity.

Account export and deactivation are also provider APIs:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/account/export" \
  -H "authorization: Bearer <access-token>"

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/auth/account/deactivate" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "current_password":"correct horse battery",
    "totp_code":"123456"
  }'
```

Deactivation disables the account, revokes active sessions, user-owned API
tokens, and connected-app grants, and blocks future login. GateKeeper refuses
deactivation when the user is the last active owner of any organization, so
products should guide owners to transfer ownership first.

Use `/api/v1/setup/status` for operator/admin surfaces that need issuer, JWKS,
SMTP, owner, scope, and capability state.

## Admin User Lifecycle

Owners can provision users, inspect users, update profile/verification/suspension
state, assign organization roles, suspend memberships, revoke a user's sessions,
and reset authenticator 2FA:

```bash
curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/users/provision" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "org_id":"'"$ORG_ID"'",
    "email":"provisioned@example.com",
    "display_name":"Provisioned User",
    "email_verified":true,
    "role":"operator",
    "status":"active"
  }'

curl -s "$GATEKEEPER_ISSUER/api/v1/users?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/users/<user-id>" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"display_name":"Example User","email_verified":true,"disabled":false}'

curl -s -X PUT "$GATEKEEPER_ISSUER/api/v1/users/<user-id>/membership" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"org_id":"'"$ORG_ID"'","role":"owner","status":"active"}'

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/users/<user-id>/sessions/revoke" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/users/<user-id>/mfa/totp/reset" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"
```

The custom provisioning endpoint is an API-first upsert primitive. It creates
passwordless accounts by email when no user exists, updates display name,
verification and disabled state when present, assigns or updates the user's
membership in the selected organization, and revokes existing sessions when
role/status/disabled state changes. Product backends can pair it with
invitations, password reset, or configured social auth for first sign-in.

For IdP connectors that expect SCIM 2.0 shape, GateKeeper also exposes a
current-organization SCIM Users/Groups compatibility surface:

```bash
curl -s "$GATEKEEPER_ISSUER/scim/v2/ServiceProviderConfig"

curl -s "$GATEKEEPER_ISSUER/scim/v2/Users?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s "$GATEKEEPER_ISSUER/scim/v2/Users?org_id=$ORG_ID&sortBy=userName&sortOrder=ascending&startIndex=1&count=100" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s -X POST "$GATEKEEPER_ISSUER/scim/v2/Users?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/scim+json' \
  -d '{
    "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName":"provisioned@example.com",
    "displayName":"Provisioned User",
    "active":true,
    "password":"temporary horse battery",
    "roles":[{"value":"operator"}]
  }'

curl -s -X PATCH "$GATEKEEPER_ISSUER/scim/v2/Users/<user-id>?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/scim+json' \
  -d '{
    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations":[{"op":"replace","path":"password","value":"rotated horse battery"}]
  }'

curl -s -X POST "$GATEKEEPER_ISSUER/scim/v2/Groups?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/scim+json' \
  -d '{
    "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName":"support"
  }'

curl -s -X PATCH "$GATEKEEPER_ISSUER/scim/v2/Groups/<group-id>?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/scim+json' \
  -d '{
    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations":[{"op":"add","path":"members","value":[{"value":"<user-id>"}]}]
  }'

curl -s -X POST "$GATEKEEPER_ISSUER/scim/v2/Bulk?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/scim+json' \
  -d '{
    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations":[
      {
        "method":"POST",
        "path":"/Users",
        "bulkId":"user1",
        "data":{
          "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName":"bulk@example.com",
          "displayName":"Bulk User",
          "active":true,
          "password":"temporary horse battery",
          "roles":[{"value":"viewer"}],
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{
            "employeeNumber":"E-123",
            "department":"Engineering",
            "division":"Platform"
          }
        }
      },
      {
        "method":"POST",
        "path":"/Groups",
        "bulkId":"group1",
        "data":{
          "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
          "displayName":"support",
          "members":[{"value":"bulkId:user1"}]
        }
      }
    ]
  }'
```

SCIM `active` maps to the selected organization membership. Deprovisioning with
`PATCH active=false` or `DELETE /scim/v2/Users/{id}` revokes the membership and
stale sessions; if no active memberships remain, GateKeeper also disables the
central user. SCIM `roles[0].value` maps to an existing GateKeeper role name in
the selected organization. SCIM Groups are role-backed: `displayName` maps to a
GateKeeper role name, members are users with that active role, and member
add/remove operations revoke affected users' stale sessions. User lists support
`sortBy=userName`, `displayName`, `roles`, `meta.created`, and
`meta.lastModified`; group lists support `sortBy=displayName`, `meta.created`,
and `meta.lastModified`, with SCIM `startIndex`/`count` pagination on both
surfaces. SCIM `password` on user create, replace, or patch sets a normal
GateKeeper password and revokes the user's existing sessions. Passwords are
never returned in SCIM responses. SCIM Bulk supports the common `GET`, `POST`,
`PUT`, `PATCH`, and `DELETE` user operations plus `GET`, `POST`, `PUT`, and
`PATCH` role-backed group operations, including `bulkId:` references in paths
and member values. SCIM `externalId` and the Enterprise User extension fields
`employeeNumber`, `costCenter`, `organization`, `division`, `department`, and
`manager` are stored on the selected organization membership, so the same
central account can carry different IdP metadata in different organizations.
SCIM group deletion is intentionally unsupported because roles are GateKeeper
policy objects; remove members instead. Custom enterprise extension policy
beyond those common fields remains future work.

GateKeeper prevents removing the last active owner for an organization. Changing
a user's membership revokes that user's active sessions so stale role and
permission claims are not reused. Disabling a user revokes their sessions and
blocks future login, refresh, JWT use, and user-bound opaque API-token use. An
admin TOTP reset clears the user's authenticator secret and revokes their
sessions, so the user must sign in again and re-enroll MFA if required by
product policy. Org-bound admin tokens only see users, memberships, invitations,
MCP resources, and audit events for their current organization; switch
organization context before operating another product/org.

Hard delete is an explicit organization lifecycle policy. It is disabled by
default. Enable it only for installs where permanent account removal is part of
the operating model:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/orgs/$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"allow_user_hard_delete":true}'
```

Preview first. The preview returns counts for user-owned memberships, sessions,
refresh tokens, API tokens, connected-app grants, linked identities, MFA
recovery codes, device grants, one-time codes, invitations, and actor audit
events that will be deleted or unlinked:

```bash
curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/users/<user-id>/delete" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"dry_run":true}'
```

Executing a hard delete requires the target email as confirmation. GateKeeper
refuses self-delete through the admin route, refuses last-owner deletion, and
refuses org-bound deletion when the user still belongs to an organization the
operator cannot see:

```bash
curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/users/<user-id>/delete" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"dry_run":false,"confirm_email":"target@example.com"}'
```

## Admin Connected-App Grants

Owners and admins can review remembered OAuth grants for the current
organization, including the user, client, audience, approved scopes, last
authorization time, and revoked state:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/oauth/grants/admin?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s "$GATEKEEPER_ISSUER/api/v1/oauth/grants/admin?org_id=$ORG_ID&include_revoked=true" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s -X DELETE "$GATEKEEPER_ISSUER/api/v1/oauth/grants/admin/<grant-id>" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"
```

Org-bound admin tokens can only list or revoke grants in their current
organization. Revoking a grant forces the user through hosted authorization
again for future OAuth requests, but it does not revoke already-issued sessions
or refresh tokens; use session/user revocation for active access cleanup.

## Invitations

Owners can create audited organization invitations with a target role. The token
is returned once so API-first products can deliver it through their own email or
onboarding surface; GateKeeper can also email a hosted accept link when SMTP is
configured.

```bash
INVITE=$(curl -s "$GATEKEEPER_ISSUER/api/v1/invitations" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "email":"new-user@example.com",
    "org_id":"'"$ORG_ID"'",
    "role":"operator",
    "expires_in_days":7
  }')

INVITE_TOKEN=$(printf '%s' "$INVITE" | jq -r '.token')

curl -s "$GATEKEEPER_ISSUER/api/v1/invitations?org_id=$ORG_ID" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"
```

Product-owned invite acceptance screens call GateKeeper directly:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/invitations/accept" \
  -H 'content-type: application/json' \
  -d '{
    "email":"new-user@example.com",
    "password":"correct horse battery",
    "display_name":"New User",
    "token":"'"$INVITE_TOKEN"'"
  }'
```

Existing accounts must provide their current password, plus `totp_code` or
`recovery_code` when authenticator 2FA is enabled. Accepted invitations create
or update the organization membership, mark the invitation used, and issue a
normal user session bound to the invited organization. Pending invitations can
be revoked:

```bash
curl -s -X DELETE "$GATEKEEPER_ISSUER/api/v1/invitations/<invitation-id>" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"
```

## Email Code Login Or Verification

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/email-code/request" \
  -H 'content-type: application/json' \
  -d '{"email":"user@example.com","purpose":"login"}'

curl -s "$GATEKEEPER_ISSUER/api/v1/auth/email-code/verify" \
  -H 'content-type: application/json' \
  -d '{"email":"user@example.com","purpose":"login","code":"123456"}'
```

Supported purposes are `login`, `verify_email`, and `reset_password`. SMTP must
be configured before codes can be delivered outside development mode.

## Password Reset

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/password/reset/request" \
  -H 'content-type: application/json' \
  -d '{"email":"user@example.com","purpose":"reset_password"}'

curl -s "$GATEKEEPER_ISSUER/api/v1/auth/password/reset/confirm" \
  -H 'content-type: application/json' \
  -d '{
    "email":"user@example.com",
    "code":"123456",
    "new_password":"correct horse battery"
  }'
```

## Refresh

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/refresh" \
  -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh-token>"}'
```

Refresh responses rotate the refresh token. Store the new value and discard the
old one. Hosted browser sessions can also rotate from GateKeeper's HttpOnly
refresh cookie by sending an empty JSON body with browser credentials included;
API-only products should continue to store refresh tokens in secure product
cookies or encrypted server-side storage.

OAuth clients can also refresh through the standard OAuth token endpoint:

```bash
curl -s "$GATEKEEPER_ISSUER/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=<refresh-token>' \
  -d "client_id=$WEB_CLIENT_ID"
```

## Logout

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/auth/logout" \
  -H "authorization: Bearer <access-token>" \
  -X POST
```

When called with a session-bound user access token, logout revokes the backing
session and refresh token family for that session, then clears the hosted UI
access and refresh cookies if present.

## Sessions And Devices

Users can list sessions, revoke one session, revoke other sessions, or sign out
everywhere:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/sessions" \
  -H "authorization: Bearer <access-token>"

curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/sessions/<session-id>/device" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "device_label":"Work laptop",
    "trusted":true
  }'

curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/sessions/<session-id>/device" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"trusted":false}'

curl -X DELETE "$GATEKEEPER_ISSUER/api/v1/sessions/<session-id>" \
  -H "authorization: Bearer <access-token>"

curl -s "$GATEKEEPER_ISSUER/api/v1/sessions/revoke-all" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"include_current":false}'

curl -s "$GATEKEEPER_ISSUER/api/v1/sessions/revoke-all" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{"include_current":true}'
```

Session rows include IP address, user agent, current-session marker, assurance
methods (`amr`), last-seen timestamp, trusted-device metadata, and OAuth client
metadata when the session came from a registered app, CLI, MCP client, or
machine-facing surface. Users can label devices and mark a session trusted for
account-management UX. Current user JWTs carry `session_id`, so revoking a
session, signing out everywhere, or expiring a session through idle-timeout
policy invalidates the access and refresh tokens bound to the revoked sessions.

Marking a session trusted records the current device cookie against that
session. That trusted device can satisfy future client/org MFA policy only when
the user has authenticator MFA enrolled and the matching client/org policies
allow trusted-device reuse:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/sessions/<session-id>/device" \
  -H "authorization: Bearer <access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "trusted":true,
    "trusted_until":"2026-07-04T00:00:00Z"
  }'
```

Configure organization-level idle timeout:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/orgs/$ORG_ID" \
  -H "authorization: Bearer <owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"session_idle_timeout_minutes":60}'
```

Configure a stricter app/client idle timeout:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/clients/<client-row-id>" \
  -H "authorization: Bearer <owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"session_idle_timeout_minutes":15}'
```

When both organization and client policies are set, GateKeeper enforces the
stricter timeout. Client update, secret rotation, and delete operations are
scoped to the operator's current organization. Admin step-up MFA policy can
require MFA assurance before these sensitive mutations.

Configure organization audit retention and preview/prune old events explicitly:

```bash
curl -s -X PATCH "$GATEKEEPER_ISSUER/api/v1/orgs/$ORG_ID" \
  -H "authorization: Bearer <owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"audit_retention_days":365}'

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/audit/prune" \
  -H "authorization: Bearer <owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"org_id":"'"$ORG_ID"'", "dry_run":true}'

curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/audit/prune" \
  -H "authorization: Bearer <owner-access-token>" \
  -H 'content-type: application/json' \
  -d '{"org_id":"'"$ORG_ID"'", "dry_run":false}'
```

Pruning deletes only audit events for the selected organization that are older
than the configured cutoff. The destructive prune action is audited.

## API Keys And Service Tokens

Create a copy-once personal API token for the signed-in account. Non-admin
accounts can only request scopes they already hold:

```bash
PERSONAL_TOKEN=$(curl -s "$GATEKEEPER_ISSUER/api/v1/tokens" \
  -H "authorization: Bearer <user-access-token>" \
  -H 'content-type: application/json' \
  -d '{
    "name":"My product API key",
    "token_type":"personal",
    "org_id":"'"$ORG_ID"'",
    "scopes":["auth:read"],
    "audiences":["example-api"]
  }')
```

Create a service/project/admin/machine token for a product API with an owner or
token-admin access token:

```bash
API_TOKEN=$(curl -s "$GATEKEEPER_ISSUER/api/v1/tokens" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Example API service token",
    "token_type":"service",
    "org_id":"'"$ORG_ID"'",
    "scopes":["api:read"],
    "audiences":["example-api"]
  }')

RAW_API_TOKEN=$(printf '%s' "$API_TOKEN" | jq -r '.token')
```

The raw token is returned once. Store it immediately. GateKeeper stores only a
hash and hint.

Regular users only list, rotate, and revoke their own personal tokens.
Owners/operators with token administration capability can inspect and manage
organization service, project, admin, machine, and personal token metadata.

Validate opaque API tokens with required audience and scope checks:

```bash
curl -s "$GATEKEEPER_ISSUER/api/v1/tokens/validate" \
  -H 'content-type: application/json' \
  -d '{
    "token":"'"$RAW_API_TOKEN"'",
    "audience":"example-api",
    "required_scopes":["api:read"],
    "org_id":"'"$ORG_ID"'"
  }'
```

The response includes `active`, failure `reason`, token type, user/org/project
metadata, configured scopes and audiences, missing scopes, and `last_used_at`.
Use this endpoint when an API product needs to validate customer API keys and
provision or look up product-local records from GateKeeper account metadata.
Key local records by stable GateKeeper identifiers such as `user_id`, `org_id`,
`project_id`, and `token_id`, then enforce product-local entitlement, billing,
quota, and feature policy in your own database. See
[`api-keys.md`](api-keys.md) for a concrete FastAPI provisioning example.

Protocol-level introspection is still available:

```bash
curl -s "$GATEKEEPER_ISSUER/oauth/introspect" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "token=$RAW_API_TOKEN"
```

For opaque GateKeeper API tokens, introspection uses the same live validation
rules as `/api/v1/tokens/validate`: revoked or expired tokens, disabled users,
lost organization membership, deleted resources, and disabled owning clients
return `active: false` with a machine-readable `reason`. Signed user JWTs also
return inactive when their backing session is revoked, expired, idle-timed-out,
or no longer tied to an active organization membership. Signed
client-credentials JWTs return inactive after the owning OAuth client is
disabled.

Rotate or revoke API tokens:

```bash
curl -s -X POST "$GATEKEEPER_ISSUER/api/v1/tokens/<token-id>/rotate" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"

curl -s -X DELETE "$GATEKEEPER_ISSUER/api/v1/tokens/<token-id>" \
  -H "authorization: Bearer $OWNER_ACCESS_TOKEN"
```

## Machine-To-Machine Tokens

Confidential clients can use OAuth client credentials:

```bash
curl -s "$GATEKEEPER_ISSUER/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d "client_id=$API_CLIENT_ID" \
  -d "client_secret=$API_CLIENT_SECRET" \
  -d 'scope=api:read' \
  -d 'audience=example-api'
```

Use client credentials for service callers where a user session is not
appropriate. Use personal, project, or service API tokens when the product needs
copy-once API keys that operators can rotate and audit.

## Backend Verification

Product backends must verify:

- JWT signature against JWKS.
- `iss` equals `GATEKEEPER_ISSUER`.
- `aud` contains the protected API audience.
- `exp` is in the future.
- required scopes are present.
- account, organization, and role claims match product policy.

Session-bound user JWTs include `email`, `email_verified`, `display_name`,
`session_id`, MFA assurance fields, and, when organization-bound, `org_id`,
`org_slug`, `org_role`, and `permissions` for the selected active membership.
Personal-account tokens can omit those organization claims.

Use the Python SDK for FastAPI services where possible, or implement equivalent
JWKS verification in the product's runtime. Opaque API tokens should be
introspected.

## Product Backend Proxy Pattern

A product can own all auth screens while delegating auth to GateKeeper:

```text
POST /auth/signup          -> POST /api/v1/auth/signup
POST /auth/login           -> POST /api/v1/auth/login
POST /auth/refresh         -> POST /api/v1/auth/refresh
POST /auth/logout          -> POST /api/v1/auth/logout
GET  /auth/me              -> GET  /api/v1/auth/me
GET  /auth/sessions        -> GET  /api/v1/sessions
POST /auth/api-keys        -> POST /api/v1/tokens
POST /auth/api-keys/rotate -> POST /api/v1/tokens/{id}/rotate
```

The product backend should:

- store refresh tokens only in secure HTTP-only cookies or encrypted server-side
  storage;
- return only the user/session fields the product UI needs;
- verify GateKeeper tokens before provisioning product-local records;
- apply product-local policy such as account status, plan, tenant allowlist, or
  KYC state after GateKeeper identity is verified;
- log product-specific auth events alongside GateKeeper audit events.

## Current Parity Notes

Current GateKeeper builds support direct signup, signin, reset, email-code
verification/login, authenticator TOTP, linked identity listing/unlinking,
explicit session-bound provider linking, configured and admin-managed OIDC
social providers, refresh rotation, logout, admin user lifecycle controls,
invitations, role assignment, session inventory, trusted-device metadata,
session revocation, OAuth/OIDC, client credentials, API
tokens, device authorization, MCP resources, client/org-level MFA policy,
trusted-device MFA reuse policy, admin step-up MFA policy, API-token validation
with scope/audience checks, account/org switching, org/client idle-timeout
policy, organization audit retention/pruning, audit reads, SCIM Users/Groups
pagination, common sorting, password operations, SCIM Bulk, and backend JWT
verification.

Still-open parity areas include custom account-linking policy, adaptive risk
signals, custom SCIM enterprise extension policy, and richer hosted consent policy.
