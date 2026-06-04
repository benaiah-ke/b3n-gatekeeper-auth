# API Surface Map

GateKeeper has three public surfaces:

- provider APIs that product backends and product-owned UIs call directly
- OAuth/OIDC protocol endpoints used by hosted, web, CLI, MCP, and machine
  flows
- operator APIs used by owners, admins, and automation to configure the auth
  graph

Hosted UI routes are intentionally thin shells over these same APIs. If a
product wants to own its own auth screens, use the provider APIs directly.

## Health And Discovery

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /health` | Operations | Liveness check. |
| `GET /version` | Operations | Runtime artifact/version check. |
| `GET /.well-known/openid-configuration` | OAuth/OIDC | OIDC discovery metadata. |
| `GET /.well-known/oauth-authorization-server` | OAuth/OIDC | OAuth authorization server metadata. |
| `GET /oauth/jwks.json` | OAuth/OIDC | Signing keys for local JWT verification. |
| `GET /.well-known/oauth-protected-resource` | MCP/OAuth | Protected-resource metadata discovery. |
| `GET /.well-known/oauth-protected-resource/{resource_path}` | MCP/OAuth | Resource-specific protected-resource metadata. |

## Direct Auth And Account API

| Endpoint | Surface | Use |
| --- | --- | --- |
| `POST /api/v1/auth/signup` | Provider API | Product-owned signup. |
| `POST /api/v1/auth/login` | Provider API | Product-owned signin. Accepts optional `client_id`, `totp_code`, and recovery code. |
| `POST /api/v1/auth/refresh` | Provider API | Rotate a refresh token and issue a new access token. |
| `POST /api/v1/auth/session/switch-org` | Provider API | Issue a fresh session token for a selected organization, optional client, scope, and audience. |
| `POST /api/v1/auth/logout` | Provider API | Revoke the current session/refresh family when called with a session-bound token. |
| `GET /api/v1/auth/me` | Provider API | Current user, memberships, and claims. |
| `PATCH /api/v1/auth/me` | Provider API | Self-service profile update. |
| `POST /api/v1/auth/password/change` | Provider API | Self-service password change with optional other-session revocation. |
| `POST /api/v1/auth/email/change/request` | Provider API | Start verified self-service email change for a new address. |
| `POST /api/v1/auth/email/change/confirm` | Provider API | Confirm email change with the code sent to the new address. |
| `GET /api/v1/auth/identities` | Provider API | List social/federated identities linked to the current account. |
| `GET /api/v1/auth/identities/{provider_id}/link/start` | Provider API | Start a signed, current-session-bound OAuth flow to link a provider identity to the current account. |
| `DELETE /api/v1/auth/identities/{identity_id}` | Provider API | Unlink a social/federated identity when another sign-in method remains. |
| `GET /api/v1/auth/account/export` | Provider API | Export current account profile, memberships, sessions, grants, token metadata, identities, and recent audit events. |
| `POST /api/v1/auth/account/deactivate` | Provider API | Deactivate the current account with proof, last-owner protection, and revocation cleanup. |
| `POST /api/v1/auth/email-code/request` | Provider API | Request email code for login, verification, or password reset. |
| `POST /api/v1/auth/email-code/verify` | Provider API | Verify an email code and issue tokens where applicable. |
| `POST /api/v1/auth/password/reset/request` | Provider API | Start password reset. |
| `POST /api/v1/auth/password/reset/confirm` | Provider API | Complete password reset. |
| `GET /api/v1/auth/oauth/providers` | Provider API | List configured OIDC/social providers without secrets. |
| `GET /api/v1/auth/oauth/providers/admin` | Install Owner API | List database-managed providers plus read-only env-managed providers without secrets. |
| `POST /api/v1/auth/oauth/providers/admin` | Install Owner API | Create a database-managed OIDC/social provider with encrypted client secret storage. |
| `PATCH /api/v1/auth/oauth/providers/admin/{provider_id}` | Install Owner API | Update, enable/disable, rotate, or clear a database-managed provider secret. |
| `DELETE /api/v1/auth/oauth/providers/admin/{provider_id}` | Install Owner API | Delete a database-managed provider. Env-managed providers are read-only. |
| `GET /api/v1/auth/oauth/{provider_id}/start` | Provider API | Start configured OIDC/social auth with signed callback state. |
| `GET /api/v1/auth/oauth/{provider_id}/callback` | Provider API | Complete configured OIDC/social auth and link or create a federated account. |
| `GET /api/v1/auth/oauth/google/start` | Provider API | Backward-compatible Google social auth alias. |
| `GET /api/v1/auth/oauth/google/callback` | Provider API | Backward-compatible Google social auth callback alias. |

## MFA

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /api/v1/auth/mfa/status` | Provider API | Current authenticator and recovery-code state. |
| `POST /api/v1/auth/mfa/totp/setup` | Provider API | Create a pending TOTP setup secret and `otpauth://` URI. |
| `POST /api/v1/auth/mfa/totp/enable` | Provider API | Confirm TOTP and return copy-once recovery codes. |
| `POST /api/v1/auth/mfa/recovery-codes/regenerate` | Provider API | Replace unused recovery codes after TOTP verification. |
| `POST /api/v1/auth/mfa/totp/disable` | Provider API | Disable account TOTP after current factor verification. |

## Sessions And Connected Apps

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /api/v1/sessions` | Provider API | List current user's browser, app, CLI, MCP, and device sessions, including last-seen and trust metadata. |
| `PATCH /api/v1/sessions/{session_id}/device` | Provider API | Label, trust, or untrust a session/device owned by the current user. |
| `DELETE /api/v1/sessions/{session_id}` | Provider API | Revoke a session owned by the current user. |
| `POST /api/v1/sessions/revoke-all` | Provider API | Revoke other sessions or sign out everywhere. |
| `GET /api/v1/oauth/grants` | Provider API | List active connected-app grants for the current user. |
| `DELETE /api/v1/oauth/grants/{grant_id}` | Provider API | Revoke a connected-app grant. |
| `GET /api/v1/oauth/grants/admin` | Operator API | Review connected-app grants for the current organization, filtered by org, client, user, or revoked state. |
| `DELETE /api/v1/oauth/grants/admin/{grant_id}` | Operator API | Revoke an organization-scoped connected-app grant. |

## Invitations

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /api/v1/invitations` | Operator API | List organization invitations. |
| `POST /api/v1/invitations` | Operator API | Create an invitation and receive the copy-once token. |
| `DELETE /api/v1/invitations/{invitation_id}` | Operator API | Revoke a pending invitation. |
| `POST /api/v1/auth/invitations/accept` | Provider API | Product-owned or hosted invitation acceptance. |

## OAuth, Device, And Machine Flows

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /oauth/authorize` | OAuth/OIDC | Authorization-code + PKCE request. |
| `POST /oauth/authorize` | OAuth/OIDC | Hosted approval/consent submission. |
| `GET /api/v1/oauth/authorize/context` | Hosted UI backing API | Context for the hosted authorize page. |
| `POST /oauth/token` | OAuth/OIDC | Authorization-code, refresh-token, device-code, and client-credentials exchange. |
| `POST /oauth/device_authorization` | OAuth/OIDC | Start CLI/device authorization. |
| `POST /api/v1/auth/device/approve` | Provider API | Approve a device flow from a signed-in account. |
| `POST /oauth/revoke` | OAuth/OIDC | Token revocation. |
| `POST /oauth/introspect` | OAuth/OIDC | Opaque token and signed JWT introspection with session, membership, and client-disabled checks. |
| `POST /oauth/register` | OAuth/OIDC | Dynamic client registration placeholder, disabled until policy exists. |

## SCIM Compatibility

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /scim/v2/ServiceProviderConfig` | SCIM 2.0 | SCIM capability metadata for IdP connectors. |
| `GET /scim/v2/ResourceTypes` | SCIM 2.0 | Advertise the GateKeeper `User` and role-backed `Group` resource types. |
| `GET /scim/v2/Schemas` | SCIM 2.0 | Advertise the supported user and group attributes. |
| `POST /scim/v2/Bulk` | SCIM 2.0 | Execute common current-organization SCIM user and role-backed group operations in sequence, including `bulkId:` references. |
| `GET /scim/v2/Users` | SCIM 2.0 | List current-organization SCIM users with optional `userName eq "<email>"` filter, pagination, and supported sorting. |
| `POST /scim/v2/Users` | SCIM 2.0 | Create or attach a current-organization user from SCIM `userName`, `displayName`, `active`, `password`, and `roles`. |
| `GET /scim/v2/Users/{user_id}` | SCIM 2.0 | Read a current-organization SCIM user. |
| `PUT /scim/v2/Users/{user_id}` | SCIM 2.0 | Replace supported current-organization SCIM user fields, including optional write-only password. |
| `PATCH /scim/v2/Users/{user_id}` | SCIM 2.0 | Patch `active`, `displayName`/`name.formatted`, `roles`, and write-only `password`; access/password changes revoke stale sessions. |
| `DELETE /scim/v2/Users/{user_id}` | SCIM 2.0 | Deprovision the selected organization membership and revoke stale sessions. |
| `GET /scim/v2/Groups` | SCIM 2.0 | List role-backed SCIM groups with optional `displayName eq "<role>"` filter, pagination, and supported sorting. |
| `POST /scim/v2/Groups` | SCIM 2.0 | Create a role-backed SCIM group and optionally assign initial members. |
| `GET /scim/v2/Groups/{group_id}` | SCIM 2.0 | Read a role-backed SCIM group and active members. |
| `PUT /scim/v2/Groups/{group_id}` | SCIM 2.0 | Replace group display name and active member set. |
| `PATCH /scim/v2/Groups/{group_id}` | SCIM 2.0 | Add, replace, or remove members; role changes revoke stale sessions. |
| `DELETE /scim/v2/Groups/{group_id}` | SCIM 2.0 | Explicitly unsupported; remove members instead because GateKeeper roles are policy objects. |

## Organization, App, Resource, And Policy Setup

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /api/v1/setup/status` | Operator API | Issuer, JWKS, SMTP, owner, and setup capability status. |
| `GET /api/v1/orgs` | Provider/Operator API | List organizations visible to the current principal. |
| `POST /api/v1/orgs` | Operator API | Create an organization, seed default roles, and make the session user owner. |
| `PATCH /api/v1/orgs/{org_id}` | Operator API | Update name, org-wide MFA policy, trusted-device MFA reuse policy, admin step-up MFA policy, org idle-timeout policy, audit retention policy, and user hard-delete policy. |
| `GET /api/v1/workspaces` | Operator API | List workspaces visible to the current organization/operator. |
| `POST /api/v1/workspaces` | Operator API | Create a current-organization workspace. |
| `GET /api/v1/projects` | Operator API | List protected project/API audiences visible to the current organization/operator. |
| `POST /api/v1/projects` | Operator API | Create a current-organization project/API audience. |
| `GET /api/v1/roles` | Operator API | List roles and permissions visible to the current organization/operator. |
| `POST /api/v1/roles` | Operator API | Create a current-organization role. |
| `GET /api/v1/clients` | Operator API | List web, backend, CLI, MCP, and machine clients visible to the current organization/operator. |
| `POST /api/v1/clients` | Operator API | Register a client, defaulting to the current organization for org-bound operators. Operators may provide a stable lowercase `client_id`; otherwise GateKeeper generates a reserved `gkc_*` ID. |
| `PATCH /api/v1/clients/{client_id}` | Operator API | Update current-organization app metadata, publisher/verified trust metadata, client MFA policy, trusted-device MFA reuse policy, and client idle-timeout policy. |
| `POST /api/v1/clients/{client_id}/rotate-secret` | Operator API | Rotate a current-organization confidential client secret. |
| `DELETE /api/v1/clients/{client_id}` | Operator API | Disable/delete a current-organization client. |
| `GET /api/v1/mcp/resources` | Operator API | List MCP protected resources visible to the current organization/operator. |
| `POST /api/v1/mcp/resources` | Operator API | Register a current-organization MCP resource. |

## API Tokens And API Auth

| Endpoint | Surface | Use |
| --- | --- | --- |
| `GET /api/v1/tokens` | Provider/Operator API | List own personal tokens or operator-visible organization tokens. |
| `POST /api/v1/tokens` | Provider/Operator API | Create personal, service, project, admin, or machine token. |
| `POST /api/v1/tokens/validate` | Provider API | Validate an opaque API token with optional audience, scope, org, and project checks. |
| `POST /api/v1/tokens/{token_id}/rotate` | Provider/Operator API | Rotate a token and receive a copy-once value. |
| `DELETE /api/v1/tokens/{token_id}` | Provider/Operator API | Revoke a token. |

## Admin And Audit

| Endpoint | Surface | Use |
| --- | --- | --- |
| `POST /api/v1/users/provision` | Operator API | SCIM-style upsert for a current-organization user: create passwordless account by email, assign role/status, update profile/disabled state, and revoke stale sessions when access changes. |
| `GET /api/v1/users` | Operator API | List users with current-organization membership/MFA/session status. |
| `GET /api/v1/users/{user_id}` | Operator API | Inspect a current-organization user. |
| `PATCH /api/v1/users/{user_id}` | Operator API | Update current-organization user profile, verification, or suspension state. |
| `PUT /api/v1/users/{user_id}/membership` | Operator API | Assign or suspend current-organization membership. |
| `POST /api/v1/users/{user_id}/sessions/revoke` | Operator API | Revoke a current-organization user's sessions. |
| `POST /api/v1/users/{user_id}/mfa/totp/reset` | Operator API | Clear a current-organization user's TOTP/recovery state and revoke sessions. |
| `POST /api/v1/users/{user_id}/delete` | Operator API | Preview or execute policy-gated permanent user deletion with email confirmation, current-org visibility checks, and last-owner protection. |
| `GET /api/v1/audit` | Operator API | Read audit events visible to the current organization/operator. |
| `POST /api/v1/audit/prune` | Operator API | Preview or prune current-organization audit events older than the configured retention cutoff. |

## Deliberately Not Complete Yet

- Dynamic client registration is disabled by default and returns `501` until a
  registration policy is implemented.
- SCIM v2 `Users` and role-backed `Groups` compatibility exists for the common
  IdP provisioning paths, including list pagination, common sort fields, and
  write-only user password operations. SCIM Bulk supports common user and
  role-backed group provisioning operations. The Enterprise User extension
  stores common membership-scoped IdP fields such as employee number,
  department, division, cost center, organization, and manager. Group deletion
  and custom enterprise extension policy are still future work.
- Social auth supports configured OIDC-style providers through read-only
  environment bootstrap config or install-owner database-managed provider APIs.
  Explicit session-bound identity linking exists; custom linking policy beyond
  verified-email and already-linked-subject protections is still future work.
- Device inventory, user-managed trusted-device metadata, org/client
  idle-timeout policy, org/client trusted-device MFA reuse policy, and
  organization admin step-up MFA policy, and organization user hard-delete
  policy are implemented; organization audit retention/pruning is explicit
  operator policy; adaptive risk signals still need provider APIs.
- WebAuthn/passkey tables exist in the data model but product endpoints are not
  implemented yet.
