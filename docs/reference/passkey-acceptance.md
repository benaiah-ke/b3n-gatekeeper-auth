# Passkey Acceptance Contract

Use this checklist when changing GateKeeper passkeys, authenticator MFA,
invitations, hosted OAuth, or device authorization. A passing build alone is
not sufficient evidence for these flows.

## WebAuthn Ceremony

- Registration requires an active user session created within the last 15
  minutes.
- Registration creates a discoverable credential and requires user
  verification.
- Authentication does not require an email hint and requires user
  verification.
- RP ID and every accepted browser origin are validated before a ceremony.
  Non-loopback origins require HTTPS.
- Client, scope, and audience requested for passwordless login are stored with
  the server challenge and revalidated before token issuance.
- Challenges are random, encrypted at rest, short-lived, purpose-bound,
  session/user-bound where applicable, and atomically consumed on the first
  verification attempt.
- Expired challenges are removed as new ceremonies are created.
- Credential IDs are looked up by hash. Public keys, transports, signature
  counters, device type, backup state, and last-used time are updated without
  storing authenticator private material.
- A credential cannot be registered twice, and a user cannot remove their last
  sign-in method.

Primary regression coverage:

- `test_passkey_registration_login_management_and_replay_protection`
- `test_passkey_management_requires_a_recent_session`
- `test_passkey_options_reject_invalid_origin_configuration`

## Assurance And Account Surfaces

- Successful passkey login issues `amr=["webauthn"]` and
  `mfa_passkey_enabled=true`.
- `webauthn`, `otp`, and `recovery` satisfy client MFA, organization MFA,
  refresh, admin step-up, hosted OAuth, invitation, and device policies.
- Password login cannot silently downgrade a passkey-only account.
- Existing passkey users accept invitations with a passkey-backed session or
  another enrolled factor; password-only invitation acceptance is rejected.
- Account export includes passkey metadata, linked-identity removal counts
  passkeys as sign-in methods, and account deactivation accepts current
  passkey assurance as MFA.
- Admin user and policy surfaces count passkeys as MFA while keeping
  authenticator reset explicitly TOTP-only.

Primary regression coverage:

- `test_client_mfa_policy_enforces_login_oauth_refresh_and_device_flows`
- `test_admin_step_up_policy_requires_mfa_for_sensitive_org_mutations`
- `test_linked_identities_can_be_listed_and_safely_unlinked`
- `test_invitation_create_accept_reuse_and_revoke`

## Hosted UX

- The login page offers passkey sign-in when WebAuthn is supported.
- Authenticator and recovery inputs are present before the first password form
  submission.
- OAuth redirect, client, scope, and audience context survives passkey or
  authenticator step-up.
- The account Security section supports passkey registration, list, rename,
  and removal.
- `/device` is protected by the router session guard before the approval form
  mounts. An expired session redirects back through login with the complete
  device URL preserved.
- A signed-in device grant can be approved with a passkey, authenticator,
  recovery code, trusted session, or a policy-permitted current session.
- Passkey-unavailable messaging does not direct the user to a button their
  browser cannot render.

Required verification:

- `pnpm --filter gatekeeper-ui build`
- Desktop and mobile browser checks for `/login`, `/account` Security, and
  `/device?user_code=...`
- Browser network inspection confirming `/device` redirects before approval
  calls when no valid session exists

## Device Grant Integrity

- Device passkey options and verification require a session-bound user token.
- Device approval attempts are rate-limited before user-code lookup, including
  invalid codes and passkey option requests.
- The challenge binds the current user, current session, and pending grant.
- Only a credential owned by the current user can approve the grant.
- Approval propagates `webauthn` into the device token's `amr`.
- Approval and denial are terminal conditional updates; only the first
  concurrent decision wins.

Primary regression coverage:

- `test_device_flow_and_api_token_revocation`
- `test_device_grant_accepts_only_one_concurrent_decision`
- `test_device_approval_rate_limit_counts_invalid_user_codes`
- `test_passkey_registration_login_management_and_replay_protection`

## Operations

- `WEBAUTHN_RP_ID` is the credential domain without a scheme or port.
- `WEBAUTHN_ORIGINS` contains exact browser origins.
- `WEBAUTHN_CHALLENGE_TTL_SECONDS` remains between 60 and 600 seconds.
- The Alembic upgrade works on a clean database, and the passkey migration can
  downgrade and reapply.
- Auth rate-limit counters update atomically and persist failed attempts.
- API, JS SDK, Vue SDK, hosted UI, and Compose validation run in CI.
- Touched auth, environment, and deployment files pass secret-pattern review.

Repository verification commands:

```bash
cd api
uv run ruff check app tests
uv run pytest
uv run alembic upgrade head

cd ..
pnpm --filter gatekeeper-js build
pnpm --filter gatekeeper-vue build
pnpm --filter gatekeeper-ui build

GATEKEEPER_ENV_FILE=.env.example.selfhost \
  docker compose -f deploy/docker-compose.selfhost.yml config -q
```

See [the passkey integration guide](../integrations/passkeys.md) for API and SDK
usage.
