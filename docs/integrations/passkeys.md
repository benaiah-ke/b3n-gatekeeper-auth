# Passkeys

GateKeeper supports discoverable WebAuthn passkeys for passwordless sign-in,
MFA assurance, account credential management, invitation acceptance, and
signed-in CLI/device approval.

The hosted UI implements the complete browser ceremony. Product-owned UIs can
use the same provider APIs directly or through `gatekeeper-js` and
`gatekeeper-vue`.

## Runtime Configuration

Set the relying-party ID to the hostname that owns the credential and list
every exact browser origin that may complete a ceremony:

```env
WEBAUTHN_RP_ID=auth.example.com
WEBAUTHN_RP_NAME=GateKeeper
WEBAUTHN_ORIGINS=https://auth.example.com
WEBAUTHN_CHALLENGE_TTL_SECONDS=300
```

`WEBAUTHN_RP_ID` is a hostname, without a scheme or port.
`WEBAUTHN_ORIGINS` is a comma-separated list of complete origins, including
scheme and any non-default port. Production passkeys require a secure HTTPS
context. `http://localhost` is suitable for local development.

When the explicit values are absent, GateKeeper derives the RP ID and one
origin from `UI_URL`. Explicit values are recommended for deployed installs,
especially when the UI has more than one allowed origin.

## Registration

Registration requires an active, session-bound user token:

1. Call `POST /api/v1/auth/passkeys/registration/options`.
2. Pass the returned `public_key` value to the browser WebAuthn registration
   API.
3. Send the browser credential and returned `challenge_id` to
   `POST /api/v1/auth/passkeys/registration/verify`.

With `@simplewebauthn/browser` and `gatekeeper-js`:

```ts
import { startRegistration } from '@simplewebauthn/browser'
import { GateKeeperClient } from 'gatekeeper-js'

const gatekeeper = new GateKeeperClient({
  issuer: 'https://auth.example.com',
})

const options = await gatekeeper.passkeyRegistrationOptions(accessToken)
const credential = await startRegistration({ optionsJSON: options.public_key })
const passkey = await gatekeeper.registerPasskey(accessToken, {
  challengeId: options.challenge_id,
  credential,
  name: 'Work laptop',
})
```

Use `GET /api/v1/auth/passkeys` to list active credentials,
`PATCH /api/v1/auth/passkeys/{credential_id}` to rename one, and
`DELETE /api/v1/auth/passkeys/{credential_id}` to remove one. GateKeeper
refuses to remove the last remaining sign-in method.

## Passwordless Sign-In

Authentication options do not require an email address because GateKeeper
creates discoverable credentials:

```ts
import { startAuthentication } from '@simplewebauthn/browser'

const options = await gatekeeper.passkeyAuthenticationOptions({
  clientId: 'example-web',
  scope: 'openid profile email api:read',
  audience: 'example-api',
})
const credential = await startAuthentication({ optionsJSON: options.public_key })
const tokens = await gatekeeper.verifyPasskeyAuthentication({
  challengeId: options.challenge_id,
  credential,
})
```

The optional client, scope, and audience values are bound to the server-side
challenge and validated again before tokens are issued. Successful passkey
sessions carry `amr=["webauthn"]` and `mfa_passkey_enabled=true`.

Once an account has a passkey, the password login endpoint does not silently
downgrade that account to password-only authentication. The hosted login page
offers passkey sign-in directly.

## Device Approval And Invitations

The hosted `/device` page is session-protected. A signed-in user with a
registered passkey can approve a pending device grant through:

- `POST /api/v1/auth/device/passkey/options`
- `POST /api/v1/auth/device/passkey/verify`

The resulting device token preserves `webauthn` in its `amr` claim. TOTP,
recovery-code, trusted-session, and policy-permitted non-MFA approval paths
remain available through `POST /api/v1/auth/device/approve`.

Existing users may accept invitations with an active session. A passkey-enrolled
account must use a passkey-backed session, TOTP, or a recovery code when MFA
assurance is required; invitation acceptance cannot be used as a password-only
bypass.

## Verification And Storage Rules

GateKeeper:

- requires user verification and discoverable credentials;
- validates the exact configured origin and RP ID;
- generates random challenges, encrypts them at rest, binds them to their
  purpose and session where applicable, and accepts each challenge once;
- expires challenges after the configured short lifetime;
- stores credential public keys, transports, counters, device type, and backup
  state, but never stores private key material;
- updates signature counters and last-used timestamps after successful
  authentication; and
- treats `webauthn`, `otp`, and `recovery` as MFA assurance methods in client,
  organization, admin step-up, refresh, invitation, and device policies.

See the [WebAuthn Level 3 specification](https://www.w3.org/TR/webauthn-3/)
for the browser security model and the
[`@simplewebauthn/browser` documentation](https://simplewebauthn.dev/docs/packages/browser/)
for browser ceremony helpers.
