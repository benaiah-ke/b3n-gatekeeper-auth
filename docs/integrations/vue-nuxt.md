# Vue And Nuxt Integration

GateKeeper's frontend packages support hosted OAuth/OIDC integration when a
product wants to redirect to GateKeeper for login/signup and then return with an
authorization-code + PKCE callback. Product-owned auth screens can still call
GateKeeper APIs directly; hosted auth is optional.

## Runtime Config

```env
NUXT_PUBLIC_GATEKEEPER_ISSUER=https://auth.example.com
NUXT_PUBLIC_GATEKEEPER_CLIENT_ID=example-web
NUXT_PUBLIC_GATEKEEPER_AUDIENCE=example-api
NUXT_PUBLIC_GATEKEEPER_SCOPES=openid profile email api:read
```

The backend still verifies tokens server-side. Frontend SDK state is
convenience, not authorization proof.

## Framework-Agnostic JS

Use `gatekeeper-js` when the product wants to own routing and state:

```ts
import { BrowserTokenStore, GateKeeperClient } from 'gatekeeper-js'

const gatekeeper = new GateKeeperClient({
  issuer: 'https://auth.example.com',
  clientId: 'example-web',
  redirectUri: `${window.location.origin}/auth/callback`,
  audience: 'example-api',
  scope: 'openid profile email api:read',
})

const flow = await gatekeeper.startAuthorization()
sessionStorage.setItem('gatekeeper.pkce', JSON.stringify(flow))
window.location.assign(flow.url)
```

On the callback route:

```ts
import { BrowserTokenStore } from 'gatekeeper-js'

const stored = JSON.parse(sessionStorage.getItem('gatekeeper.pkce') || '{}')
const code = new URLSearchParams(window.location.search).get('code')

if (!code || !stored.codeVerifier) {
  throw new Error('Missing GateKeeper callback data')
}

const response = await gatekeeper.exchangeCode({
  code,
  codeVerifier: stored.codeVerifier,
})

const tokens = new BrowserTokenStore().save(response)
const account = await gatekeeper.me(tokens.accessToken)
```

For product-owned auth screens, use the same client without redirecting through
hosted UI:

```ts
const signup = await gatekeeper.signup({
  email: 'user@example.com',
  password: 'correct horse battery',
  displayName: 'Example User',
})
const tokens = new BrowserTokenStore().save(signup)

const signin = await gatekeeper.login({
  email: 'user@example.com',
  password: 'correct horse battery',
  totpCode: '123456',
})
new BrowserTokenStore().save(signin)

await gatekeeper.requestPasswordReset({ email: 'user@example.com' })
await gatekeeper.confirmPasswordReset({
  email: 'user@example.com',
  code: 'ABC12345',
  newPassword: 'new correct horse battery',
})
```

`gatekeeper-js` also includes refresh, logout, client-credentials token
exchange, direct signup/signin/invitation/email-code/password-reset helpers,
`/me`, protected-resource metadata, API-token validation, API-token
list/create/rotate/revoke helpers, session revocation, global signout,
connected-app grant listing, and grant revocation helpers.

## Server Verification For Node And Nuxt

Browser auth state is not authorization proof. Product APIs and Nuxt server
routes should verify the GateKeeper JWT with issuer, audience, expiry, signature,
and required scopes before trusting the request.

```ts
import { createGateKeeperVerifier } from 'gatekeeper-js'

const verifier = createGateKeeperVerifier({
  issuer: 'https://auth.example.com',
  audience: 'example-api',
  requiredScopes: ['api:read'],
})

export async function requirePrincipal(authorization?: string | null) {
  return verifier.verifyAuthorizationHeader(authorization)
}
```

In a Nuxt server route:

```ts
import { createGateKeeperVerifier } from 'gatekeeper-js'

const verifier = createGateKeeperVerifier({
  issuer: useRuntimeConfig().public.gatekeeperIssuer,
  audience: useRuntimeConfig().public.gatekeeperAudience,
})

export default defineEventHandler(async (event) => {
  const principal = await verifier.verifyAuthorizationHeader(
    getRequestHeader(event, 'authorization'),
    { requiredScopes: ['api:read'] },
  )

  return { subject: principal.subject, role: principal.orgRole }
})
```

The verifier caches JWKS, refreshes when a `kid` is unknown, validates RS256
signatures, and exposes `subject`, `scopes`, `audience`, `orgId`, `orgRole`,
`permissions`, `amr`, and raw claims.

## Vue

Register the Vue plugin once:

```ts
import { createApp } from 'vue'
import { createGateKeeper } from 'gatekeeper-vue'

const app = createApp(App)

app.use(
  createGateKeeper({
    issuer: import.meta.env.VITE_GATEKEEPER_ISSUER,
    clientId: import.meta.env.VITE_GATEKEEPER_CLIENT_ID,
    redirectUri: `${window.location.origin}/auth/callback`,
    audience: import.meta.env.VITE_GATEKEEPER_AUDIENCE,
    scope: import.meta.env.VITE_GATEKEEPER_SCOPES,
  }),
)
```

Use the composable from login and callback views:

```ts
import { useGateKeeperAuth } from 'gatekeeper-vue'

const auth = useGateKeeperAuth()

await auth.loginWithRedirect()
await auth.handleRedirectCallback()
await auth.loadUser()
```

The composable exposes `tokens`, `accessToken`, `isAuthenticated`,
`needsRefresh`, `user`, `orgs`, `me`, `refresh`, `logout`,
`signup`, `loginWithPassword`, `acceptInvitation`, `requestEmailCode`,
`verifyEmailCode`, `requestPasswordReset`, `confirmPasswordReset`, `switchOrg`,
`updateProfile`, `changePassword`, `requestEmailChange`, `confirmEmailChange`,
`linkedIdentities`, `unlinkIdentity`, `oauthProviders`, `startOAuthProvider`,
`apiTokens`, `createApiToken`, `rotateApiToken`, `revokeApiToken`,
`exportAccount`, `deactivateAccount`, `sessions`, `updateSessionDevice`,
`revokeSession`, `revokeAllSessions`, `grants`, `revokeGrant`, `grantsAdmin`,
and `revokeGrantAdmin`.

Product-owned login screens can save the returned token response directly into
the composable state:

```ts
await auth.signup({
  email: form.email,
  password: form.password,
  displayName: form.displayName,
})

await auth.loginWithPassword({
  email: form.email,
  password: form.password,
  clientId: 'gkc_product_client',
  audience: 'example-api',
  scope: 'api:read',
  totpCode: form.totpCode || null,
})
```

Use `switchOrg` when a product needs to move the active account context without
forcing a new signin:

```ts
await auth.switchOrg({
  orgId,
  clientId: 'gkc_product_client',
  audience: 'example-api',
  scope: 'api:read',
})
```

Products that expose API extensions can let signed-in users create
account-bound API keys without leaving the product UI:

```ts
const created = await auth.createApiToken({
  name: 'Example API key',
  tokenType: 'personal',
  scopes: ['api:read'],
  audiences: ['example-api'],
})

console.log(created.token) // copy-once value; show it once and store only the hint
```

For product-owned account, device/session, and API-key pages, use the
view-model composables instead of rebuilding loading/error/copy-once state from
scratch:

```ts
import {
  useGateKeeperAccount,
  useGateKeeperApiTokens,
  useGateKeeperAuth,
  useGateKeeperConnectedApps,
  useGateKeeperConnectedAppsAdmin,
  useGateKeeperSessions,
} from 'gatekeeper-vue'

const auth = useGateKeeperAuth()
const account = useGateKeeperAccount(auth, { immediate: true })
const sessions = useGateKeeperSessions(auth, { immediate: true })
const apiKeys = useGateKeeperApiTokens(auth, { immediate: true })
const connectedApps = useGateKeeperConnectedApps(auth, { immediate: true })
const grantReview = useGateKeeperConnectedAppsAdmin(auth, {
  orgId,
  includeRevoked: false,
})

await account.updateProfile({ displayName: 'Ada Lovelace' })
await sessions.updateDevice(sessionId, { deviceLabel: 'Work laptop', trusted: true })
await connectedApps.revoke(grantId)
await grantReview.load({ userId })

const createdKey = await apiKeys.create({
  name: 'Billing API extension',
  tokenType: 'personal',
  scopes: ['billing:read'],
  audiences: ['billing-api'],
})

console.log(apiKeys.copyOnceToken.value?.token || createdKey.token)
```

These composables expose product-ready state such as `activeOrg`,
`identities`, `activeSessions`, `currentSession`, `activeTokens`,
`activeGrants`, `revokedGrants`, `copyOnceToken`, `loading`, and `error`, plus
actions for profile, password, email, identity unlinking, account
export/deactivation, device labels/trust, session revocation, connected-app
grant revocation, admin grant review by org/client/user, and API-token
create/rotate/revoke.

For apps that want a faster account surface, the Vue package also exports
small optional components backed by the same composables:

```vue
<script setup lang="ts">
import {
  GateKeeperAccountCard,
  GateKeeperApiTokenList,
  GateKeeperConnectedAppsList,
  GateKeeperSessionList,
  useGateKeeperAuth,
} from 'gatekeeper-vue'

const auth = useGateKeeperAuth()
</script>

<template>
  <GateKeeperAccountCard :auth="auth" />
  <GateKeeperSessionList :auth="auth" />
  <GateKeeperApiTokenList
    :auth="auth"
    default-name="Billing API key"
    :scopes="['billing:read']"
    :audiences="['billing-api']"
  />
  <GateKeeperConnectedAppsList :auth="auth" />
</template>
```

The components render account identity, active organization/permissions,
sessions/devices, copy-once API-key values, API-key rotation/revocation, and
connected-app grant revocation. They emit predictable `gk-*` class names and
accept a `class-prefix` prop for design-system styling. Each component also has
a default scoped slot (`account`, `sessions`, `apiTokens`, or
`connectedApps`) so a product can keep the same state/actions while replacing
the markup.

## Nuxt

Nuxt uses the same Vue plugin on the client, sourced from runtime config:

```ts
// plugins/gatekeeper.client.ts
import { createGateKeeperFromNuxtRuntime } from 'gatekeeper-vue'

export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.vueApp.use(createGateKeeperFromNuxtRuntime(useRuntimeConfig()))
})
```

Use a callback page to finish hosted auth:

```vue
<!-- pages/auth/callback.vue -->
<script setup lang="ts">
import { useGateKeeperAuth } from 'gatekeeper-vue'

const auth = useGateKeeperAuth()

onMounted(async () => {
  await auth.handleRedirectCallback()
  await navigateTo('/account')
})
</script>
```

For guarded client routes:

```ts
// middleware/gatekeeper-auth.client.ts
import { useGateKeeperAuth, useGateKeeperHydration } from 'gatekeeper-vue'

export default defineNuxtRouteMiddleware(async (to) => {
  const auth = useGateKeeperAuth()
  const hydration = useGateKeeperHydration(auth)
  const allowed = await hydration.requireAuth({
    currentPath: to.fullPath,
    onRedirect: (path) => navigateTo(path),
  })
  return allowed ? undefined : false
})
```

`useGateKeeperHydration()` loads browser token storage, refreshes near-expired
tokens when a refresh token is available, optionally loads `/me`, and builds a
safe login redirect such as `/login?redirect=/account`. It is intentionally
Nuxt-light, so the same helper can be used in plain Vue route guards.

Nuxt server routes should still use `createGateKeeperVerifier` from
`gatekeeper-js`, not the browser token store.

Install-owner provider setup can use the same composable access token:
`oauthProvidersAdmin()`, `createOAuthProvider()`, `updateOAuthProvider()`, and
`deleteOAuthProvider()`. Public login screens should keep using
`oauthProviders()` and `startOAuthProvider()`.

Remaining SDK work: more server-framework examples and deeper component
coverage for provider/admin setup screens.
