<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, gatekeeperApiUrl } from '@/services/api'
import { safeInternalRedirect } from '@/services/redirects'
import type { OAuthProvider } from '@/types'

const router = useRouter()
const route = useRoute()
const email = ref('')
const password = ref('')
const totpCode = ref('')
const recoveryCode = ref('')
const providers = ref<OAuthProvider[]>([])
const error = ref('')
const loading = ref(false)
const providerLoading = ref('')
const mfaChallenge = ref(false)

const redirectTarget = computed(() => {
  return safeInternalRedirect(route.query.redirect)
})
const isStepUp = computed(() => route.query.step_up === 'mfa')
const oauthLoginContext = computed(() => {
  if (!redirectTarget.value.startsWith('/oauth/authorize')) {
    return {}
  }
  try {
    const authorize = new URL(redirectTarget.value, window.location.origin)
    return {
      clientId: authorize.searchParams.get('client_id'),
      scope: authorize.searchParams.get('scope'),
      audience: authorize.searchParams.get('audience'),
    }
  } catch {
    return {}
  }
})
const showMfaFields = computed(() => isStepUp.value || mfaChallenge.value || Boolean(totpCode.value || recoveryCode.value))
const signupRoute = computed(() =>
  redirectTarget.value ? { path: '/signup', query: { redirect: redirectTarget.value } } : '/signup',
)
const configuredProviders = computed(() => providers.value.filter((provider) => provider.configured))

async function loadProviders() {
  try {
    providers.value = await api.oauthProviders()
  } catch {
    providers.value = []
  }
}

async function startProvider(provider: OAuthProvider) {
  error.value = ''
  providerLoading.value = provider.id
  try {
    const started = await api.startOAuthProvider(provider.id, redirectTarget.value || undefined)
    window.location.assign(started.authorization_url)
  } catch (err) {
    error.value = err instanceof Error ? err.message : `Could not start ${provider.name} sign in`
  } finally {
    providerLoading.value = ''
  }
}

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.login(email.value, password.value, totpCode.value, recoveryCode.value, oauthLoginContext.value)
    if (redirectTarget.value.startsWith('/oauth/')) {
      window.location.assign(gatekeeperApiUrl(redirectTarget.value))
      return
    }
    router.push(redirectTarget.value || '/account')
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Sign in failed'
    if (message.includes('TOTP code required') || message.includes('MFA required')) {
      mfaChallenge.value = true
      error.value = 'Enter an authenticator code or recovery code to finish this sign in.'
    } else {
      error.value = message
    }
  } finally {
    loading.value = false
  }
}

onMounted(loadProviders)
</script>

<template>
  <section class="auth-page">
    <div class="auth-shell">
      <aside class="auth-copy">
        <div>
          <div class="auth-wordmark" aria-label="GateKeeper">
            <span>GateKeeper</span>
          </div>
          <p class="mono-label mt-12">Control plane auth</p>
          <h2 class="mt-3 max-w-lg text-3xl font-semibold leading-tight sm:text-4xl">Sign in to the trust boundary.</h2>
          <p class="mt-5 max-w-md text-sm leading-6 text-muted">
            Use an owner, admin, or operator account to manage sessions, clients, project tokens, and audit events.
          </p>
        </div>

        <ol class="setup-list">
          <li class="setup-step">
            <span class="setup-step-number">01</span>
            <span><span class="setup-step-title">First install?</span> Create the first owner account before registering clients.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">02</span>
            <span><span class="setup-step-title">Connect applications</span> Register redirect URIs for web apps, APIs, and local tools.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">03</span>
            <span><span class="setup-step-title">Verify runtime auth</span> Check discovery, JWKS, and scoped API tokens before cutover.</span>
          </li>
        </ol>
      </aside>

      <form class="auth-card" @submit.prevent="submit">
        <p class="mono-label">GateKeeper</p>
        <h1 class="mt-3 text-2xl font-semibold leading-tight">{{ isStepUp ? 'Verify sign in' : 'Sign in' }}</h1>
        <p class="mt-3 text-sm leading-6 text-muted">
          {{ isStepUp ? 'This application requires a fresh MFA-backed GateKeeper session.' : 'Manage auth from your self-hosted control plane.' }}
        </p>

        <div v-if="configuredProviders.length" class="mt-7 grid gap-2">
          <button
            v-for="provider in configuredProviders"
            :key="provider.id"
            type="button"
            class="btn-secondary w-full text-sm"
            :disabled="loading || Boolean(providerLoading)"
            @click="startProvider(provider)"
          >
            {{ providerLoading === provider.id ? 'Connecting' : `Continue with ${provider.name}` }}
          </button>
        </div>

        <div class="mt-7 grid gap-4">
          <label class="auth-field">
            Email
            <input v-model="email" class="input" type="email" placeholder="you@example.com" autocomplete="email" required />
          </label>
          <label class="auth-field">
            Password
            <input v-model="password" class="input" type="password" autocomplete="current-password" required />
          </label>
          <div
            v-if="showMfaFields"
            class="rounded-md border border-border bg-surface p-3"
          >
            <p class="text-sm font-semibold text-fg">Additional verification</p>
            <p class="mt-1 text-xs leading-5 text-muted">
              Use a current authenticator code, or a recovery code if the authenticator is unavailable.
            </p>
          </div>
          <label v-if="showMfaFields" class="auth-field">
            Authenticator code
            <input
              v-model="totpCode"
              class="input font-mono"
              inputmode="numeric"
              autocomplete="one-time-code"
              placeholder="Optional unless 2FA is enabled"
            />
          </label>
          <label v-if="showMfaFields" class="auth-field">
            Recovery code
            <input
              v-model="recoveryCode"
              class="input font-mono"
              autocomplete="one-time-code"
              placeholder="Optional backup code"
            />
          </label>
          <p v-if="error" class="auth-alert" role="alert">{{ error }}</p>
          <button class="btn-primary w-full" :disabled="loading">{{ loading ? 'Signing in' : 'Sign in' }}</button>
        </div>

        <div class="mt-5 flex flex-wrap justify-between gap-3 text-sm text-muted">
          <RouterLink :to="signupRoute" class="hover:text-fg">Create account</RouterLink>
          <RouterLink to="/reset-password" class="hover:text-fg">Reset password</RouterLink>
        </div>
      </form>
    </div>
  </section>
</template>
