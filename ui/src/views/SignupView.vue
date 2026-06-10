<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, gatekeeperApiUrl } from '@/services/api'
import { safeInternalRedirect } from '@/services/redirects'
import type { OAuthProvider } from '@/types'

const router = useRouter()
const route = useRoute()
const email = ref('')
const displayName = ref('')
const password = ref('')
const providers = ref<OAuthProvider[]>([])
const error = ref('')
const loading = ref(false)
const providerLoading = ref('')

const redirectTarget = computed(() => {
  return safeInternalRedirect(route.query.redirect)
})
const loginRoute = computed(() =>
  redirectTarget.value ? { path: '/login', query: { redirect: redirectTarget.value } } : '/login',
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
    error.value = err instanceof Error ? err.message : `Could not start ${provider.name} sign up`
  } finally {
    providerLoading.value = ''
  }
}

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.signup(email.value, password.value, displayName.value)
    if (redirectTarget.value.startsWith('/oauth/')) {
      window.location.assign(gatekeeperApiUrl(redirectTarget.value))
      return
    }
    router.push(redirectTarget.value || '/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Sign up failed'
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
          <p class="mono-label mt-12">Self-host setup</p>
          <h2 class="mt-3 max-w-lg text-3xl font-semibold leading-tight sm:text-4xl">Own the auth layer.</h2>
          <p class="mt-5 max-w-md text-sm leading-6 text-muted">
            Create the first owner, then connect products through OAuth clients, scoped tokens, and
            API-first sessions.
          </p>
        </div>

        <ol class="setup-list">
          <li class="setup-step">
            <span class="setup-step-number">01</span>
            <span><span class="setup-step-title">Create the first owner</span> This account manages the initial org.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">02</span>
            <span><span class="setup-step-title">Register clients</span> Add web, API, CLI, and MCP callbacks.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">03</span>
            <span><span class="setup-step-title">Issue scoped tokens</span> Use audiences and scopes before service cutover.</span>
          </li>
        </ol>
      </aside>

      <form class="auth-card" @submit.prevent="submit">
        <p class="mono-label">GateKeeper</p>
        <h1 class="mt-3 text-2xl font-semibold leading-tight">Create account</h1>
        <p class="mt-3 text-sm leading-6 text-muted">The first account becomes the owner for this install.</p>

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
            Name
            <input v-model="displayName" class="input" placeholder="Benaiah Wepundi" autocomplete="name" />
          </label>
          <label class="auth-field">
            Email
            <input v-model="email" class="input" type="email" placeholder="you@example.com" autocomplete="email" required />
          </label>
          <label class="auth-field">
            Password
            <input
              v-model="password"
              class="input"
              type="password"
              autocomplete="new-password"
              minlength="12"
              required
            />
          </label>
          <p v-if="error" class="auth-alert" role="alert">{{ error }}</p>
          <button class="btn-primary w-full" :disabled="loading">{{ loading ? 'Creating account' : 'Create account' }}</button>
        </div>

        <RouterLink :to="loginRoute" class="mt-5 block text-sm text-muted hover:text-fg">Sign in instead</RouterLink>
      </form>
    </div>
  </section>
</template>
