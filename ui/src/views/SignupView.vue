<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api } from '@/services/api'

const router = useRouter()
const route = useRoute()
const email = ref('')
const displayName = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const redirectTarget = computed(() => {
  const value = Array.isArray(route.query.redirect) ? route.query.redirect[0] : route.query.redirect
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : ''
})
const loginRoute = computed(() =>
  redirectTarget.value ? { path: '/login', query: { redirect: redirectTarget.value } } : '/login',
)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.signup(email.value, password.value, displayName.value)
    router.push(redirectTarget.value || '/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Sign up failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="auth-page">
    <div class="auth-shell">
      <aside class="auth-copy">
        <div>
          <div class="auth-wordmark" aria-label="B3n GateKeeper">
            <span>b3n</span>
            <span class="text-accent">/</span>
            <span>GateKeeper</span>
          </div>
          <p class="mono-label mt-12">Self-host setup</p>
          <h2 class="mt-3 max-w-lg font-serif text-5xl leading-[0.98] sm:text-6xl">Own the auth layer.</h2>
          <p class="mt-5 max-w-md text-sm leading-6 text-muted">
            Create the first owner, then connect B3n tools through OAuth clients, scoped tokens, and
            resource-bound sessions.
          </p>
        </div>

        <ol class="setup-list">
          <li class="setup-step">
            <span class="setup-step-number">01</span>
            <span><span class="setup-step-title">Create the first owner</span> This account manages the initial org.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">02</span>
            <span><span class="setup-step-title">Register control-plane clients</span> Add Sentinel, Knowhere, and CLI callbacks.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">03</span>
            <span><span class="setup-step-title">Issue scoped tokens</span> Use audiences and scopes before service cutover.</span>
          </li>
        </ol>
      </aside>

      <form class="auth-card" @submit.prevent="submit">
        <p class="mono-label">GateKeeper</p>
        <h1 class="mt-3 font-serif text-4xl leading-none">Create account</h1>
        <p class="mt-3 text-sm leading-6 text-muted">The first account becomes the owner for this install.</p>

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
