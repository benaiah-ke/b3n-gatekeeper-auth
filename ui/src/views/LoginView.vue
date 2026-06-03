<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api } from '@/services/api'

const router = useRouter()
const route = useRoute()
const email = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const redirectTarget = computed(() => {
  const value = Array.isArray(route.query.redirect) ? route.query.redirect[0] : route.query.redirect
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : ''
})
const signupRoute = computed(() =>
  redirectTarget.value ? { path: '/signup', query: { redirect: redirectTarget.value } } : '/signup',
)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.login(email.value, password.value)
    router.push(redirectTarget.value || '/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Sign in failed'
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
          <p class="mono-label mt-12">Control plane auth</p>
          <h2 class="mt-3 max-w-lg font-serif text-5xl leading-[0.98] sm:text-6xl">Sign in to the trust boundary.</h2>
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
            <span><span class="setup-step-title">Connect applications</span> Register redirect URIs for Sentinel, Knowhere, and local tools.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">03</span>
            <span><span class="setup-step-title">Verify runtime auth</span> Check discovery, JWKS, and scoped API tokens before cutover.</span>
          </li>
        </ol>
      </aside>

      <form class="auth-card" @submit.prevent="submit">
        <p class="mono-label">GateKeeper</p>
        <h1 class="mt-3 font-serif text-4xl leading-none">Sign in</h1>
        <p class="mt-3 text-sm leading-6 text-muted">Manage B3n auth from your self-hosted control plane.</p>

        <div class="mt-7 grid gap-4">
          <label class="auth-field">
            Email
            <input v-model="email" class="input" type="email" placeholder="you@example.com" autocomplete="email" required />
          </label>
          <label class="auth-field">
            Password
            <input v-model="password" class="input" type="password" autocomplete="current-password" required />
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
