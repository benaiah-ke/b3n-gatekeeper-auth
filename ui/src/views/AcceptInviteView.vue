<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api } from '@/services/api'

const route = useRoute()
const router = useRouter()
const email = ref('')
const displayName = ref('')
const password = ref('')
const totpCode = ref('')
const recoveryCode = ref('')
const error = ref('')
const loading = ref(false)

const token = computed(() => {
  const value = Array.isArray(route.query.token) ? route.query.token[0] : route.query.token
  return typeof value === 'string' ? value : ''
})

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.acceptInvitation(
      email.value,
      password.value,
      token.value,
      displayName.value,
      totpCode.value,
      recoveryCode.value,
    )
    router.push('/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not accept invitation'
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
          <div class="auth-wordmark" aria-label="GateKeeper">
            <span>GateKeeper</span>
          </div>
          <p class="mono-label mt-12">Invitation</p>
          <h2 class="mt-3 max-w-lg font-serif text-5xl leading-[0.98] sm:text-6xl">Join the control plane.</h2>
          <p class="mt-5 max-w-md text-sm leading-6 text-muted">
            Accept a scoped organization invitation and continue with the same central GateKeeper account.
          </p>
        </div>

        <ol class="setup-list">
          <li class="setup-step">
            <span class="setup-step-number">01</span>
            <span><span class="setup-step-title">Verify invite</span> The token binds the requested email, org, and role.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">02</span>
            <span><span class="setup-step-title">Create or confirm account</span> Existing accounts use their current password.</span>
          </li>
          <li class="setup-step">
            <span class="setup-step-number">03</span>
            <span><span class="setup-step-title">Start with scoped access</span> The accepted role appears immediately in sessions.</span>
          </li>
        </ol>
      </aside>

      <form class="auth-card" @submit.prevent="submit">
        <p class="mono-label">GateKeeper</p>
        <h1 class="mt-3 font-serif text-4xl leading-none">Accept invite</h1>
        <p class="mt-3 text-sm leading-6 text-muted">Use the email address that received the invitation.</p>

        <div class="mt-7 grid gap-4">
          <label class="auth-field">
            Email
            <input v-model="email" class="input" type="email" placeholder="you@example.com" autocomplete="email" required />
          </label>
          <label class="auth-field">
            Name
            <input v-model="displayName" class="input" placeholder="Optional for new accounts" autocomplete="name" />
          </label>
          <label class="auth-field">
            Password
            <input
              v-model="password"
              class="input"
              type="password"
              autocomplete="current-password"
              minlength="12"
              required
            />
          </label>
          <label class="auth-field">
            Authenticator code
            <input
              v-model="totpCode"
              class="input font-mono"
              inputmode="numeric"
              autocomplete="one-time-code"
              placeholder="Optional unless 2FA is enabled"
            />
          </label>
          <label class="auth-field">
            Recovery code
            <input
              v-model="recoveryCode"
              class="input font-mono"
              autocomplete="one-time-code"
              placeholder="Optional backup code"
            />
          </label>
          <p v-if="!token" class="auth-alert" role="alert">Invitation token missing.</p>
          <p v-if="error" class="auth-alert" role="alert">{{ error }}</p>
          <button class="btn-primary w-full" :disabled="loading || !token">
            {{ loading ? 'Accepting invite' : 'Accept invite' }}
          </button>
        </div>

        <RouterLink to="/login" class="mt-5 block text-sm text-muted hover:text-fg">Sign in instead</RouterLink>
      </form>
    </div>
  </section>
</template>
