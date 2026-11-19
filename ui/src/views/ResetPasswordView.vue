<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'

const email = ref('')
const code = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const step = ref<'request' | 'confirm' | 'done'>('request')
const resetEnabled = ref(true)
const message = ref('')
const error = ref('')
const loading = ref(false)

onMounted(async () => {
  try {
    resetEnabled.value = (await api.authOptions()).password_reset
  } catch {
    resetEnabled.value = true
  }
})

async function requestCode() {
  loading.value = true
  message.value = ''
  error.value = ''
  try {
    await api.requestPasswordReset(email.value)
    message.value = 'If an account uses that email, we sent a code. It expires in 15 minutes.'
    step.value = 'confirm'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not send reset code'
  } finally {
    loading.value = false
  }
}

async function confirm() {
  error.value = ''
  if (newPassword.value.length < 12) {
    error.value = 'Use at least 12 characters for the new password.'
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    error.value = 'The two passwords do not match.'
    return
  }
  loading.value = true
  try {
    await api.confirmPasswordReset(email.value, code.value, newPassword.value)
    step.value = 'done'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not set the new password'
  } finally {
    loading.value = false
  }
}

function sendNewCode() {
  step.value = 'request'
  code.value = ''
  newPassword.value = ''
  confirmPassword.value = ''
  message.value = ''
  error.value = ''
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <div v-if="step === 'done'" class="panel w-full max-w-md p-6">
      <p class="mono-label">Account</p>
      <h1 class="mt-3 text-2xl font-semibold leading-tight">Password Changed</h1>
      <p class="mt-4 text-sm leading-6 text-muted" role="status">
        Your password is changed. Every other session was signed out.
      </p>
      <RouterLink to="/login" class="btn-primary mt-6 block text-center">Go to sign in</RouterLink>
    </div>

    <form v-else class="panel w-full max-w-md p-6" @submit.prevent="step === 'request' ? requestCode() : confirm()">
      <p class="mono-label">Account</p>
      <h1 class="mt-3 text-2xl font-semibold leading-tight">Reset Password</h1>
      <p v-if="!resetEnabled" class="mt-4 text-sm leading-6 text-muted" role="status">
        Email is not set up here, so we cannot send a reset code. Ask an admin to reset your password.
      </p>
      <div class="mt-8 grid gap-4">
        <label class="auth-field">
          Email
          <input
            v-model="email"
            class="input"
            type="email"
            placeholder="you@example.com"
            autocomplete="email"
            :readonly="step === 'confirm'"
            required
          />
        </label>
        <template v-if="step === 'request'">
          <button class="btn-primary" :disabled="loading || !resetEnabled">{{ loading ? 'Sending' : 'Send reset code' }}</button>
        </template>
        <template v-else>
          <p v-if="message" class="text-sm text-green" role="status">{{ message }}</p>
          <label class="auth-field">
            Reset code
            <input v-model="code" class="input font-mono" autocapitalize="characters" spellcheck="false" autocomplete="one-time-code" required />
          </label>
          <label class="auth-field">
            New password
            <input v-model="newPassword" class="input" type="password" autocomplete="new-password" minlength="12" required />
          </label>
          <label class="auth-field">
            Confirm new password
            <input v-model="confirmPassword" class="input" type="password" autocomplete="new-password" minlength="12" required />
          </label>
          <button class="btn-primary" :disabled="loading">{{ loading ? 'Saving' : 'Set new password' }}</button>
          <button type="button" class="btn-secondary text-sm" :disabled="loading" @click="sendNewCode">Send a new code</button>
        </template>
        <p v-if="error" class="auth-alert" role="alert">{{ error }}</p>
      </div>
      <RouterLink to="/login" class="mt-6 block text-sm text-muted hover:text-fg">Back to sign in</RouterLink>
    </form>
  </section>
</template>
