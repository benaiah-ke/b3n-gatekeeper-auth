<script setup lang="ts">
import { ref } from 'vue'

import { api } from '@/services/api'

const email = ref('')
const message = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  loading.value = true
  message.value = ''
  error.value = ''
  try {
    await api.requestCode(email.value, 'reset_password')
    message.value = 'Code sent'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not send reset code'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-md p-6" @submit.prevent="submit">
      <p class="mono-label">Account</p>
      <h1 class="mt-3 text-2xl font-semibold leading-tight">Reset password</h1>
      <div class="mt-8 grid gap-4">
        <input v-model="email" class="input" type="email" placeholder="Email" required />
        <button class="btn-primary" :disabled="loading">{{ loading ? 'Sending' : 'Send reset code' }}</button>
        <p v-if="message" class="text-sm text-green">{{ message }}</p>
        <p v-if="error" class="text-sm text-red">{{ error }}</p>
      </div>
      <RouterLink to="/login" class="mt-6 block text-sm text-muted hover:text-fg">Back to sign in</RouterLink>
    </form>
  </section>
</template>
