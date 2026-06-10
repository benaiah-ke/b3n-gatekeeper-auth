<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '@/services/api'

const router = useRouter()
const email = ref('')
const code = ref('')
const message = ref('')
const error = ref('')
const loading = ref(false)
const sending = ref(false)

async function send() {
  error.value = ''
  message.value = ''
  sending.value = true
  try {
    await api.requestCode(email.value, 'verify_email')
    message.value = 'Code sent'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not send code'
  } finally {
    sending.value = false
  }
}

async function verify() {
  error.value = ''
  loading.value = true
  try {
    await api.verifyCode(email.value, code.value, 'verify_email')
    router.push('/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Verification failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-md p-6" @submit.prevent="verify">
      <p class="mono-label">Email</p>
      <h1 class="mt-3 text-2xl font-semibold leading-tight">Verify email</h1>
      <div class="mt-8 grid gap-4">
        <input v-model="email" class="input" type="email" placeholder="Email" required />
        <button type="button" class="btn-secondary" :disabled="sending" @click="send">
          {{ sending ? 'Sending' : 'Send code' }}
        </button>
        <input v-model="code" class="input font-mono uppercase" placeholder="Code" required />
        <p v-if="message" class="text-sm text-green">{{ message }}</p>
        <p v-if="error" class="text-sm text-red">{{ error }}</p>
        <button class="btn-primary" :disabled="loading">{{ loading ? 'Verifying' : 'Verify' }}</button>
      </div>
    </form>
  </section>
</template>
