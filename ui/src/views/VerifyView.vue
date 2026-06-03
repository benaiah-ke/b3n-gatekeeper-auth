<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '@/services/api'

const router = useRouter()
const email = ref('')
const code = ref('')
const message = ref('')
const error = ref('')

async function send() {
  error.value = ''
  await api.requestCode(email.value, 'verify_email')
  message.value = 'Code sent'
}

async function verify() {
  error.value = ''
  try {
    await api.verifyCode(email.value, code.value, 'verify_email')
    router.push('/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Verification failed'
  }
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-md p-6" @submit.prevent="verify">
      <p class="mono-label">Email</p>
      <h1 class="mt-3 font-serif text-4xl">Verify email</h1>
      <div class="mt-8 grid gap-4">
        <input v-model="email" class="input" type="email" placeholder="Email" required />
        <button type="button" class="btn-secondary" @click="send">Send code</button>
        <input v-model="code" class="input font-mono uppercase" placeholder="Code" required />
        <p v-if="message" class="text-sm text-green">{{ message }}</p>
        <p v-if="error" class="text-sm text-red">{{ error }}</p>
        <button class="btn-primary">Verify</button>
      </div>
    </form>
  </section>
</template>

