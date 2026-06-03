<script setup lang="ts">
import { ref } from 'vue'

import { api } from '@/services/api'

const email = ref('')
const message = ref('')

async function submit() {
  await api.requestCode(email.value, 'reset_password')
  message.value = 'Code sent'
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-md p-6" @submit.prevent="submit">
      <p class="mono-label">Account</p>
      <h1 class="mt-3 font-serif text-4xl">Reset password</h1>
      <div class="mt-8 grid gap-4">
        <input v-model="email" class="input" type="email" placeholder="Email" required />
        <button class="btn-primary">Send reset code</button>
        <p v-if="message" class="text-sm text-green">{{ message }}</p>
      </div>
      <RouterLink to="/login" class="mt-6 block text-sm text-muted hover:text-fg">Back to sign in</RouterLink>
    </form>
  </section>
</template>

