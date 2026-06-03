<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api } from '@/services/api'

const router = useRouter()
const route = useRoute()
const email = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.login(email.value, password.value)
    router.push(String(route.query.redirect || '/account'))
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Sign in failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-md p-6" @submit.prevent="submit">
      <img src="/brand/b3n-logo-dark.png" class="mb-8 h-10" alt="B3n" />
      <p class="mono-label">GateKeeper</p>
      <h1 class="mt-3 font-serif text-4xl">Sign in</h1>
      <div class="mt-8 grid gap-4">
        <label class="grid gap-2 text-sm text-muted">
          Email
          <input v-model="email" class="input" type="email" autocomplete="email" required />
        </label>
        <label class="grid gap-2 text-sm text-muted">
          Password
          <input v-model="password" class="input" type="password" autocomplete="current-password" required />
        </label>
        <p v-if="error" class="rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
        <button class="btn-primary w-full" :disabled="loading">{{ loading ? 'Signing in' : 'Sign in' }}</button>
      </div>
      <div class="mt-6 flex justify-between text-sm text-muted">
        <RouterLink to="/signup" class="hover:text-fg">Create account</RouterLink>
        <RouterLink to="/reset-password" class="hover:text-fg">Reset password</RouterLink>
      </div>
    </form>
  </section>
</template>
