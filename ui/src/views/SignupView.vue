<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api } from '@/services/api'

const router = useRouter()
const route = useRoute()
const email = ref('')
const displayName = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await api.signup(email.value, password.value, displayName.value)
    router.push(String(route.query.redirect || '/account'))
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Sign up failed'
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
      <h1 class="mt-3 font-serif text-4xl">Create account</h1>
      <div class="mt-8 grid gap-4">
        <input v-model="displayName" class="input" placeholder="Name" autocomplete="name" />
        <input v-model="email" class="input" type="email" placeholder="Email" autocomplete="email" required />
        <input v-model="password" class="input" type="password" placeholder="Password" autocomplete="new-password" required />
        <p v-if="error" class="rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
        <button class="btn-primary w-full" :disabled="loading">{{ loading ? 'Creating' : 'Create account' }}</button>
      </div>
      <RouterLink to="/login" class="mt-6 block text-sm text-muted hover:text-fg">Sign in instead</RouterLink>
    </form>
  </section>
</template>
