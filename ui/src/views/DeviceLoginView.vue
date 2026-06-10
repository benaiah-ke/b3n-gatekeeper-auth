<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api } from '@/services/api'

const route = useRoute()
const userCode = ref('')
const totpCode = ref('')
const recoveryCode = ref('')
const status = ref('')
const error = ref('')
const loading = ref(false)

onMounted(() => {
  userCode.value = String(route.query.user_code || '')
})

async function approve() {
  error.value = ''
  status.value = ''
  loading.value = true
  try {
    const result = await api.approveDevice(userCode.value, true, undefined, totpCode.value, recoveryCode.value)
    status.value = result.status
    totpCode.value = ''
    recoveryCode.value = ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Device approval failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-md p-6" @submit.prevent="approve">
      <p class="mono-label">CLI</p>
      <h1 class="mt-3 font-serif text-4xl">Device login</h1>
      <div class="mt-8 grid gap-4">
        <input v-model="userCode" class="input font-mono uppercase" placeholder="User code" required />
        <div class="grid gap-3 rounded-md border border-border bg-surface p-3">
          <label class="grid gap-2 text-sm text-muted">
            Authenticator code
            <input
              v-model="totpCode"
              class="input font-mono"
              inputmode="numeric"
              autocomplete="one-time-code"
              placeholder="123456"
            />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Recovery code
            <input
              v-model="recoveryCode"
              class="input font-mono"
              autocomplete="one-time-code"
              placeholder="Optional backup code"
            />
          </label>
        </div>
        <button class="btn-primary" :disabled="loading">{{ loading ? 'Approving' : 'Approve device' }}</button>
        <p v-if="status" class="text-sm text-green">{{ status }}</p>
        <p v-if="error" class="text-sm text-red">{{ error }}</p>
      </div>
    </form>
  </section>
</template>
