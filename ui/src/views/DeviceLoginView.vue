<script setup lang="ts">
import { AlertTriangle, CheckCircle2, KeyRound, RefreshCw, ShieldCheck, Terminal } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api } from '@/services/api'

const route = useRoute()
const userCode = ref('')
const totpCode = ref('')
const recoveryCode = ref('')
const status = ref('')
const error = ref('')
const loading = ref(false)

const approved = computed(() => status.value === 'approved')
const statusLabel = computed(() => {
  if (approved.value) {
    return 'approved'
  }
  if (error.value) {
    return 'needs attention'
  }
  return 'pending approval'
})
const errorTitle = computed(() => {
  if (!error.value) {
    return ''
  }
  if (error.value.includes('not found')) {
    return 'Code expired or already used'
  }
  if (error.value.includes('MFA required') || error.value.includes('TOTP code required')) {
    return 'Authenticator code required'
  }
  return 'Approval failed'
})
const errorDetail = computed(() => {
  if (!error.value) {
    return ''
  }
  if (error.value.includes('not found')) {
    return 'Start a new CLI login and approve the new device code.'
  }
  if (error.value.includes('MFA required') || error.value.includes('TOTP code required')) {
    return 'Enter an authenticator code or recovery code, then approve again.'
  }
  return error.value
})

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

function resetApproval() {
  status.value = ''
  error.value = ''
  totpCode.value = ''
  recoveryCode.value = ''
}
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-10">
    <form class="panel w-full max-w-2xl p-6 sm:p-8" @submit.prevent="approve">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="mono-label">CLI</p>
          <h1 class="mt-3 text-2xl font-semibold leading-tight sm:text-3xl">Device login</h1>
        </div>
        <span
          class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
          :class="approved ? 'border-green/40 bg-green/10 text-green' : error ? 'border-red/40 bg-red/10 text-red' : 'border-border bg-surface text-muted'"
        >
          <CheckCircle2 v-if="approved" class="h-4 w-4" aria-hidden="true" />
          <AlertTriangle v-else-if="error" class="h-4 w-4" aria-hidden="true" />
          <Terminal v-else class="h-4 w-4" aria-hidden="true" />
          {{ statusLabel }}
        </span>
      </div>

      <div class="mt-8 grid gap-5">
        <section
          v-if="approved"
          class="grid gap-4 rounded-md border border-green/35 bg-green/10 p-4"
          aria-live="polite"
        >
          <div class="flex gap-3">
            <span class="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-green/40 bg-bg text-green">
              <CheckCircle2 class="h-5 w-5" aria-hidden="true" />
            </span>
            <div>
              <h2 class="text-lg font-semibold text-green">Device approved</h2>
              <p class="mt-1 text-sm leading-6 text-muted">
                Return to your terminal to finish the CLI sign-in. This browser tab can be closed.
              </p>
            </div>
          </div>
          <div class="rounded-md border border-border bg-bg p-3">
            <p class="font-mono text-xs text-muted">approved code</p>
            <p class="mt-2 break-all font-mono text-lg text-fg">{{ userCode }}</p>
          </div>
        </section>

        <template v-else>
          <label class="grid gap-2 text-sm text-muted">
            User code
            <input v-model="userCode" class="input font-mono uppercase" placeholder="Q4H7K2XP" required />
          </label>

          <section class="grid gap-4 rounded-md border border-border bg-surface p-4">
            <div class="flex gap-3">
              <span class="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-border bg-bg text-accent">
                <ShieldCheck class="h-4 w-4" aria-hidden="true" />
              </span>
              <div>
                <h2 class="font-semibold">Verify this approval</h2>
                <p class="mt-1 text-sm leading-6 text-muted">
                  Required for CLI clients protected by GateKeeper MFA policy.
                </p>
              </div>
            </div>
            <div class="grid gap-3 sm:grid-cols-2">
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
          </section>

          <button class="btn-primary gap-2" :disabled="loading">
            <KeyRound class="h-4 w-4" aria-hidden="true" />
            {{ loading ? 'Approving' : 'Approve device' }}
          </button>

          <section
            v-if="error"
            class="grid gap-3 rounded-md border border-red/40 bg-red/10 p-4"
            aria-live="polite"
          >
            <div class="flex gap-3">
              <AlertTriangle class="mt-0.5 h-5 w-5 shrink-0 text-red" aria-hidden="true" />
              <div>
                <h2 class="font-semibold text-red">{{ errorTitle }}</h2>
                <p class="mt-1 text-sm leading-6 text-muted">{{ errorDetail }}</p>
              </div>
            </div>
            <button type="button" class="btn-secondary w-fit min-h-9 gap-2 px-3 text-xs" @click="resetApproval">
              <RefreshCw class="h-3.5 w-3.5" aria-hidden="true" />
              Try again
            </button>
          </section>
        </template>
      </div>
    </form>
  </section>
</template>
