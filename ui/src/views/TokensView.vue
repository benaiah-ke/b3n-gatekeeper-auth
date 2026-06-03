<script setup lang="ts">
import { Check, Copy } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { ApiToken } from '@/types'

const tokens = ref<ApiToken[]>([])
const createdToken = ref('')
const copied = ref(false)
const name = ref('CLI token')
const scopes = ref('auth:read token:*')
const loading = ref(true)
const saving = ref(false)
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    tokens.value = await api.tokens()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load tokens'
  } finally {
    loading.value = false
  }
}

async function create() {
  saving.value = true
  error.value = ''
  copied.value = false
  try {
    const token = await api.createToken({
      name: name.value,
      token_type: 'personal',
      scopes: scopes.value.split(/\s+/).filter(Boolean),
      audiences: ['gatekeeper-api'],
    })
    createdToken.value = token.token || ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create token'
  } finally {
    saving.value = false
  }
}

async function revoke(id: string) {
  error.value = ''
  try {
    await api.revokeToken(id)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke token'
  }
}

async function copyCreatedToken() {
  await navigator.clipboard.writeText(createdToken.value)
  copied.value = true
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Tokens</p>
    <h1 class="mt-3 font-serif text-5xl">Token management</h1>
    <p class="mt-3 max-w-2xl text-sm text-muted">
      Create personal and service credentials with explicit scopes and auditable revocation.
    </p>
    <form class="panel mt-8 grid gap-3 p-5 md:grid-cols-[1fr_1fr_auto]" @submit.prevent="create">
      <input v-model="name" class="input" placeholder="Name" />
      <input v-model="scopes" class="input font-mono" placeholder="Scopes" />
      <button class="btn-primary" :disabled="saving">{{ saving ? 'Creating' : 'Create' }}</button>
    </form>
    <article v-if="createdToken" class="panel mt-4 grid gap-3 p-4 md:grid-cols-[1fr_auto]">
      <p class="break-all font-mono text-sm text-green">{{ createdToken }}</p>
      <button type="button" class="btn-secondary gap-2 text-sm" @click="copyCreatedToken">
        <Check v-if="copied" class="h-4 w-4" aria-hidden="true" />
        <Copy v-else class="h-4 w-4" aria-hidden="true" />
        {{ copied ? 'Copied' : 'Copy' }}
      </button>
    </article>
    <p v-if="error" class="mt-4 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
    <div class="mt-6 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading tokens...</article>
      <article v-else-if="!tokens.length" class="panel p-4 text-sm text-muted">No tokens created yet.</article>
      <template v-else>
        <article v-for="token in tokens" :key="token.id" class="panel flex items-center justify-between gap-4 p-4">
          <div>
            <h2 class="font-semibold">{{ token.name }}</h2>
            <p class="font-mono text-xs text-muted">
              {{ token.token_type }} / {{ token.token_hint }} / {{ token.scopes.join(' ') }}
            </p>
          </div>
          <button class="btn-secondary text-sm" :disabled="Boolean(token.revoked_at)" @click="revoke(token.id)">
            {{ token.revoked_at ? 'Revoked' : 'Revoke' }}
          </button>
        </article>
      </template>
    </div>
  </section>
</template>
