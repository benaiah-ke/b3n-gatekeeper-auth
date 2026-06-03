<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { ApiToken } from '@/types'

const tokens = ref<ApiToken[]>([])
const createdToken = ref('')
const name = ref('CLI token')
const scopes = ref('auth:read token:*')

async function load() {
  tokens.value = await api.tokens()
}

async function create() {
  const token = await api.createToken({
    name: name.value,
    token_type: 'personal',
    scopes: scopes.value.split(/\s+/).filter(Boolean),
    audiences: ['gatekeeper-api'],
  })
  createdToken.value = token.token || ''
  await load()
}

async function revoke(id: string) {
  await api.revokeToken(id)
  await load()
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Tokens</p>
    <h1 class="mt-3 font-serif text-5xl">Token management</h1>
    <form class="panel mt-8 grid gap-3 p-5 md:grid-cols-[1fr_1fr_auto]" @submit.prevent="create">
      <input v-model="name" class="input" placeholder="Name" />
      <input v-model="scopes" class="input font-mono" placeholder="Scopes" />
      <button class="btn-primary">Create</button>
    </form>
    <p v-if="createdToken" class="panel mt-4 break-all p-4 font-mono text-sm text-green">{{ createdToken }}</p>
    <div class="mt-6 grid gap-3">
      <article v-for="token in tokens" :key="token.id" class="panel flex items-center justify-between gap-4 p-4">
        <div>
          <h2 class="font-semibold">{{ token.name }}</h2>
          <p class="font-mono text-xs text-muted">{{ token.token_type }} / {{ token.token_hint }}</p>
        </div>
        <button class="btn-secondary text-sm" @click="revoke(token.id)">Revoke</button>
      </article>
    </div>
  </section>
</template>

