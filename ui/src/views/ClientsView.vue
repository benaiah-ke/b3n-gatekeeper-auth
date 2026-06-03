<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuthClient } from '@/types'

const clients = ref<AuthClient[]>([])
const name = ref('Sentinel')
const redirect = ref('https://sentinel.b3n.in/callback')
const audience = ref('sentinel-api')
const scopes = ref('auth:read token:* mcp:*')

async function load() {
  clients.value = await api.clients()
}

async function create() {
  await api.createClient({
    name: name.value,
    public: true,
    redirect_uris: [redirect.value],
    allowed_origins: [new URL(redirect.value).origin],
    audiences: [audience.value],
    scopes: scopes.value.split(/\s+/).filter(Boolean),
  })
  await load()
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">OAuth</p>
    <h1 class="mt-3 font-serif text-5xl">Auth clients</h1>
    <form class="panel mt-8 grid gap-3 p-5" @submit.prevent="create">
      <div class="grid gap-3 md:grid-cols-3">
        <input v-model="name" class="input" placeholder="Name" />
        <input v-model="redirect" class="input" placeholder="Redirect URI" />
        <input v-model="audience" class="input" placeholder="Audience" />
      </div>
      <input v-model="scopes" class="input font-mono" placeholder="Scopes" />
      <button class="btn-primary justify-self-start">Create client</button>
    </form>
    <div class="mt-6 grid gap-3">
      <article v-for="client in clients" :key="client.id" class="panel p-4">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 class="font-semibold">{{ client.name }}</h2>
            <p class="font-mono text-xs text-muted">{{ client.client_id }}</p>
          </div>
          <span class="font-mono text-xs text-muted">{{ client.public ? 'public' : 'confidential' }}</span>
        </div>
        <p class="mt-3 break-all font-mono text-xs text-muted">{{ client.redirect_uris.join(', ') }}</p>
      </article>
    </div>
  </section>
</template>

