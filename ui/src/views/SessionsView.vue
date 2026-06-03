<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Session } from '@/types'

const sessions = ref<Session[]>([])

async function load() {
  sessions.value = await api.sessions()
}

async function revoke(id: string) {
  await api.revokeSession(id)
  await load()
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Sessions</p>
    <h1 class="mt-3 font-serif text-5xl">Active sessions</h1>
    <div class="mt-8 grid gap-3">
      <article v-for="session in sessions" :key="session.id" class="panel flex items-center justify-between gap-4 p-4">
        <div>
          <h2 class="font-mono text-sm">{{ session.id }}</h2>
          <p class="mt-1 text-sm text-muted">{{ session.ip_address || 'unknown ip' }}</p>
        </div>
        <button class="btn-secondary text-sm" :disabled="Boolean(session.revoked_at)" @click="revoke(session.id)">
          {{ session.revoked_at ? 'Revoked' : 'Revoke' }}
        </button>
      </article>
    </div>
  </section>
</template>
