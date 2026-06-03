<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Session } from '@/types'

const sessions = ref<Session[]>([])
const loading = ref(true)
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    sessions.value = await api.sessions()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load sessions'
  } finally {
    loading.value = false
  }
}

async function revoke(id: string) {
  error.value = ''
  try {
    await api.revokeSession(id)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke session'
  }
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Sessions</p>
    <h1 class="mt-3 font-serif text-5xl">Active sessions</h1>
    <p class="mt-3 max-w-2xl text-sm text-muted">
      Review browser and API sessions, then revoke anything that should no longer be trusted.
    </p>
    <p v-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading sessions...</article>
      <article v-else-if="!sessions.length" class="panel p-4 text-sm text-muted">No sessions found.</article>
      <template v-else>
        <article v-for="session in sessions" :key="session.id" class="panel flex items-center justify-between gap-4 p-4">
          <div>
            <h2 class="break-all font-mono text-sm">{{ session.id }}</h2>
            <p class="mt-1 text-sm text-muted">
              {{ session.ip_address || 'unknown ip' }} / expires {{ new Date(session.expires_at).toLocaleString() }}
            </p>
          </div>
          <button class="btn-secondary text-sm" :disabled="Boolean(session.revoked_at)" @click="revoke(session.id)">
            {{ session.revoked_at ? 'Revoked' : 'Revoke' }}
          </button>
        </article>
      </template>
    </div>
  </section>
</template>
