<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuditEvent } from '@/types'

const events = ref<AuditEvent[]>([])
const loading = ref(true)
const error = ref('')

onMounted(async () => {
  try {
    events.value = await api.audit()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load audit events'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Audit</p>
    <h1 class="mt-3 font-serif text-5xl">Security events</h1>
    <p class="mt-3 max-w-2xl text-sm text-muted">
      Immutable operator, token, client, and session events written by the auth core.
    </p>
    <p v-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading audit events...</article>
      <article v-else-if="!events.length" class="panel p-4 text-sm text-muted">No audit events recorded yet.</article>
      <template v-else>
        <article v-for="event in events" :key="event.id" class="panel p-4">
          <div class="flex flex-wrap justify-between gap-3">
            <h2 class="font-semibold">{{ event.action }}</h2>
            <time class="font-mono text-xs text-muted">{{ new Date(event.created_at).toLocaleString() }}</time>
          </div>
          <p class="mt-2 break-all font-mono text-xs text-muted">{{ event.target_type }} / {{ event.target_id }}</p>
          <pre class="mt-3 overflow-x-auto rounded-md bg-bg p-3 text-xs text-muted">{{ JSON.stringify(event.details, null, 2) }}</pre>
        </article>
      </template>
    </div>
  </section>
</template>
