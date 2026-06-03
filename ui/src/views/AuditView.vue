<script setup lang="ts">
import { Filter, Search } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuditEvent } from '@/types'

const events = ref<AuditEvent[]>([])
const loading = ref(true)
const error = ref('')
const action = ref('')
const actorUserId = ref('')
const orgId = ref('')
const targetType = ref('')
const targetId = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    events.value = await api.audit({
      action: action.value,
      actor_user_id: actorUserId.value,
      org_id: orgId.value,
      target_type: targetType.value,
      target_id: targetId.value,
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load audit events'
  } finally {
    loading.value = false
  }
}

function clearFilters() {
  action.value = ''
  actorUserId.value = ''
  orgId.value = ''
  targetType.value = ''
  targetId.value = ''
  load()
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <p class="mono-label">Audit</p>
    <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">Security events</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
      Filter operator, token, client, and session events written by the auth core.
    </p>

    <form class="panel mt-8 grid gap-4 p-5" @submit.prevent="load">
      <div class="flex items-center gap-2">
        <Filter class="h-4 w-4 text-accent" aria-hidden="true" />
        <h2 class="font-semibold">Filters</h2>
      </div>
      <div class="grid gap-3 md:grid-cols-5">
        <input v-model="action" class="input font-mono" placeholder="action" />
        <input v-model="actorUserId" class="input font-mono" placeholder="actor user id" />
        <input v-model="orgId" class="input font-mono" placeholder="org id" />
        <input v-model="targetType" class="input font-mono" placeholder="target type" />
        <input v-model="targetId" class="input font-mono" placeholder="target id" />
      </div>
      <div class="flex flex-wrap gap-2">
        <button class="btn-primary gap-2" :disabled="loading">
          <Search class="h-4 w-4" aria-hidden="true" />
          Search
        </button>
        <button type="button" class="btn-secondary" @click="clearFilters">Clear</button>
      </div>
    </form>

    <p v-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading audit events...</article>
      <article v-else-if="!events.length" class="panel p-4 text-sm text-muted">No audit events matched.</article>
      <template v-else>
        <article v-for="event in events" :key="event.id" class="panel p-4">
          <div class="flex flex-wrap justify-between gap-3">
            <h2 class="font-semibold">{{ event.action }}</h2>
            <time class="font-mono text-xs text-muted">{{ new Date(event.created_at).toLocaleString() }}</time>
          </div>
          <div class="mt-3 grid gap-2 text-xs text-muted md:grid-cols-2">
            <p class="break-all font-mono">actor: {{ event.actor_user_id || 'system' }}</p>
            <p class="break-all font-mono">org: {{ event.org_id || 'none' }}</p>
            <p class="break-all font-mono">target: {{ event.target_type || 'none' }}</p>
            <p class="break-all font-mono">target id: {{ event.target_id || 'none' }}</p>
          </div>
          <pre class="mt-3 overflow-x-auto rounded-md bg-bg p-3 text-xs text-muted">{{ JSON.stringify(event.details, null, 2) }}</pre>
        </article>
      </template>
    </div>
  </section>
</template>
