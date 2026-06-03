<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuthClient } from '@/types'

const clients = ref<AuthClient[]>([])
const loading = ref(true)
const error = ref('')

const defaultProjects = [
  { name: 'Sentinel', audience: 'sentinel-api' },
  { name: 'Knowhere', audience: 'knowhere-api' },
]

const audienceSummaries = computed(() => {
  const summaries = new Map<string, { audience: string; clients: string[]; scopes: Set<string> }>()
  for (const client of clients.value) {
    for (const audience of client.audiences || []) {
      const existing = summaries.get(audience) || { audience, clients: [], scopes: new Set<string>() }
      existing.clients.push(client.name)
      for (const scope of client.scopes || []) {
        existing.scopes.add(scope)
      }
      summaries.set(audience, existing)
    }
  }

  return Array.from(summaries.values()).map((summary) => ({
    audience: summary.audience,
    clients: summary.clients,
    scopes: Array.from(summary.scopes).sort(),
  }))
})

onMounted(async () => {
  try {
    clients.value = await api.clients()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load project clients'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Projects</p>
    <h1 class="mt-3 font-serif text-5xl">Protected projects</h1>

    <div class="mt-8 grid gap-4 md:grid-cols-2">
      <article class="panel p-5">
        <p class="text-sm text-muted">Registered audiences</p>
        <h2 class="mt-2 text-3xl font-semibold">{{ audienceSummaries.length }}</h2>
      </article>
      <article class="panel p-5">
        <p class="text-sm text-muted">Auth clients</p>
        <h2 class="mt-2 text-3xl font-semibold">{{ clients.length }}</h2>
      </article>
    </div>

    <div class="mt-6 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading protected projects...</article>
      <article v-else-if="error" class="rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
        {{ error }}
      </article>
      <template v-else-if="audienceSummaries.length">
        <article v-for="summary in audienceSummaries" :key="summary.audience" class="panel p-5">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 class="text-xl font-semibold">{{ summary.audience }}</h2>
              <p class="mt-2 font-mono text-xs text-muted">{{ summary.clients.join(', ') }}</p>
            </div>
            <span class="font-mono text-xs text-muted">{{ summary.scopes.length }} scopes</span>
          </div>
          <div class="mt-4 flex flex-wrap gap-2">
            <span
              v-for="scope in summary.scopes"
              :key="scope"
              class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
            >
              {{ scope }}
            </span>
          </div>
        </article>
      </template>
      <template v-else>
        <article v-for="project in defaultProjects" :key="project.audience" class="panel p-5">
          <h2 class="text-xl font-semibold">{{ project.name }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">audience: {{ project.audience }}</p>
        </article>
      </template>
    </div>
  </section>
</template>
