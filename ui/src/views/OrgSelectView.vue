<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Org } from '@/types'

const orgs = ref<Org[]>([])
const loading = ref(true)
const error = ref('')

onMounted(async () => {
  try {
    orgs.value = await api.orgs()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load organizations'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <section class="mx-auto max-w-4xl px-4 py-10 md:px-8">
    <p class="mono-label">Organizations</p>
    <h1 class="mt-3 font-serif text-4xl">Select org</h1>
    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading organizations...</article>
      <article v-else-if="error" class="rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
        {{ error }}
      </article>
      <article v-else-if="!orgs.length" class="panel p-4 text-sm text-muted">No organizations available.</article>
      <template v-else>
        <RouterLink
          v-for="org in orgs"
          :key="org.id"
          to="/account"
          class="panel flex items-center justify-between gap-4 p-4"
        >
          <span>{{ org.name }}</span>
          <span class="font-mono text-xs text-muted">{{ org.role || 'member' }}</span>
        </RouterLink>
      </template>
    </div>
  </section>
</template>
