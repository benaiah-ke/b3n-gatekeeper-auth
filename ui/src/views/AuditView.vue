<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuditEvent } from '@/types'

const events = ref<AuditEvent[]>([])

onMounted(async () => {
  events.value = await api.audit()
})
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Audit</p>
    <h1 class="mt-3 font-serif text-5xl">Security events</h1>
    <div class="mt-8 grid gap-3">
      <article v-for="event in events" :key="event.id" class="panel p-4">
        <div class="flex flex-wrap justify-between gap-3">
          <h2 class="font-semibold">{{ event.action }}</h2>
          <time class="font-mono text-xs text-muted">{{ new Date(event.created_at).toLocaleString() }}</time>
        </div>
        <p class="mt-2 font-mono text-xs text-muted">{{ event.target_type }} / {{ event.target_id }}</p>
      </article>
    </div>
  </section>
</template>

