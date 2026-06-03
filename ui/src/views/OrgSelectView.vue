<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Org } from '@/types'

const orgs = ref<Org[]>([])

onMounted(async () => {
  orgs.value = await api.orgs()
})
</script>

<template>
  <section class="mx-auto max-w-4xl px-4 py-10 md:px-8">
    <p class="mono-label">Organizations</p>
    <h1 class="mt-3 font-serif text-4xl">Select org</h1>
    <div class="mt-8 grid gap-3">
      <RouterLink v-for="org in orgs" :key="org.id" to="/account" class="panel flex items-center justify-between p-4">
        <span>{{ org.name }}</span>
        <span class="font-mono text-xs text-muted">{{ org.role }}</span>
      </RouterLink>
    </div>
  </section>
</template>

