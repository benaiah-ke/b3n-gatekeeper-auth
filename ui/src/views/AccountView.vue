<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Org, User } from '@/types'

const user = ref<User | null>(null)
const scopes = ref<string[]>([])
const orgs = ref<Org[]>([])

onMounted(async () => {
  const [me, memberships] = await Promise.all([api.me(), api.orgs()])
  user.value = me.user
  scopes.value = me.scopes
  orgs.value = memberships
})
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Account</p>
    <h1 class="mt-3 font-serif text-5xl">GateKeeper</h1>
    <div class="mt-8 grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
      <article class="panel p-5">
        <p class="text-sm text-muted">Signed in as</p>
        <h2 class="mt-2 text-2xl font-semibold">{{ user?.email || 'Unknown' }}</h2>
        <p class="mt-4 font-mono text-xs text-muted">{{ scopes.join(' ') }}</p>
      </article>
      <article class="panel p-5">
        <p class="text-sm text-muted">Organizations</p>
        <div class="mt-4 grid gap-2">
          <div v-for="org in orgs" :key="org.id" class="flex justify-between border-b border-border py-2">
            <span>{{ org.name }}</span>
            <span class="font-mono text-xs text-muted">{{ org.role }}</span>
          </div>
        </div>
      </article>
    </div>
  </section>
</template>

