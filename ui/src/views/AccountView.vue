<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Org, User } from '@/types'

const user = ref<User | null>(null)
const scopes = ref<string[]>([])
const orgs = ref<Org[]>([])
const loading = ref(true)
const error = ref('')

onMounted(async () => {
  try {
    const [me, memberships] = await Promise.all([api.me(), api.orgs()])
    user.value = me.user
    scopes.value = me.scopes
    orgs.value = memberships
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load account'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Account</p>
    <h1 class="mt-3 font-serif text-5xl">GateKeeper</h1>
    <p class="mt-3 max-w-2xl text-sm text-muted">
      Session, tenant, and scope posture for the current operator.
    </p>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading account context...</article>
    <article v-else-if="error" class="mt-8 rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
      {{ error }}
    </article>

    <div v-else class="mt-8 grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
      <article class="panel p-5">
        <p class="text-sm text-muted">Signed in as</p>
        <h2 class="mt-2 text-2xl font-semibold">{{ user?.email || 'Unknown' }}</h2>
        <div class="mt-5 flex flex-wrap gap-2">
          <span
            v-for="scope in scopes"
            :key="scope"
            class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
          >
            {{ scope }}
          </span>
          <span v-if="!scopes.length" class="text-sm text-muted">No bearer scopes on the current session.</span>
        </div>
      </article>
      <article class="panel p-5">
        <p class="text-sm text-muted">Organizations</p>
        <div class="mt-4 grid gap-2">
          <div v-for="org in orgs" :key="org.id" class="flex justify-between border-b border-border py-2">
            <span>{{ org.name }}</span>
            <span class="font-mono text-xs text-muted">{{ org.role }}</span>
          </div>
          <p v-if="!orgs.length" class="text-sm text-muted">No organization memberships were returned.</p>
        </div>
      </article>
    </div>
  </section>
</template>
