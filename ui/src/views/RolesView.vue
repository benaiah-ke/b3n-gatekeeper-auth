<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Org } from '@/types'

const orgs = ref<Org[]>([])
const loading = ref(true)
const error = ref('')

const seedRoles = [
  { name: 'owner', permissions: ['admin:*', 'auth:*', 'token:*'] },
  { name: 'admin', permissions: ['admin:*', 'auth:read', 'token:*'] },
  { name: 'operator', permissions: ['auth:read', 'token:create', 'token:revoke'] },
  { name: 'viewer', permissions: ['auth:read'] },
]

const activeRoles = computed(() =>
  orgs.value
    .filter((org) => org.role)
    .map((org) => ({
      org: org.name,
      role: org.role || 'member',
      permissions: org.permissions || [],
    })),
)

onMounted(async () => {
  try {
    orgs.value = await api.orgs()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load roles'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">RBAC</p>
    <h1 class="mt-3 font-serif text-5xl">Roles</h1>

    <div class="mt-8 grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
      <article class="panel p-5">
        <p class="text-sm text-muted">Seed roles</p>
        <h2 class="mt-2 text-3xl font-semibold">{{ seedRoles.length }}</h2>
      </article>
      <article class="panel p-5">
        <p class="text-sm text-muted">Assigned org roles</p>
        <h2 class="mt-2 text-3xl font-semibold">{{ activeRoles.length }}</h2>
      </article>
    </div>

    <div class="mt-6 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading roles...</article>
      <article v-else-if="error" class="rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
        {{ error }}
      </article>
      <template v-else>
        <article v-for="role in seedRoles" :key="role.name" class="panel p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 class="capitalize">{{ role.name }}</h2>
            <span class="font-mono text-xs text-muted">{{ role.permissions.length }} permissions</span>
          </div>
          <div class="mt-3 flex flex-wrap gap-2">
            <span
              v-for="permission in role.permissions"
              :key="permission"
              class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
            >
              {{ permission }}
            </span>
          </div>
        </article>
      </template>
    </div>

    <div v-if="!loading && !error" class="mt-8 grid gap-3">
      <p class="mono-label">Current assignments</p>
      <article v-if="!activeRoles.length" class="panel p-4 text-sm text-muted">No assigned org roles returned.</article>
      <template v-else>
        <article v-for="role in activeRoles" :key="`${role.org}:${role.role}`" class="panel p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h2>{{ role.org }}</h2>
            <span class="font-mono text-xs text-muted">{{ role.role }}</span>
          </div>
          <div class="mt-3 flex flex-wrap gap-2">
            <span
              v-for="permission in role.permissions"
              :key="permission"
              class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
            >
              {{ permission }}
            </span>
            <span v-if="!role.permissions.length" class="text-sm text-muted">No permissions returned.</span>
          </div>
        </article>
      </template>
    </div>
  </section>
</template>
