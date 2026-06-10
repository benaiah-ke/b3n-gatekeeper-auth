<script setup lang="ts">
import { ShieldCheck, UserPlus } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Org, Role, SetupStatus } from '@/types'

const setup = ref<SetupStatus | null>(null)
const roles = ref<Role[]>([])
const orgs = ref<Org[]>([])
const roleName = ref('operator')
const permissionsText = ref('auth:read token:*')
const loading = ref(true)
const saving = ref(false)
const error = ref('')

const activeOrg = computed(() => setup.value?.org || setup.value?.orgs[0] || null)
const canManage = computed(() => Boolean(setup.value?.can_manage_roles))
const activeAssignments = computed(() =>
  orgs.value
    .filter((org) => org.role)
    .map((org) => ({
      org: org.name,
      role: org.role || 'member',
      permissions: org.permissions || [],
    })),
)

function parsePermissions() {
  return permissionsText.value
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const setupStatus = await api.setupStatus()
    setup.value = setupStatus
    const [roleRows, orgRows] = await Promise.all([api.roles(setupStatus.org?.id), api.orgs()])
    roles.value = roleRows
    orgs.value = orgRows
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load roles'
  } finally {
    loading.value = false
  }
}

async function createRole() {
  saving.value = true
  error.value = ''
  try {
    await api.createRole({
      org_id: activeOrg.value?.id || null,
      name: roleName.value,
      permissions: parsePermissions(),
    })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create role'
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <p class="mono-label">RBAC</p>
    <h1 class="mt-3 text-2xl font-semibold leading-tight md:text-3xl">Roles and memberships</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
      Inspect seed roles, create scoped roles, and confirm which org role the current account is using.
    </p>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading roles...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <article
        v-if="!canManage"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        Role creation and assignment require an owner account.
      </article>

      <div class="grid gap-4 md:grid-cols-3">
        <article class="panel p-5">
          <p class="text-sm text-muted">Roles</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ roles.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Assignments</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ activeAssignments.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Current org</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ activeOrg?.role || 'none' }}</h2>
        </article>
      </div>

      <form class="panel grid gap-4 p-5" :class="{ 'opacity-60': !canManage }" @submit.prevent="createRole">
        <div class="flex items-center gap-2">
          <ShieldCheck class="h-4 w-4 text-accent" aria-hidden="true" />
          <h2 class="font-semibold">Create role</h2>
        </div>
        <div class="grid gap-4 md:grid-cols-[0.8fr_1.2fr_auto]">
          <input v-model="roleName" class="input" :disabled="!canManage" placeholder="role name" required />
          <input v-model="permissionsText" class="input font-mono" :disabled="!canManage" placeholder="auth:read token:*" />
          <button class="btn-primary" :disabled="saving || !canManage">{{ saving ? 'Creating' : 'Create' }}</button>
        </div>
      </form>

      <article class="panel p-5">
        <div class="flex items-center gap-2">
          <UserPlus class="h-4 w-4 text-muted" aria-hidden="true" />
          <h2 class="font-semibold">Membership management</h2>
        </div>
        <p class="mt-3 text-sm leading-6 text-muted">
          Assign existing users from the Users page, or send scoped organization invitations from the Invites page.
        </p>
      </article>

      <div class="grid gap-3">
        <p class="mono-label">Role catalog</p>
        <article v-if="!roles.length" class="panel p-4 text-sm text-muted">No roles returned.</article>
        <article v-for="role in roles" v-else :key="role.id" class="panel p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 class="font-semibold">{{ role.name }}</h2>
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
            <span v-if="!role.permissions.length" class="text-sm text-muted">No permissions assigned.</span>
          </div>
        </article>
      </div>

      <div class="grid gap-3">
        <p class="mono-label">Current assignments</p>
        <article v-if="!activeAssignments.length" class="panel p-4 text-sm text-muted">No active org roles returned.</article>
        <article v-for="assignment in activeAssignments" v-else :key="`${assignment.org}:${assignment.role}`" class="panel p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 class="font-semibold">{{ assignment.org }}</h2>
            <span class="font-mono text-xs text-muted">{{ assignment.role }}</span>
          </div>
          <div class="mt-3 flex flex-wrap gap-2">
            <span
              v-for="permission in assignment.permissions"
              :key="permission"
              class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
            >
              {{ permission }}
            </span>
            <span v-if="!assignment.permissions.length" class="text-sm text-muted">No permissions returned.</span>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
