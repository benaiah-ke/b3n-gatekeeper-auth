<script setup lang="ts">
import { BadgeCheck, Clock, Filter, KeyRound, MonitorSmartphone, Save, Search, ShieldCheck, Trash2, Users } from 'lucide-vue-next'
import type { Component } from 'vue'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuditEvent, AuditPruneResult, SetupStatus } from '@/types'

type AuditCategory = 'auth' | 'apps' | 'tokens' | 'policy' | 'access' | 'other'

const events = ref<AuditEvent[]>([])
const setup = ref<SetupStatus | null>(null)
const loading = ref(true)
const error = ref('')
const action = ref('')
const actorUserId = ref('')
const orgId = ref('')
const targetType = ref('')
const targetId = ref('')
const categoryFilter = ref<AuditCategory | ''>('')
const retentionDays = ref<number | null>(null)
const retentionNotice = ref('')
const retentionLoading = ref(false)
const pruneResult = ref<AuditPruneResult | null>(null)

const categoryDefinitions: Array<{ key: AuditCategory; label: string; icon: Component }> = [
  { key: 'auth', label: 'Auth', icon: MonitorSmartphone },
  { key: 'apps', label: 'Apps', icon: BadgeCheck },
  { key: 'tokens', label: 'Tokens', icon: KeyRound },
  { key: 'policy', label: 'Policy', icon: ShieldCheck },
  { key: 'access', label: 'Access', icon: Users },
  { key: 'other', label: 'Other', icon: Filter },
]

function categoryForAction(value: string): AuditCategory {
  const normalized = value.toLowerCase()
  if (normalized.includes('token') || normalized.includes('credential') || normalized.includes('secret')) {
    return 'tokens'
  }
  if (
    normalized.includes('policy') ||
    normalized.includes('mfa') ||
    normalized.includes('totp') ||
    normalized.startsWith('org.')
  ) {
    return 'policy'
  }
  if (
    normalized.includes('client') ||
    normalized.includes('oauth') ||
    normalized.includes('grant') ||
    normalized.includes('provider') ||
    normalized.includes('mcp')
  ) {
    return 'apps'
  }
  if (
    normalized.includes('user') ||
    normalized.includes('role') ||
    normalized.includes('membership') ||
    normalized.includes('invite')
  ) {
    return 'access'
  }
  if (normalized.startsWith('auth.') || normalized.includes('session') || normalized.includes('login')) {
    return 'auth'
  }
  return 'other'
}

const visibleEvents = computed(() =>
  categoryFilter.value ? events.value.filter((event) => categoryForAction(event.action) === categoryFilter.value) : events.value,
)
const auditCategories = computed(() =>
  categoryDefinitions.map((category) => ({
    ...category,
    count: events.value.filter((event) => categoryForAction(event.action) === category.key).length,
  })),
)
const latestEvent = computed(() => events.value[0] || null)
const latestEventLabel = computed(() =>
  latestEvent.value ? new Date(latestEvent.value.created_at).toLocaleString() : 'No events loaded',
)
const activeOrg = computed(() => setup.value?.org || setup.value?.orgs[0] || null)
const canManageRetention = computed(() => Boolean(setup.value?.can_manage_roles))
const retentionLabel = computed(() =>
  activeOrg.value?.audit_retention_days ? `${activeOrg.value.audit_retention_days} days` : 'Not set',
)

function eventDetails(event: AuditEvent) {
  return Object.keys(event.details || {}).length ? JSON.stringify(event.details, null, 2) : ''
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [rows, setupStatus] = await Promise.all([
      api.audit({
        action: action.value,
        actor_user_id: actorUserId.value,
        org_id: orgId.value,
        target_type: targetType.value,
        target_id: targetId.value,
      }),
      api.setupStatus(),
    ])
    events.value = rows
    setup.value = setupStatus
    retentionDays.value = setupStatus.org?.audit_retention_days || null
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
  categoryFilter.value = ''
  load()
}

function applyUpdatedOrg() {
  if (!setup.value || !activeOrg.value) {
    return
  }
  const updated = { ...activeOrg.value, audit_retention_days: retentionDays.value || null }
  setup.value.org = updated
  setup.value.orgs = setup.value.orgs.map((org) => (org.id === updated.id ? updated : org))
}

async function saveRetention() {
  if (!activeOrg.value) {
    return
  }
  retentionLoading.value = true
  retentionNotice.value = ''
  pruneResult.value = null
  error.value = ''
  try {
    const value = retentionDays.value ? Number(retentionDays.value) : null
    const updated = await api.updateOrg(activeOrg.value.id, { audit_retention_days: value })
    retentionDays.value = updated.audit_retention_days || null
    applyUpdatedOrg()
    retentionNotice.value = updated.audit_retention_days
      ? `Audit retention set to ${updated.audit_retention_days} days.`
      : 'Audit retention policy cleared.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update audit retention'
  } finally {
    retentionLoading.value = false
  }
}

async function runPrune(dryRun: boolean) {
  if (!activeOrg.value) {
    return
  }
  retentionLoading.value = true
  retentionNotice.value = ''
  error.value = ''
  try {
    const result = await api.pruneAudit({ org_id: activeOrg.value.id, dry_run: dryRun })
    pruneResult.value = result
    retentionNotice.value = dryRun
      ? `${result.pruned_count} events are older than ${result.retention_days} days.`
      : `${result.pruned_count} old audit events pruned.`
    if (!dryRun) {
      await load()
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not prune audit events'
  } finally {
    retentionLoading.value = false
  }
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

    <div class="mt-8 grid gap-4 md:grid-cols-5">
      <article class="panel p-5">
        <p class="text-sm text-muted">Loaded</p>
        <h2 class="mt-2 text-2xl font-semibold">{{ events.length }}</h2>
        <p class="mt-2 font-mono text-xs text-muted">{{ latestEventLabel }}</p>
      </article>
      <article v-for="category in auditCategories" :key="category.key" class="panel p-5">
        <div class="flex items-center justify-between gap-3">
          <p class="text-sm text-muted">{{ category.label }}</p>
          <component :is="category.icon" class="h-4 w-4 text-accent" aria-hidden="true" />
        </div>
        <h2 class="mt-2 text-2xl font-semibold">{{ category.count }}</h2>
        <p class="mt-2 font-mono text-xs text-muted">visible in current query</p>
      </article>
    </div>

    <article class="panel mt-4 p-5">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="mono-label">Retention</p>
          <h2 class="mt-2 text-xl font-semibold">Audit retention policy</h2>
          <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
            Set how long this organization keeps audit events, then preview or prune events older than that cutoff.
          </p>
        </div>
        <span class="inline-flex min-h-9 items-center gap-2 rounded-md border border-border px-3 font-mono text-xs text-muted">
          <Clock class="h-4 w-4" aria-hidden="true" />
          {{ retentionLabel }}
        </span>
      </div>

      <p v-if="retentionNotice" class="mt-4 text-sm text-green">{{ retentionNotice }}</p>

      <div class="mt-5 flex flex-wrap items-end gap-3">
        <label class="grid w-48 gap-2 text-sm text-muted">
          Days
          <input
            v-model.number="retentionDays"
            class="input"
            type="number"
            min="1"
            max="3650"
            placeholder="not set"
            :disabled="retentionLoading || !canManageRetention || !activeOrg"
          />
        </label>
        <button
          type="button"
          class="btn-primary gap-2 text-sm"
          :disabled="retentionLoading || !canManageRetention || !activeOrg"
          @click="saveRetention"
        >
          <Save class="h-4 w-4" aria-hidden="true" />
          Save policy
        </button>
        <button
          type="button"
          class="btn-secondary gap-2 text-sm"
          :disabled="retentionLoading || !canManageRetention || !activeOrg?.audit_retention_days"
          @click="runPrune(true)"
        >
          <Search class="h-4 w-4" aria-hidden="true" />
          Preview prune
        </button>
        <button
          type="button"
          class="btn-secondary gap-2 text-sm"
          :disabled="retentionLoading || !canManageRetention || !activeOrg?.audit_retention_days || !pruneResult?.dry_run"
          @click="runPrune(false)"
        >
          <Trash2 class="h-4 w-4" aria-hidden="true" />
          Prune old
        </button>
      </div>
    </article>

    <div class="mt-4 flex flex-wrap gap-2">
      <button
        type="button"
        class="btn-secondary min-h-9 px-3 text-xs"
        :class="{ 'border-accent text-fg': !categoryFilter }"
        @click="categoryFilter = ''"
      >
        <Filter class="h-4 w-4" aria-hidden="true" />
        All
      </button>
      <button
        v-for="category in auditCategories"
        :key="`filter-${category.key}`"
        type="button"
        class="btn-secondary min-h-9 px-3 text-xs"
        :class="{ 'border-accent text-fg': categoryFilter === category.key }"
        @click="categoryFilter = category.key"
      >
        <component :is="category.icon" class="h-4 w-4" aria-hidden="true" />
        {{ category.label }}
      </button>
    </div>

    <form class="panel mt-6 grid gap-4 p-5" @submit.prevent="load">
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
      <article v-else-if="!visibleEvents.length" class="panel p-4 text-sm text-muted">No audit events matched.</article>
      <template v-else>
        <article v-for="event in visibleEvents" :key="event.id" class="panel p-4">
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
          <pre v-if="eventDetails(event)" class="mt-3 overflow-x-auto rounded-md bg-bg p-3 text-xs text-muted">{{ eventDetails(event) }}</pre>
          <p v-else class="mt-3 rounded-md bg-bg p-3 text-xs text-muted">No structured details recorded.</p>
        </article>
      </template>
    </div>
  </section>
</template>
