<script setup lang="ts">
import { BadgeCheck, RefreshCw, ShieldCheck, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { OAuthGrant, SetupStatus } from '@/types'

const grants = ref<OAuthGrant[]>([])
const setup = ref<SetupStatus | null>(null)
const mode = ref<'self' | 'admin'>('self')
const includeRevoked = ref(false)
const loading = ref(true)
const error = ref('')
const actionLoading = ref('')
const canReviewGrants = computed(() => Boolean(setup.value?.can_manage_clients))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const setupStatus = await api.setupStatus()
    setup.value = setupStatus
    if (mode.value === 'admin' && !canReviewGrants.value) {
      mode.value = 'self'
    }
    grants.value =
      mode.value === 'admin'
        ? await api.oauthGrantsAdmin({
            orgId: setupStatus.org?.id || undefined,
            includeRevoked: includeRevoked.value,
          })
        : await api.oauthGrants()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load connected apps'
  } finally {
    loading.value = false
  }
}

async function revoke(id: string) {
  error.value = ''
  actionLoading.value = id
  try {
    if (mode.value === 'admin') {
      await api.revokeOAuthGrantAdmin(id)
    } else {
      await api.revokeOAuthGrant(id)
    }
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke app access'
  } finally {
    actionLoading.value = ''
  }
}

function setMode(nextMode: 'self' | 'admin') {
  mode.value = nextMode
  void load()
}

function toggleRevoked() {
  includeRevoked.value = !includeRevoked.value
  void load()
}

function formatDate(value: string) {
  return new Date(value).toLocaleString()
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">Connected apps</p>
        <h1 class="mt-3 text-2xl font-semibold leading-tight md:text-3xl">OAuth grants</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Review apps that can skip hosted authorization because access has already been approved.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <template v-if="canReviewGrants">
          <button
            type="button"
            class="btn-secondary gap-2 text-sm"
            :class="{ 'border-accent text-accent': mode === 'self' }"
            :disabled="loading || Boolean(actionLoading)"
            @click="setMode('self')"
          >
            My grants
          </button>
          <button
            type="button"
            class="btn-secondary gap-2 text-sm"
            :class="{ 'border-accent text-accent': mode === 'admin' }"
            :disabled="loading || Boolean(actionLoading)"
            @click="setMode('admin')"
          >
            <ShieldCheck class="h-4 w-4" aria-hidden="true" />
            Admin review
          </button>
        </template>
        <button type="button" class="btn-secondary gap-2 text-sm" :disabled="loading || Boolean(actionLoading)" @click="load">
          <RefreshCw class="h-4 w-4" aria-hidden="true" />
          Refresh
        </button>
      </div>
    </div>

    <p v-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>

    <div v-if="canReviewGrants && mode === 'admin'" class="mt-6 flex flex-wrap items-center gap-3">
      <span class="rounded-md border border-accent/40 bg-accent/10 px-3 py-2 font-mono text-xs text-accent">
        Reviewing {{ setup?.org?.name || 'current org' }}
      </span>
      <label class="inline-flex items-center gap-2 text-sm text-muted">
        <input type="checkbox" :checked="includeRevoked" :disabled="loading || Boolean(actionLoading)" @change="toggleRevoked" />
        Include revoked grants
      </label>
    </div>

    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading connected apps...</article>
      <article v-else-if="!grants.length" class="panel p-4 text-sm text-muted">No connected apps yet.</article>
      <template v-else>
        <article v-for="grant in grants" :key="grant.id" class="panel p-4">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div class="flex items-center gap-2">
                <BadgeCheck class="h-4 w-4 text-accent" aria-hidden="true" />
                <h2 class="text-base font-semibold">{{ grant.client_name }}</h2>
              </div>
              <p class="mt-1 break-all font-mono text-xs text-muted">{{ grant.client_id }}</p>
            </div>
            <button
              type="button"
              class="btn-secondary gap-2 text-sm"
              :disabled="Boolean(actionLoading) || Boolean(grant.revoked_at)"
              @click="revoke(grant.id)"
            >
              <Trash2 class="h-4 w-4" aria-hidden="true" />
              {{ grant.revoked_at ? 'Revoked' : 'Revoke' }}
            </button>
          </div>

          <div class="mt-4 grid gap-2 text-xs text-muted md:grid-cols-3">
            <p v-if="mode === 'admin'"><span class="mono-label">User</span><br />{{ grant.user_email || grant.user_id || 'unknown' }}</p>
            <p><span class="mono-label">Audience</span><br />{{ grant.audience || 'default' }}</p>
            <p><span class="mono-label">Organization</span><br />{{ grant.org_id || 'personal account' }}</p>
            <p><span class="mono-label">Last approved</span><br />{{ formatDate(grant.last_authorized_at) }}</p>
            <p v-if="grant.revoked_at"><span class="mono-label">Revoked</span><br />{{ formatDate(grant.revoked_at) }}</p>
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <span v-for="scope in grant.scopes" :key="scope" class="rounded-md border border-border px-2 py-1 font-mono text-xs">
              {{ scope }}
            </span>
          </div>
        </article>
      </template>
    </div>
  </section>
</template>
