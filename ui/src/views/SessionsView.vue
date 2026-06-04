<script setup lang="ts">
import { BadgeCheck, CheckCircle2, Globe2, LogOut, RefreshCw, ShieldCheck, ShieldX, Trash2 } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import { api, clearTokens } from '@/services/api'
import type { Session } from '@/types'

const router = useRouter()
const sessions = ref<Session[]>([])
const deviceLabels = ref<Record<string, string>>({})
const loading = ref(true)
const error = ref('')
const notice = ref('')
const actionLoading = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const rows = await api.sessions()
    sessions.value = rows
    deviceLabels.value = Object.fromEntries(rows.map((session) => [session.id, session.device_label || '']))
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load sessions'
  } finally {
    loading.value = false
  }
}

async function revoke(id: string) {
  error.value = ''
  notice.value = ''
  actionLoading.value = id
  try {
    await api.revokeSession(id)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke session'
  } finally {
    actionLoading.value = ''
  }
}

async function revokeAll(includeCurrent: boolean) {
  error.value = ''
  notice.value = ''
  actionLoading.value = includeCurrent ? 'all' : 'others'
  try {
    await api.revokeAllSessions(includeCurrent)
    if (includeCurrent) {
      clearTokens()
      router.push({ path: '/login' })
      return
    }
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke sessions'
  } finally {
    actionLoading.value = ''
  }
}

function replaceSession(updated: Session) {
  sessions.value = sessions.value.map((session) => (session.id === updated.id ? updated : session))
  deviceLabels.value[updated.id] = updated.device_label || ''
}

async function saveDeviceLabel(session: Session) {
  error.value = ''
  notice.value = ''
  actionLoading.value = `device:${session.id}`
  try {
    const updated = await api.updateSessionDevice(session.id, {
      device_label: deviceLabels.value[session.id]?.trim() || null,
    })
    replaceSession(updated)
    notice.value = 'Device label saved.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update device label'
  } finally {
    actionLoading.value = ''
  }
}

async function setTrusted(session: Session, trusted: boolean) {
  error.value = ''
  notice.value = ''
  actionLoading.value = `trust:${session.id}`
  try {
    const updated = await api.updateSessionDevice(session.id, { trusted })
    replaceSession(updated)
    notice.value = trusted ? 'Device trusted.' : 'Device trust cleared.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update device trust'
  } finally {
    actionLoading.value = ''
  }
}

function sessionTitle(session: Session) {
  return session.device_label || session.client_name || 'Direct GateKeeper session'
}

function sessionSubtitle(session: Session) {
  if (session.client_id) {
    return session.client_id
  }
  return session.user_agent || 'No app client'
}

function trustDetail(session: Session) {
  if (!session.trusted) {
    return 'not trusted'
  }
  if (session.trusted_until) {
    return `trusted until ${new Date(session.trusted_until).toLocaleString()}`
  }
  return 'trusted'
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">Sessions</p>
    <h1 class="mt-3 font-serif text-5xl">Active sessions</h1>
    <p class="mt-3 max-w-2xl text-sm text-muted">
      Review browser and API sessions, then revoke anything that should no longer be trusted.
    </p>
    <div class="mt-6 flex flex-wrap gap-3">
      <button type="button" class="btn-secondary gap-2 text-sm" :disabled="loading || Boolean(actionLoading)" @click="load">
        <RefreshCw class="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
      <button
        type="button"
        class="btn-secondary gap-2 text-sm"
        :disabled="loading || Boolean(actionLoading)"
        @click="revokeAll(false)"
      >
        <ShieldX class="h-4 w-4" aria-hidden="true" />
        Revoke other sessions
      </button>
      <button
        type="button"
        class="btn-secondary gap-2 text-sm"
        :disabled="loading || Boolean(actionLoading)"
        @click="revokeAll(true)"
      >
        <LogOut class="h-4 w-4" aria-hidden="true" />
        Sign out everywhere
      </button>
    </div>
    <p v-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">{{ error }}</p>
    <p v-if="notice" class="mt-6 rounded-md border border-green/40 bg-green/10 p-3 text-sm text-green">{{ notice }}</p>
    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading sessions...</article>
      <article v-else-if="!sessions.length" class="panel p-4 text-sm text-muted">No sessions found.</article>
      <template v-else>
        <article v-for="session in sessions" :key="session.id" class="panel flex flex-col gap-4 p-4 md:flex-row md:items-center md:justify-between">
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
              <BadgeCheck v-if="session.current" class="h-4 w-4 text-accent" aria-hidden="true" />
              <Globe2 v-else class="h-4 w-4 text-muted" aria-hidden="true" />
              <h2 class="truncate text-sm font-semibold">{{ sessionTitle(session) }}</h2>
              <span v-if="session.current" class="rounded-md border border-accent/50 px-2 py-0.5 text-xs text-accent">Current</span>
              <span
                class="rounded-md border px-2 py-0.5 text-xs"
                :class="session.trusted ? 'border-green/50 text-green' : 'border-border text-muted'"
              >
                {{ trustDetail(session) }}
              </span>
            </div>
            <p class="mt-1 truncate font-mono text-xs text-muted">{{ sessionSubtitle(session) }}</p>
            <p class="mt-2 text-sm text-muted">
              {{ session.ip_address || 'unknown ip' }} / expires {{ new Date(session.expires_at).toLocaleString() }}
            </p>
            <p class="mt-1 text-xs text-muted">
              last seen {{ session.last_seen_at ? new Date(session.last_seen_at).toLocaleString() : 'unknown' }}
            </p>
            <p v-if="session.amr.length" class="mt-1 font-mono text-[11px] text-muted">amr: {{ session.amr.join(', ') }}</p>
            <p class="mt-1 break-all font-mono text-[11px] text-muted">{{ session.id }}</p>
            <div class="mt-3 flex flex-wrap items-center gap-2">
              <input
                v-model="deviceLabels[session.id]"
                class="input h-9 w-full max-w-full text-sm md:w-60"
                type="text"
                placeholder="Device label"
                :disabled="Boolean(session.revoked_at) || Boolean(actionLoading)"
              />
              <button
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="Boolean(session.revoked_at) || Boolean(actionLoading)"
                @click="saveDeviceLabel(session)"
              >
                <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
                Save label
              </button>
              <button
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="Boolean(session.revoked_at) || Boolean(actionLoading)"
                @click="setTrusted(session, !session.trusted)"
              >
                <ShieldCheck class="h-4 w-4" aria-hidden="true" />
                {{ session.trusted ? 'Untrust' : 'Trust' }}
              </button>
            </div>
          </div>
          <button
            class="btn-secondary gap-2 text-sm"
            :disabled="Boolean(session.revoked_at) || Boolean(actionLoading)"
            @click="revoke(session.id)"
          >
            <Trash2 class="h-4 w-4" aria-hidden="true" />
            {{ session.revoked_at ? 'Revoked' : 'Revoke' }}
          </button>
        </article>
      </template>
    </div>
  </section>
</template>
