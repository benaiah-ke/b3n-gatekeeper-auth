<script setup lang="ts">
import { CheckCircle2, Copy, MailPlus, RotateCcw, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { Invitation, Role, SetupStatus } from '@/types'

const setup = ref<SetupStatus | null>(null)
const invitations = ref<Invitation[]>([])
const roles = ref<Role[]>([])
const email = ref('')
const selectedRoleId = ref('')
const expiresInDays = ref(7)
const includeInactive = ref(false)
const createdToken = ref('')
const copied = ref(false)
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const notice = ref('')

const activeOrg = computed(() => setup.value?.org || setup.value?.orgs[0] || null)
const canManage = computed(() => Boolean(setup.value?.can_manage_roles))
const pendingInvitations = computed(
  () => invitations.value.filter((item) => !item.accepted_at && !item.revoked_at && new Date(item.expires_at) > new Date()),
)
const acceptedInvitations = computed(() => invitations.value.filter((item) => item.accepted_at))

function invitationState(invitation: Invitation) {
  if (invitation.accepted_at) return 'accepted'
  if (invitation.revoked_at) return 'revoked'
  if (new Date(invitation.expires_at) <= new Date()) return 'expired'
  return 'pending'
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const setupStatus = await api.setupStatus()
    setup.value = setupStatus
    const orgId = setupStatus.org?.id || setupStatus.orgs[0]?.id
    const [roleRows, inviteRows] = await Promise.all([
      api.roles(orgId),
      api.invitations({ orgId, includeInactive: includeInactive.value }),
    ])
    roles.value = roleRows
    invitations.value = inviteRows
    if (!selectedRoleId.value) {
      selectedRoleId.value = roleRows.find((role) => role.name === 'viewer')?.id || roleRows[0]?.id || ''
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load invitations'
  } finally {
    loading.value = false
  }
}

async function createInvitation() {
  if (!activeOrg.value) return
  saving.value = true
  error.value = ''
  notice.value = ''
  copied.value = false
  createdToken.value = ''
  try {
    const invite = await api.createInvitation({
      email: email.value,
      org_id: activeOrg.value.id,
      role_id: selectedRoleId.value || null,
      expires_in_days: expiresInDays.value,
    })
    createdToken.value = invite.token || ''
    notice.value = 'Invitation created.'
    email.value = ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create invitation'
  } finally {
    saving.value = false
  }
}

async function revokeInvitation(id: string) {
  error.value = ''
  notice.value = ''
  try {
    await api.revokeInvitation(id)
    notice.value = 'Invitation revoked.'
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke invitation'
  }
}

async function copyCreatedToken() {
  await navigator.clipboard.writeText(createdToken.value)
  copied.value = true
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">Invitations</p>
        <h1 class="mt-3 text-2xl font-semibold leading-tight md:text-3xl">Invite users</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Add people to an organization with an audited, scoped invitation that can be accepted through the API or hosted UI.
        </p>
      </div>
      <button type="button" class="btn-secondary gap-2 text-sm" :disabled="loading" @click="load">
        <RotateCcw class="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
    </div>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading invitations...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>
    <article v-else-if="notice" class="mt-6 rounded-md border border-green/40 bg-green/10 p-3 text-sm text-green">
      {{ notice }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <div class="grid gap-4 md:grid-cols-3">
        <article class="panel p-5">
          <p class="text-sm text-muted">Pending</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ pendingInvitations.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Accepted</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ acceptedInvitations.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Organization</p>
          <h2 class="mt-2 break-words text-xl font-semibold">{{ activeOrg?.name || 'No org' }}</h2>
        </article>
      </div>

      <form class="panel grid gap-4 p-5 lg:grid-cols-[1fr_0.8fr_0.45fr_auto]" @submit.prevent="createInvitation">
        <label class="grid gap-2 text-sm text-muted">
          Email
          <input v-model="email" class="input" type="email" placeholder="user@example.com" :disabled="!canManage" required />
        </label>
        <label class="grid gap-2 text-sm text-muted">
          Role
          <select v-model="selectedRoleId" class="input" :disabled="!canManage">
            <option v-for="role in roles" :key="role.id" :value="role.id">{{ role.name }}</option>
          </select>
        </label>
        <label class="grid gap-2 text-sm text-muted">
          Days
          <input v-model.number="expiresInDays" class="input" type="number" min="1" max="90" :disabled="!canManage" />
        </label>
        <button class="btn-primary self-end gap-2 text-sm" :disabled="!canManage || saving || !activeOrg">
          <MailPlus class="h-4 w-4" aria-hidden="true" />
          {{ saving ? 'Creating' : 'Invite' }}
        </button>
      </form>

      <article v-if="createdToken" class="panel p-5">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p class="mono-label">Copy-once token</p>
            <p class="mt-2 text-sm text-muted">Send this through your product-owned invite flow if SMTP is not delivering email.</p>
          </div>
          <button type="button" class="btn-secondary gap-2 text-sm" @click="copyCreatedToken">
            <Copy class="h-4 w-4" aria-hidden="true" />
            {{ copied ? 'Copied' : 'Copy' }}
          </button>
        </div>
        <pre class="mt-4 overflow-x-auto rounded-md bg-bg p-3 text-xs text-muted">{{ createdToken }}</pre>
      </article>

      <div class="flex items-center justify-between gap-4">
        <p class="mono-label">Invitation log</p>
        <label class="flex items-center gap-2 text-sm text-muted">
          <input v-model="includeInactive" type="checkbox" class="h-4 w-4 accent-accent" @change="load" />
          Show inactive
        </label>
      </div>

      <div class="grid gap-3">
        <article v-if="!invitations.length" class="panel p-4 text-sm text-muted">No invitations returned.</article>
        <article v-for="invitation in invitations" v-else :key="invitation.id" class="panel grid gap-4 p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 class="break-words text-lg font-semibold">{{ invitation.email }}</h2>
              <p class="mt-1 font-mono text-xs text-muted">{{ invitation.id }}</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
                {{ invitation.role }}
              </span>
              <span
                class="rounded-md border px-2 py-1 font-mono text-xs"
                :class="invitationState(invitation) === 'pending' ? 'border-green/50 text-green' : 'border-border text-muted'"
              >
                {{ invitationState(invitation) }}
              </span>
            </div>
          </div>

          <div class="grid gap-2 text-sm text-muted md:grid-cols-3">
            <p>Org: {{ invitation.org_name }}</p>
            <p>Expires: {{ new Date(invitation.expires_at).toLocaleString() }}</p>
            <p>Hint: {{ invitation.token_hint }}</p>
          </div>

          <div class="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
            <button
              v-if="invitationState(invitation) === 'pending'"
              type="button"
              class="btn-secondary gap-2 text-sm"
              :disabled="!canManage"
              @click="revokeInvitation(invitation.id)"
            >
              <Trash2 class="h-4 w-4" aria-hidden="true" />
              Revoke
            </button>
            <span v-else class="inline-flex min-h-10 items-center gap-2 text-sm text-muted">
              <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
              {{ invitationState(invitation) }}
            </span>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
