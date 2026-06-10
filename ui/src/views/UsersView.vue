<script setup lang="ts">
import { CheckCircle2, KeyRound, RotateCcw, Search, ShieldAlert, ShieldCheck, Trash2, UserCheck, UserX } from 'lucide-vue-next'
import { computed, onMounted, reactive, ref } from 'vue'

import { api } from '@/services/api'
import type { AdminUser, Role, SetupStatus, UserDeleteResult, UserMembership } from '@/types'

const setup = ref<SetupStatus | null>(null)
const users = ref<AdminUser[]>([])
const roles = ref<Role[]>([])
const query = ref('')
const loading = ref(true)
const actionLoading = ref('')
const error = ref('')
const notice = ref('')
const selectedRoleId = reactive<Record<string, string>>({})
const selectedStatus = reactive<Record<string, string>>({})
const displayNames = reactive<Record<string, string>>({})
const deleteConfirm = reactive<Record<string, string>>({})
const deletePreviews = reactive<Record<string, UserDeleteResult>>({})
const provisionEmail = ref('')
const provisionDisplayName = ref('')
const provisionRoleId = ref('')
const provisionStatus = ref('active')
const provisionEmailVerified = ref(false)
const provisionDisabled = ref(false)

const activeOrg = computed(() => setup.value?.org || setup.value?.orgs[0] || null)
const canManage = computed(() => Boolean(setup.value?.can_manage_roles))
const hardDeleteAllowed = computed(() => Boolean(activeOrg.value?.allow_user_hard_delete))
const activeUsers = computed(() => users.value.filter((user) => !user.disabled))
const disabledUsers = computed(() => users.value.filter((user) => user.disabled))
const mfaUsers = computed(() => users.value.filter((user) => user.mfa_totp_enabled))
const owners = computed(() =>
  users.value.filter((user) => membershipFor(user)?.status === 'active' && membershipFor(user)?.role === 'owner'),
)

function membershipFor(user: AdminUser): UserMembership | undefined {
  return user.memberships.find((membership) => membership.org_id === activeOrg.value?.id) || user.memberships[0]
}

function deletePreviewCounts(user: AdminUser) {
  return deletePreviews[user.id]?.counts || {}
}

function seedControls() {
  for (const user of users.value) {
    const membership = membershipFor(user)
    displayNames[user.id] = user.display_name || ''
    selectedRoleId[user.id] = membership?.role_id || roles.value[0]?.id || ''
    selectedStatus[user.id] = membership?.status || 'active'
    deleteConfirm[user.id] = deleteConfirm[user.id] || ''
  }
}

async function load() {
  loading.value = true
  error.value = ''
  notice.value = ''
  try {
    const setupStatus = await api.setupStatus()
    setup.value = setupStatus
    const orgId = setupStatus.org?.id || setupStatus.orgs[0]?.id
    const [roleRows, userRows] = await Promise.all([
      api.roles(orgId),
      api.users({ orgId, q: query.value.trim() || undefined }),
    ])
    roles.value = roleRows
    users.value = userRows
    if (!provisionRoleId.value) {
      provisionRoleId.value = roleRows.find((role) => role.name === 'viewer')?.id || roleRows[0]?.id || ''
    }
    seedControls()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load users'
  } finally {
    loading.value = false
  }
}

async function runAction(key: string, action: () => Promise<unknown>, message: string) {
  actionLoading.value = key
  error.value = ''
  notice.value = ''
  try {
    await action()
    notice.value = message
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update user'
  } finally {
    actionLoading.value = ''
  }
}

async function saveProfile(user: AdminUser) {
  await runAction(
    `profile:${user.id}`,
    () => api.updateUser(user.id, { display_name: displayNames[user.id] || null }),
    'Profile updated.',
  )
}

async function toggleVerified(user: AdminUser) {
  await runAction(
    `verified:${user.id}`,
    () => api.updateUser(user.id, { email_verified: !user.email_verified }),
    user.email_verified ? 'Email marked unverified.' : 'Email marked verified.',
  )
}

async function toggleDisabled(user: AdminUser) {
  await runAction(
    `disabled:${user.id}`,
    () => api.updateUser(user.id, { disabled: !user.disabled }),
    user.disabled ? 'User reactivated.' : 'User suspended and sessions revoked.',
  )
}

async function saveMembership(user: AdminUser) {
  if (!activeOrg.value) return
  await runAction(
    `membership:${user.id}`,
    () =>
      api.updateUserMembership(user.id, {
        org_id: activeOrg.value!.id,
        role_id: selectedRoleId[user.id],
        status: selectedStatus[user.id] || 'active',
      }),
    'Membership updated and user sessions revoked.',
  )
}

async function provisionUser() {
  if (!activeOrg.value) return
  await runAction(
    'provision',
    () =>
      api.provisionUser({
        org_id: activeOrg.value!.id,
        email: provisionEmail.value,
        display_name: provisionDisplayName.value || null,
        role_id: provisionRoleId.value || null,
        status: provisionStatus.value,
        email_verified: provisionEmailVerified.value,
        disabled: provisionDisabled.value,
      }),
    'User provisioned.',
  )
  provisionEmail.value = ''
  provisionDisplayName.value = ''
  provisionStatus.value = 'active'
  provisionEmailVerified.value = false
  provisionDisabled.value = false
}

async function revokeSessions(user: AdminUser) {
  await runAction(
    `sessions:${user.id}`,
    () => api.revokeUserSessions(user.id),
    'User sessions revoked.',
  )
}

async function resetTotp(user: AdminUser) {
  await runAction(
    `mfa:${user.id}`,
    () => api.resetUserTotp(user.id),
    'Authenticator 2FA reset and user sessions revoked.',
  )
}

async function previewDeleteUser(user: AdminUser) {
  actionLoading.value = `delete-preview:${user.id}`
  error.value = ''
  notice.value = ''
  try {
    deletePreviews[user.id] = await api.deleteUser(user.id, { dry_run: true })
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not preview user deletion'
  } finally {
    actionLoading.value = ''
  }
}

async function deleteUser(user: AdminUser) {
  await runAction(
    `delete:${user.id}`,
    () => api.deleteUser(user.id, { dry_run: false, confirm_email: deleteConfirm[user.id] || null }),
    'User permanently deleted.',
  )
  delete deleteConfirm[user.id]
  delete deletePreviews[user.id]
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">Users</p>
        <h1 class="mt-3 text-2xl font-semibold leading-tight md:text-3xl">User administration</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Review accounts, assign roles, suspend access, verify email state, and revoke sessions from one provider surface.
        </p>
      </div>
      <button type="button" class="btn-secondary gap-2 text-sm" :disabled="loading" @click="load">
        <RotateCcw class="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
    </div>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading users...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>
    <article v-else-if="notice" class="mt-6 rounded-md border border-green/40 bg-green/10 p-3 text-sm text-green">
      {{ notice }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <article
        v-if="!canManage"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        <div class="flex gap-3">
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
          <p>This account can inspect user state only if it has admin permissions. Use an owner account for role and access changes.</p>
        </div>
      </article>

      <div class="grid gap-4 md:grid-cols-5">
        <article class="panel p-5">
          <p class="text-sm text-muted">Users</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ users.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Active</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ activeUsers.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Suspended</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ disabledUsers.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">2FA</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ mfaUsers.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Owners</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ owners.length }}</h2>
        </article>
      </div>

      <form class="panel grid gap-4 p-4" :class="{ 'opacity-60': !canManage }" @submit.prevent="provisionUser">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p class="mono-label">Provisioning</p>
            <h2 class="mt-2 text-xl font-semibold">Create or update account access</h2>
          </div>
          <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
            current org
          </span>
        </div>
        <div class="grid gap-3 md:grid-cols-[1fr_1fr_0.7fr_0.7fr]">
          <label class="grid gap-2 text-sm text-muted">
            Email
            <input v-model="provisionEmail" class="input" type="email" :disabled="!canManage" required />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Display name
            <input v-model="provisionDisplayName" class="input" :disabled="!canManage" />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Role
            <select v-model="provisionRoleId" class="input" :disabled="!canManage">
              <option v-for="role in roles" :key="role.id" :value="role.id">{{ role.name }}</option>
            </select>
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Status
            <select v-model="provisionStatus" class="input" :disabled="!canManage">
              <option value="active">active</option>
              <option value="suspended">suspended</option>
              <option value="revoked">revoked</option>
            </select>
          </label>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          <label class="inline-flex min-h-10 items-center gap-2 rounded-md border border-border bg-surface px-3 text-sm text-muted">
            <input v-model="provisionEmailVerified" type="checkbox" :disabled="!canManage" />
            Email verified
          </label>
          <label class="inline-flex min-h-10 items-center gap-2 rounded-md border border-border bg-surface px-3 text-sm text-muted">
            <input v-model="provisionDisabled" type="checkbox" :disabled="!canManage" />
            Disabled account
          </label>
          <button class="btn-primary gap-2 text-sm" :disabled="!canManage || !activeOrg || actionLoading === 'provision'">
            <UserCheck class="h-4 w-4" aria-hidden="true" />
            Provision
          </button>
        </div>
      </form>

      <form class="panel grid gap-3 p-4 md:grid-cols-[1fr_auto]" @submit.prevent="load">
        <label class="relative block">
          <Search class="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" aria-hidden="true" />
          <input v-model="query" class="input pl-10" placeholder="Search by email or display name" />
        </label>
        <button class="btn-secondary gap-2">
          <Search class="h-4 w-4" aria-hidden="true" />
          Search
        </button>
      </form>

      <div class="grid gap-3">
        <article v-if="!users.length" class="panel p-4 text-sm text-muted">No users returned.</article>
        <article v-for="user in users" v-else :key="user.id" class="panel grid gap-5 p-4">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 class="break-words text-lg font-semibold">{{ user.email }}</h2>
              <p class="mt-1 font-mono text-xs text-muted">{{ user.id }}</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <span
                class="rounded-md border px-2 py-1 font-mono text-xs"
                :class="user.disabled ? 'border-red/50 text-red' : 'border-green/50 text-green'"
              >
                {{ user.disabled ? 'suspended' : 'active' }}
              </span>
              <span
                class="rounded-md border px-2 py-1 font-mono text-xs"
                :class="user.email_verified ? 'border-green/50 text-green' : 'border-border text-muted'"
              >
                {{ user.email_verified ? 'verified' : 'unverified' }}
              </span>
              <span
                class="inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-xs"
                :class="user.mfa_totp_enabled ? 'border-green/50 text-green' : 'border-border text-muted'"
              >
                <ShieldCheck v-if="user.mfa_totp_enabled" class="h-3 w-3" aria-hidden="true" />
                {{ user.mfa_totp_enabled ? '2fa on' : '2fa off' }}
              </span>
            </div>
          </div>

          <div class="grid gap-4 lg:grid-cols-[1fr_1fr]">
            <div class="grid gap-3">
              <p class="mono-label">Profile</p>
              <div class="grid gap-3 md:grid-cols-[1fr_auto_auto]">
                <input
                  v-model="displayNames[user.id]"
                  class="input"
                  :disabled="!canManage"
                  placeholder="Display name"
                />
                <button
                  type="button"
                  class="btn-secondary gap-2 text-sm"
                  :disabled="!canManage || actionLoading === `profile:${user.id}`"
                  @click="saveProfile(user)"
                >
                  <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
                  Save
                </button>
                <button
                  type="button"
                  class="btn-secondary gap-2 text-sm"
                  :disabled="!canManage || actionLoading === `verified:${user.id}`"
                  @click="toggleVerified(user)"
                >
                  <UserCheck class="h-4 w-4" aria-hidden="true" />
                  {{ user.email_verified ? 'Unverify' : 'Verify' }}
                </button>
              </div>
            </div>

            <div class="grid gap-3">
              <p class="mono-label">Membership</p>
              <div class="grid gap-3 md:grid-cols-[1fr_0.75fr_auto]">
                <select v-model="selectedRoleId[user.id]" class="input" :disabled="!canManage">
                  <option v-for="role in roles" :key="role.id" :value="role.id">{{ role.name }}</option>
                </select>
                <select v-model="selectedStatus[user.id]" class="input" :disabled="!canManage">
                  <option value="active">active</option>
                  <option value="suspended">suspended</option>
                  <option value="revoked">revoked</option>
                </select>
                <button
                  type="button"
                  class="btn-secondary gap-2 text-sm"
                  :disabled="!canManage || !activeOrg || actionLoading === `membership:${user.id}`"
                  @click="saveMembership(user)"
                >
                  <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
                  Apply
                </button>
              </div>
            </div>
          </div>

          <div class="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
            <div class="flex flex-wrap gap-2">
              <span
                v-for="membership in user.memberships"
                :key="membership.id"
                class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
              >
                {{ membership.org_name }} / {{ membership.role }} / {{ membership.status }}
              </span>
            </div>
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="!canManage || !user.mfa_totp_enabled || actionLoading === `mfa:${user.id}`"
                @click="resetTotp(user)"
              >
                <KeyRound class="h-4 w-4" aria-hidden="true" />
                Reset 2FA
              </button>
              <button
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="!canManage || actionLoading === `sessions:${user.id}`"
                @click="revokeSessions(user)"
              >
                <RotateCcw class="h-4 w-4" aria-hidden="true" />
                Revoke sessions
              </button>
              <button
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="!canManage || actionLoading === `disabled:${user.id}`"
                @click="toggleDisabled(user)"
              >
                <UserX class="h-4 w-4" aria-hidden="true" />
                {{ user.disabled ? 'Reactivate' : 'Suspend' }}
              </button>
            </div>
          </div>
          <div class="grid gap-3 rounded-md border border-red/25 bg-red/5 p-3">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Account lifecycle</p>
                <p class="mt-2 text-sm font-semibold text-red">Permanent delete</p>
                <p class="mt-1 max-w-2xl text-sm leading-6 text-muted">
                  {{ hardDeleteAllowed ? 'Preview the affected auth artifacts before deleting this account.' : 'Enable hard delete from Policy before permanent account removal.' }}
                </p>
              </div>
              <span
                class="inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 font-mono text-xs"
                :class="hardDeleteAllowed ? 'border-orange/45 bg-orange/10 text-orange' : 'border-border bg-surface text-muted'"
              >
                <Trash2 class="h-4 w-4" aria-hidden="true" />
                {{ hardDeleteAllowed ? 'allowed' : 'blocked' }}
              </span>
            </div>
            <div v-if="deletePreviews[user.id]" class="flex flex-wrap gap-2 text-xs">
              <span
                v-for="(count, key) in deletePreviewCounts(user)"
                :key="key"
                class="rounded-md border border-border bg-bg px-2 py-1 font-mono text-muted"
              >
                {{ key }} {{ count }}
              </span>
            </div>
            <div class="grid gap-3 md:grid-cols-[1fr_auto_auto]">
              <input
                v-model="deleteConfirm[user.id]"
                class="input font-mono text-sm"
                :disabled="!canManage || !hardDeleteAllowed"
                :placeholder="user.email"
              />
              <button
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="!canManage || !hardDeleteAllowed || actionLoading === `delete-preview:${user.id}`"
                @click="previewDeleteUser(user)"
              >
                <Search class="h-4 w-4" aria-hidden="true" />
                Preview delete
              </button>
              <button
                type="button"
                class="btn-secondary gap-2 text-sm text-red"
                :disabled="!canManage || !hardDeleteAllowed || deleteConfirm[user.id] !== user.email || actionLoading === `delete:${user.id}`"
                @click="deleteUser(user)"
              >
                <Trash2 class="h-4 w-4" aria-hidden="true" />
                Delete
              </button>
            </div>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
