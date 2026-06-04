<script setup lang="ts">
import { ArrowRight, CheckCircle2, ListChecks, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '@/services/api'
import type { AuthClient, Org, SetupStatus } from '@/types'

const setup = ref<SetupStatus | null>(null)
const clients = ref<AuthClient[]>([])
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const notice = ref('')
const orgIdleTimeoutMinutes = ref<number | null>(null)
const baselineIdleTimeoutMinutes = 720

const activeOrg = computed(() => setup.value?.org || setup.value?.orgs[0] || null)
const canManage = computed(() => Boolean(setup.value?.can_manage_roles))
const currentUserMfaEnabled = computed(() => Boolean(setup.value?.user?.mfa_totp_enabled))
const orgMfaRequired = computed(() => Boolean(activeOrg.value?.require_mfa))
const orgTrustedDeviceBypass = computed(() => Boolean(activeOrg.value?.trusted_device_mfa_bypass))
const adminStepUpRequired = computed(() => Boolean(activeOrg.value?.admin_step_up_mfa_required))
const userHardDeleteAllowed = computed(() => Boolean(activeOrg.value?.allow_user_hard_delete))
const appMfaCount = computed(() => clients.value.filter((client) => client.require_mfa).length)
const trustedDeviceAllowedCount = computed(
  () => activeOrgClients.value.filter((client) => trustedDeviceStatus(client).allowed).length,
)
const orgIdleTimeoutLabel = computed(() =>
  activeOrg.value?.session_idle_timeout_minutes
    ? `${activeOrg.value.session_idle_timeout_minutes} min`
    : 'Not set',
)
const orgIdleTimeoutReady = computed(() =>
  Boolean(
    activeOrg.value?.session_idle_timeout_minutes &&
      activeOrg.value.session_idle_timeout_minutes <= baselineIdleTimeoutMinutes,
  ),
)
const activeOrgClients = computed(() =>
  activeOrg.value ? clients.value.filter((client) => !client.org_id || client.org_id === activeOrg.value?.id) : clients.value,
)
const baselineItems = computed(() => [
  {
    key: 'owner-mfa',
    label: 'Owner MFA enrolled',
    detail: currentUserMfaEnabled.value
      ? 'This session can safely enforce sensitive-action step-up.'
      : 'Enroll authenticator MFA before locking sensitive admin changes behind step-up.',
    done: currentUserMfaEnabled.value,
    to: '/account',
  },
  {
    key: 'org-mfa',
    label: 'Organization MFA',
    detail: orgMfaRequired.value
      ? 'Registered app, CLI, and device sessions require MFA assurance.'
      : 'Require MFA across org-bound auth surfaces before production use.',
    done: orgMfaRequired.value,
    to: '',
  },
  {
    key: 'admin-step-up',
    label: 'Admin step-up',
    detail: adminStepUpRequired.value
      ? 'Client, provider, role, token, and policy mutations require MFA-backed sessions.'
      : 'Protect sensitive operator mutations after owner MFA is enrolled.',
    done: adminStepUpRequired.value,
    to: '',
  },
  {
    key: 'idle-timeout',
    label: 'Idle timeout',
    detail: orgIdleTimeoutReady.value
      ? `Inactive sessions expire after ${activeOrg.value?.session_idle_timeout_minutes} minutes.`
      : `Set inactive browser, CLI, and MCP sessions to ${baselineIdleTimeoutMinutes} minutes or stricter.`,
    done: orgIdleTimeoutReady.value,
    to: '',
  },
  {
    key: 'trusted-device',
    label: 'Trusted-device reuse',
    detail: orgTrustedDeviceBypass.value
      ? 'Enrolled users can reuse trusted MFA devices where client policy allows it.'
      : 'Allow trusted devices to keep org-wide MFA practical for recurring sessions.',
    done: orgTrustedDeviceBypass.value,
    to: '',
  },
])
const baselineMissingCount = computed(() => baselineItems.value.filter((item) => !item.done).length)
const baselineNeedsMfa = computed(() => !currentUserMfaEnabled.value && !adminStepUpRequired.value)

function trustedDeviceStatus(client: AuthClient) {
  const clientRequiresMfa = Boolean(client.require_mfa)
  const orgRequiresMfa = orgMfaRequired.value
  if (!clientRequiresMfa && !orgRequiresMfa) {
    return { allowed: false, label: 'not required' }
  }
  const clientAllows = !clientRequiresMfa || Boolean(client.trusted_device_mfa_bypass)
  const orgAllows = !orgRequiresMfa || orgTrustedDeviceBypass.value
  const allowed = clientAllows && orgAllows
  return { allowed, label: allowed ? 'trusted device allowed' : 'trusted device blocked' }
}

function applyUpdatedOrg(updated: Org) {
  if (!setup.value) {
    return
  }
  const previous = activeOrg.value
  setup.value.org = previous ? { ...previous, ...updated } : updated
  setup.value.orgs = setup.value.orgs.map((org) => (org.id === updated.id ? { ...org, ...updated } : org))
}

async function load() {
  loading.value = true
  error.value = ''
  notice.value = ''
  try {
    const [setupStatus, clientRows] = await Promise.all([api.setupStatus(), api.clients()])
    setup.value = setupStatus
    clients.value = clientRows
    orgIdleTimeoutMinutes.value = setupStatus.org?.session_idle_timeout_minutes || null
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load policy'
  } finally {
    loading.value = false
  }
}

async function toggleOrgMfa() {
  if (!activeOrg.value) {
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const updated = await api.updateOrg(activeOrg.value.id, { require_mfa: !orgMfaRequired.value })
    applyUpdatedOrg(updated)
    notice.value = updated.require_mfa ? 'Organization MFA policy enabled.' : 'Organization MFA policy disabled.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update policy'
  } finally {
    saving.value = false
  }
}

async function toggleOrgTrustedDeviceBypass() {
  if (!activeOrg.value) {
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const updated = await api.updateOrg(activeOrg.value.id, {
      trusted_device_mfa_bypass: !orgTrustedDeviceBypass.value,
    })
    applyUpdatedOrg(updated)
    notice.value = updated.trusted_device_mfa_bypass
      ? 'Trusted-device MFA bypass enabled.'
      : 'Trusted-device MFA bypass disabled.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update trusted-device policy'
  } finally {
    saving.value = false
  }
}

async function toggleAdminStepUpMfa() {
  if (!activeOrg.value) {
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const updated = await api.updateOrg(activeOrg.value.id, {
      admin_step_up_mfa_required: !adminStepUpRequired.value,
    })
    applyUpdatedOrg(updated)
    notice.value = updated.admin_step_up_mfa_required
      ? 'Admin step-up policy enabled.'
      : 'Admin step-up policy disabled.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update admin step-up policy'
  } finally {
    saving.value = false
  }
}

async function saveOrgIdleTimeout() {
  if (!activeOrg.value) {
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const value = orgIdleTimeoutMinutes.value ? Number(orgIdleTimeoutMinutes.value) : null
    const updated = await api.updateOrg(activeOrg.value.id, { session_idle_timeout_minutes: value })
    applyUpdatedOrg(updated)
    orgIdleTimeoutMinutes.value = updated.session_idle_timeout_minutes || null
    notice.value = updated.session_idle_timeout_minutes
      ? `Organization idle timeout set to ${updated.session_idle_timeout_minutes} minutes.`
      : 'Organization idle timeout cleared.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update idle timeout'
  } finally {
    saving.value = false
  }
}

async function toggleUserHardDelete() {
  if (!activeOrg.value) {
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const updated = await api.updateOrg(activeOrg.value.id, {
      allow_user_hard_delete: !userHardDeleteAllowed.value,
    })
    applyUpdatedOrg(updated)
    notice.value = updated.allow_user_hard_delete
      ? 'User hard-delete policy enabled.'
      : 'User hard-delete policy disabled.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update account lifecycle policy'
  } finally {
    saving.value = false
  }
}

async function applyRecommendedBaseline() {
  if (!activeOrg.value) {
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const currentTimeout = activeOrg.value.session_idle_timeout_minutes || baselineIdleTimeoutMinutes
    const payload: {
      require_mfa: boolean
      trusted_device_mfa_bypass: boolean
      admin_step_up_mfa_required?: boolean
      session_idle_timeout_minutes: number
    } = {
      require_mfa: true,
      trusted_device_mfa_bypass: true,
      session_idle_timeout_minutes: Math.min(currentTimeout, baselineIdleTimeoutMinutes),
    }
    if (currentUserMfaEnabled.value || adminStepUpRequired.value) {
      payload.admin_step_up_mfa_required = true
    }

    const updated = await api.updateOrg(activeOrg.value.id, payload)
    applyUpdatedOrg(updated)
    orgIdleTimeoutMinutes.value = updated.session_idle_timeout_minutes || null
    notice.value = currentUserMfaEnabled.value || updated.admin_step_up_mfa_required
      ? 'Recommended policy baseline applied.'
      : 'Baseline applied. Enroll authenticator MFA to enable admin step-up safely.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not apply recommended baseline'
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">Policy</p>
        <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">Security and account policy</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Set the baseline assurance and account lifecycle rules for organization apps, CLI approvals, and product sessions.
        </p>
      </div>
      <button type="button" class="btn-secondary gap-2 text-sm" @click="load">
        <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
    </div>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading policy...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>

    <div v-else-if="setup" class="mt-8 grid gap-6">
      <article
        v-if="!canManage"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        This account can inspect policy but cannot update organization rules.
      </article>
      <article v-if="notice" class="rounded-md border border-green/35 bg-green/10 p-3 text-sm text-green">
        {{ notice }}
      </article>

      <article class="panel p-5">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="mono-label">Recommended baseline</p>
            <h2 class="mt-2 text-xl font-semibold">Production-ready session policy</h2>
            <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
              Apply the org-level guardrails most API-first installs need before connecting real products.
            </p>
          </div>
          <span
            class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
            :class="baselineMissingCount ? 'border-orange/45 bg-orange/10 text-orange' : 'border-green/35 bg-green/10 text-green'"
          >
            <ListChecks class="h-4 w-4" aria-hidden="true" />
            {{ baselineMissingCount ? `${baselineMissingCount} open` : 'ready' }}
          </span>
        </div>

        <div class="mt-5 divide-y divide-border/70">
          <div v-for="item in baselineItems" :key="item.key" class="grid gap-3 py-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
            <div>
              <p class="text-sm font-semibold">{{ item.label }}</p>
              <p class="mt-1 text-sm leading-6 text-muted">{{ item.detail }}</p>
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <span
                class="inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 font-mono text-xs"
                :class="item.done ? 'border-green/35 bg-green/10 text-green' : 'border-orange/45 bg-orange/10 text-orange'"
              >
                <ShieldCheck v-if="item.done" class="h-4 w-4" aria-hidden="true" />
                <ShieldAlert v-else class="h-4 w-4" aria-hidden="true" />
                {{ item.done ? 'ready' : 'open' }}
              </span>
              <RouterLink v-if="item.to && !item.done" :to="item.to" class="btn-secondary min-h-8 px-2.5 text-xs">
                <ArrowRight class="h-4 w-4" aria-hidden="true" />
                Open
              </RouterLink>
            </div>
          </div>
        </div>

        <div class="mt-5 flex flex-wrap items-center gap-3">
          <button
            type="button"
            class="btn-primary gap-2 text-sm"
            :disabled="saving || !canManage || !activeOrg"
            @click="applyRecommendedBaseline"
          >
            <ListChecks class="h-4 w-4" aria-hidden="true" />
            Apply baseline
          </button>
          <RouterLink v-if="baselineNeedsMfa" to="/account" class="btn-secondary gap-2 text-sm">
            <ArrowRight class="h-4 w-4" aria-hidden="true" />
            Enroll MFA
          </RouterLink>
        </div>
      </article>

      <div class="grid gap-4 md:grid-cols-5">
        <article class="panel p-5">
          <p class="text-sm text-muted">Organization</p>
          <h2 class="mt-2 text-xl font-semibold">{{ activeOrg?.name || 'No org' }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">{{ activeOrg?.slug || 'none' }}</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Org MFA</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ orgMfaRequired ? 'Required' : 'Optional' }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">registered org apps</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">App MFA</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ appMfaCount }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">clients with app policy</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Trusted Device</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ trustedDeviceAllowedCount }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">clients allowing reuse</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Admin Step-Up</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ adminStepUpRequired ? 'Required' : 'Optional' }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">sensitive mutations</p>
        </article>
        <article class="panel p-5 md:col-span-5">
          <p class="text-sm text-muted">Org idle timeout</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ orgIdleTimeoutLabel }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">applies to org-bound sessions unless a stricter client timeout is set</p>
        </article>
        <article class="panel p-5 md:col-span-5">
          <p class="text-sm text-muted">Hard delete</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ userHardDeleteAllowed ? 'Allowed' : 'Disabled' }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">permanent user purge policy</p>
        </article>
      </div>

      <article class="panel p-5">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="mono-label">Organization MFA</p>
            <h2 class="mt-2 text-xl font-semibold">Require authenticator MFA</h2>
            <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
              {{ orgMfaRequired ? 'Client-bound sessions must prove MFA.' : 'Client-bound sessions can use the client-level rule.' }}
            </p>
          </div>
          <span
            class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
            :class="orgMfaRequired ? 'border-green/35 bg-green/10 text-green' : 'border-border bg-surface text-muted'"
          >
            <ShieldCheck v-if="orgMfaRequired" class="h-4 w-4" aria-hidden="true" />
            <ShieldAlert v-else class="h-4 w-4" aria-hidden="true" />
            {{ orgMfaRequired ? 'enforced' : 'not enforced' }}
          </span>
        </div>
        <button type="button" class="btn-primary mt-5 gap-2 text-sm" :disabled="saving || !canManage || !activeOrg" @click="toggleOrgMfa">
          <ShieldCheck class="h-4 w-4" aria-hidden="true" />
          {{ orgMfaRequired ? 'Disable org MFA' : 'Enable org MFA' }}
        </button>
      </article>

      <article class="panel p-5">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="mono-label">Admin Step-Up</p>
            <h2 class="mt-2 text-xl font-semibold">Require MFA for sensitive changes</h2>
            <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
              Protect client secrets, providers, users, invitations, roles, API tokens, resources, and organization policy changes with session MFA.
            </p>
          </div>
          <span
            class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
            :class="adminStepUpRequired ? 'border-green/35 bg-green/10 text-green' : 'border-border bg-surface text-muted'"
          >
            <ShieldCheck v-if="adminStepUpRequired" class="h-4 w-4" aria-hidden="true" />
            <ShieldAlert v-else class="h-4 w-4" aria-hidden="true" />
            {{ adminStepUpRequired ? 'step-up required' : 'step-up optional' }}
          </span>
        </div>
        <button
          type="button"
          class="btn-primary mt-5 gap-2 text-sm"
          :disabled="saving || !canManage || !activeOrg"
          @click="toggleAdminStepUpMfa"
        >
          <ShieldCheck class="h-4 w-4" aria-hidden="true" />
          {{ adminStepUpRequired ? 'Disable admin step-up' : 'Require admin step-up' }}
        </button>
      </article>

      <article class="panel p-5">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="mono-label">Trusted Devices</p>
            <h2 class="mt-2 text-xl font-semibold">Allow trusted-device MFA reuse</h2>
            <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
              Trusted devices can satisfy org MFA only when the user has already enrolled authenticator MFA and every active app policy also allows reuse.
            </p>
          </div>
          <span
            class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
            :class="orgTrustedDeviceBypass ? 'border-green/35 bg-green/10 text-green' : 'border-border bg-surface text-muted'"
          >
            <ShieldCheck v-if="orgTrustedDeviceBypass" class="h-4 w-4" aria-hidden="true" />
            <ShieldAlert v-else class="h-4 w-4" aria-hidden="true" />
            {{ orgTrustedDeviceBypass ? 'allowed by org' : 'blocked by org' }}
          </span>
        </div>
        <button
          type="button"
          class="btn-primary mt-5 gap-2 text-sm"
          :disabled="saving || !canManage || !activeOrg || !orgMfaRequired"
          @click="toggleOrgTrustedDeviceBypass"
        >
          <ShieldCheck class="h-4 w-4" aria-hidden="true" />
          {{ orgTrustedDeviceBypass ? 'Disable trusted-device reuse' : 'Allow trusted-device reuse' }}
        </button>
      </article>

      <article class="panel p-5">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="mono-label">Idle Timeout</p>
            <h2 class="mt-2 text-xl font-semibold">Expire inactive sessions</h2>
            <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
              Set the organization idle window for browser, hosted app, CLI, and MCP sessions. Leave blank to rely on client policy or refresh-token expiry.
            </p>
          </div>
        </div>
        <div class="mt-5 flex flex-wrap items-end gap-3">
          <label class="grid w-48 gap-2 text-sm text-muted">
            Minutes
            <input
              v-model.number="orgIdleTimeoutMinutes"
              class="input"
              type="number"
              min="5"
              max="10080"
              placeholder="not set"
              :disabled="saving || !canManage || !activeOrg"
            />
          </label>
          <button type="button" class="btn-primary gap-2 text-sm" :disabled="saving || !canManage || !activeOrg" @click="saveOrgIdleTimeout">
            <ShieldCheck class="h-4 w-4" aria-hidden="true" />
            Save timeout
          </button>
        </div>
      </article>

      <article class="panel p-5">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="mono-label">Account Lifecycle</p>
            <h2 class="mt-2 text-xl font-semibold">Allow permanent user deletion</h2>
            <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
              Hard delete removes the user and user-owned auth artifacts after an admin preview, email confirmation, and last-owner checks.
            </p>
          </div>
          <span
            class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
            :class="userHardDeleteAllowed ? 'border-orange/45 bg-orange/10 text-orange' : 'border-green/35 bg-green/10 text-green'"
          >
            <Trash2 class="h-4 w-4" aria-hidden="true" />
            {{ userHardDeleteAllowed ? 'delete allowed' : 'delete blocked' }}
          </span>
        </div>
        <button
          type="button"
          class="btn-primary mt-5 gap-2 text-sm"
          :disabled="saving || !canManage || !activeOrg"
          @click="toggleUserHardDelete"
        >
          <Trash2 class="h-4 w-4" aria-hidden="true" />
          {{ userHardDeleteAllowed ? 'Disable hard delete' : 'Allow hard delete' }}
        </button>
      </article>

      <section class="grid gap-3">
        <div class="flex items-center justify-between gap-3">
          <p class="mono-label">Client policy</p>
          <RouterLink to="/clients" class="btn-secondary min-h-9 px-3 text-xs">Clients</RouterLink>
        </div>
        <article v-if="!activeOrgClients.length" class="panel p-4 text-sm text-muted">No clients registered yet.</article>
        <article v-for="client in activeOrgClients" v-else :key="client.id" class="panel p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 class="font-semibold">{{ client.name }}</h2>
              <p class="mt-1 break-all font-mono text-xs text-muted">{{ client.client_id }}</p>
            </div>
            <span
              class="rounded-md border border-border px-2 py-1 font-mono text-xs"
              :class="client.require_mfa || orgMfaRequired ? 'text-green' : 'text-muted'"
            >
              {{ client.require_mfa ? 'app mfa' : orgMfaRequired ? 'org mfa' : 'mfa optional' }}
            </span>
            <span
              class="rounded-md border border-border px-2 py-1 font-mono text-xs"
              :class="trustedDeviceStatus(client).allowed ? 'text-green' : 'text-muted'"
            >
              {{ trustedDeviceStatus(client).label }}
            </span>
            <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
              idle {{ client.session_idle_timeout_minutes || activeOrg?.session_idle_timeout_minutes || 'inherit' }}{{ client.session_idle_timeout_minutes || activeOrg?.session_idle_timeout_minutes ? 'm' : '' }}
            </span>
          </div>
        </article>
      </section>
    </div>
  </section>
</template>
