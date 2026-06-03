<script setup lang="ts">
import { CheckCircle2, Copy, KeyRound, MonitorCog, ShieldAlert, Terminal } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '@/services/api'
import type { ApiToken, AuthClient, Project, SetupStatus } from '@/types'

const status = ref<SetupStatus | null>(null)
const clients = ref<AuthClient[]>([])
const tokens = ref<ApiToken[]>([])
const projects = ref<Project[]>([])
const mcpResources = ref<Array<{ id: string; name: string; resource_uri: string; scopes: string[] }>>([])
const loading = ref(true)
const error = ref('')
const copied = ref(false)

const activeOrg = computed(() => status.value?.org || status.value?.orgs[0] || null)
const role = computed(() => activeOrg.value?.role || 'none')
const permissions = computed(() => activeOrg.value?.permissions || [])
const canManageMcp = computed(() => status.value?.scopes.includes('*') || status.value?.scopes.includes('mcp:*'))
const activeTokens = computed(() => tokens.value.filter((token) => !token.revoked_at))
const cliClient = computed(() => clients.value.find((client) => client.client_id === 'gatekeeper-cli'))
const sentinelClient = computed(() => clients.value.find((client) => client.audiences.includes('sentinel-api')))
const knowhereClient = computed(() => clients.value.find((client) => client.audiences.includes('knowhere-api')))

const sessionSummary = computed(() => {
  if (!status.value?.access_expires_at) {
    return 'Cookie or API-token session'
  }
  return `Access token expires ${new Date(status.value.access_expires_at).toLocaleString()}`
})

const setupSteps = computed(() => [
  {
    title: 'Owner confirmed',
    done: Boolean(status.value?.owner_exists && status.value?.can_manage_clients),
    detail: status.value?.can_manage_clients
      ? `${role.value} can manage setup for ${activeOrg.value?.name || 'this org'}`
      : `${role.value} can read this org but cannot create clients or tokens`,
    to: '/roles',
  },
  {
    title: 'Issuer and JWKS verified',
    done: Boolean(status.value?.issuer && status.value?.jwks_uri),
    detail: status.value ? `${status.value.issuer} -> ${status.value.jwks_uri}` : 'Waiting for runtime metadata',
    to: '/account',
  },
  {
    title: 'Sentinel client',
    done: Boolean(sentinelClient.value),
    detail: sentinelClient.value?.client_id || 'Register a client with sentinel-api as its audience',
    to: '/clients',
  },
  {
    title: 'Knowhere client',
    done: Boolean(knowhereClient.value),
    detail: knowhereClient.value?.client_id || 'Register a client with knowhere-api as its audience',
    to: '/clients',
  },
  {
    title: 'CLI/device login',
    done: Boolean(cliClient.value),
    detail: cliClient.value?.enabled ? 'gatekeeper-cli is enabled' : 'Default CLI client is missing or disabled',
    to: '/clients',
  },
  {
    title: 'Scoped service token',
    done: activeTokens.value.length > 0,
    detail: activeTokens.value.length ? `${activeTokens.value.length} active tokens` : 'Create copy-once service or project tokens',
    to: '/tokens',
  },
])

const unavailableReason = computed(() => {
  if (!status.value) {
    return ''
  }
  if (!status.value.owner_exists) {
    return 'No owner exists for this org. A fresh install should promote the first successful signup to owner.'
  }
  if (!status.value.can_manage_clients || !status.value.can_issue_tokens) {
    return 'This account is a viewer. Use an owner account for first setup, client registration, and token issuance.'
  }
  return ''
})

const integrationSnippet = computed(() => {
  if (!status.value) {
    return ''
  }
  return [
    `GATEKEEPER_ISSUER=${status.value.issuer}`,
    `GATEKEEPER_JWKS_URL=${status.value.jwks_uri}`,
    'GATEKEEPER_AUDIENCE=sentinel-api',
    'GATEKEEPER_REQUIRED_SCOPES=auth:read',
  ].join('\n')
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const setup = await api.setupStatus()
    status.value = setup
    const [clientRows, tokenRows, projectRows] = await Promise.all([
      api.clients(),
      api.tokens(),
      api.projects(setup.org?.id),
    ])
    clients.value = clientRows
    tokens.value = tokenRows
    projects.value = projectRows
    if (setup.scopes.includes('*') || setup.scopes.includes('mcp:*')) {
      mcpResources.value = await api.mcpResources()
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load setup console'
  } finally {
    loading.value = false
  }
}

async function copySnippet() {
  await navigator.clipboard.writeText(integrationSnippet.value)
  copied.value = true
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">Setup console</p>
        <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">GateKeeper control plane</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Confirm the owner path, register control-plane clients, issue scoped credentials, and copy integration values.
        </p>
      </div>
      <button type="button" class="btn-secondary gap-2 text-sm" @click="load">
        <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
    </div>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading setup console...</article>
    <article v-else-if="error" class="mt-8 rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
      {{ error }}
    </article>

    <div v-else-if="status" class="mt-8 grid gap-6">
      <article
        v-if="unavailableReason"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        <div class="flex gap-3">
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
          <p>{{ unavailableReason }}</p>
        </div>
      </article>

      <div class="grid gap-4 lg:grid-cols-4">
        <article class="panel p-5">
          <p class="text-sm text-muted">Signed in as</p>
          <h2 class="mt-2 break-all text-xl font-semibold">{{ status.user?.email || 'Unknown user' }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">{{ status.auth_type }}</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Organization</p>
          <h2 class="mt-2 text-xl font-semibold">{{ activeOrg?.name || 'No org' }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">{{ role }}</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Session</p>
          <h2 class="mt-2 text-xl font-semibold">{{ status.owner_exists ? 'Owner path ready' : 'Owner missing' }}</h2>
          <p class="mt-2 text-xs text-muted">{{ sessionSummary }}</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Email mode</p>
          <h2 class="mt-2 text-xl font-semibold">{{ status.smtp_configured ? 'SMTP' : 'Dev mode' }}</h2>
          <p class="mt-2 text-xs text-muted">
            {{ status.email_dev_mode ? 'Codes are not delivered by SMTP' : 'SMTP delivery required' }}
          </p>
        </article>
      </div>

      <div class="grid gap-6 lg:grid-cols-[1fr_0.85fr]">
        <section class="grid gap-3">
          <div class="flex items-center justify-between gap-3">
            <p class="mono-label">First-run wizard</p>
            <span class="font-mono text-xs text-muted">
              {{ setupSteps.filter((step) => step.done).length }}/{{ setupSteps.length }}
            </span>
          </div>
          <RouterLink
            v-for="step in setupSteps"
            :key="step.title"
            :to="step.to"
            class="panel grid gap-3 p-4 transition hover:border-border-active md:grid-cols-[auto_1fr_auto]"
          >
            <CheckCircle2
              class="h-5 w-5"
              :class="step.done ? 'text-green' : 'text-muted'"
              aria-hidden="true"
            />
            <div>
              <h2 class="font-semibold">{{ step.title }}</h2>
              <p class="mt-1 break-all text-sm text-muted">{{ step.detail }}</p>
            </div>
            <span class="self-center font-mono text-xs text-muted">{{ step.done ? 'ready' : 'next' }}</span>
          </RouterLink>
        </section>

        <section class="grid gap-4">
          <article class="panel p-5">
            <p class="mono-label">Capabilities</p>
            <div class="mt-4 flex flex-wrap gap-2">
              <span
                v-for="permission in permissions"
                :key="permission"
                class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted"
              >
                {{ permission }}
              </span>
              <span v-if="!permissions.length" class="text-sm text-muted">No org permissions returned.</span>
            </div>
          </article>

          <article class="panel p-5">
            <p class="mono-label">Next actions</p>
            <div class="mt-4 grid gap-3">
              <RouterLink
                to="/clients"
                class="btn-secondary justify-start gap-2 text-sm"
                :class="{ 'pointer-events-none opacity-60': !status.can_manage_clients }"
              >
                <MonitorCog class="h-4 w-4" aria-hidden="true" />
                Register app client
              </RouterLink>
              <RouterLink
                to="/tokens"
                class="btn-secondary justify-start gap-2 text-sm"
                :class="{ 'pointer-events-none opacity-60': !status.can_issue_tokens }"
              >
                <KeyRound class="h-4 w-4" aria-hidden="true" />
                Create service token
              </RouterLink>
              <RouterLink
                to="/device"
                class="btn-secondary justify-start gap-2 text-sm"
                :class="{ 'pointer-events-none opacity-60': !cliClient }"
              >
                <Terminal class="h-4 w-4" aria-hidden="true" />
                Approve CLI device login
              </RouterLink>
            </div>
          </article>

          <article class="panel p-5">
            <div class="flex items-center justify-between gap-3">
              <p class="mono-label">Integration values</p>
              <button type="button" class="btn-secondary min-h-9 gap-2 px-3 text-xs" @click="copySnippet">
                <Copy class="h-3.5 w-3.5" aria-hidden="true" />
                {{ copied ? 'Copied' : 'Copy' }}
              </button>
            </div>
            <pre class="mt-4 overflow-x-auto rounded-md bg-bg p-3 text-xs text-muted">{{ integrationSnippet }}</pre>
          </article>
        </section>
      </div>

      <div class="grid gap-4 md:grid-cols-4">
        <article class="panel p-5">
          <p class="text-sm text-muted">Clients</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ clients.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Active tokens</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ activeTokens.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Projects</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ projects.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">MCP resources</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ canManageMcp ? mcpResources.length : 'locked' }}</h2>
        </article>
      </div>
    </div>
  </section>
</template>
