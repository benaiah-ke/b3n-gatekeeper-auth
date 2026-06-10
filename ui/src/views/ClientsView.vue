<script setup lang="ts">
import { BadgeCheck, Check, Copy, ExternalLink, Power, PowerOff, RotateCcw, ShieldCheck, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuthClient, SetupStatus } from '@/types'

const templates = [
  {
    id: 'api-backend',
    label: 'API backend',
    name: 'Example API backend',
    public: false,
    redirects: '',
    audiences: 'example-api',
    scopes: ['api:read', 'token:*'],
  },
  {
    id: 'spa',
    label: 'Single-page app',
    name: 'Example web app',
    public: true,
    redirects: 'https://app.example.com/auth/callback',
    audiences: 'example-api',
    scopes: ['openid', 'profile', 'email', 'api:read'],
  },
  {
    id: 'server-web',
    label: 'Server web app',
    name: 'Example server app',
    public: false,
    redirects: 'https://app.example.com/auth/callback',
    audiences: 'example-api',
    scopes: ['openid', 'profile', 'email', 'api:read'],
  },
  {
    id: 'cli',
    label: 'CLI',
    name: 'GateKeeper CLI',
    public: true,
    redirects: '',
    audiences: 'example-api',
    scopes: ['openid', 'profile', 'email', 'cli:read'],
  },
  {
    id: 'mcp',
    label: 'MCP server',
    name: 'MCP resource server',
    public: false,
    redirects: 'https://mcp.example.com/oauth/callback',
    audiences: 'https://mcp.example.com',
    scopes: ['mcp:tools', 'mcp:resources'],
  },
  {
    id: 'machine',
    label: 'Machine service',
    name: 'Machine service',
    public: false,
    redirects: '',
    audiences: 'example-api',
    scopes: ['api:read'],
  },
]

const availableScopes = [
  'openid',
  'profile',
  'email',
  'auth:read',
  'api:read',
  'api:write',
  'token:*',
  'cli:read',
  'mcp:*',
  'mcp:tools',
  'mcp:resources',
]

interface ClientMetadataDraft {
  name: string
  description: string
  logo_url: string
  homepage_url: string
  privacy_policy_url: string
  terms_url: string
  publisher_name: string
  verified: boolean
}

const setup = ref<SetupStatus | null>(null)
const clients = ref<AuthClient[]>([])
const selectedTemplate = ref('api-backend')
const name = ref('Example API backend')
const clientId = ref('')
const description = ref('')
const logoUrl = ref('')
const homepageUrl = ref('')
const privacyPolicyUrl = ref('')
const termsUrl = ref('')
const publisherName = ref('')
const verifiedClient = ref(false)
const publicClient = ref(false)
const redirects = ref('')
const allowedOrigins = ref('')
const audiences = ref('example-api')
const scopes = ref<string[]>(['api:read', 'token:*'])
const mcpResourceUri = ref('')
const requireOrgMembership = ref(true)
const requireMfa = ref(false)
const trustedDeviceMfaBypass = ref(false)
const sessionIdleTimeoutMinutes = ref<number | null>(null)
const clientIdleTimeouts = ref<Record<string, number | null>>({})
const clientMetadataDrafts = ref<Record<string, ClientMetadataDraft>>({})
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const oneTimeSecret = ref('')
const copied = ref(false)

const canManage = computed(() => Boolean(setup.value?.can_manage_clients))
const activeOrgId = computed(() => setup.value?.org?.id || setup.value?.orgs[0]?.id || null)
const clientStats = computed(() => ({
  total: clients.value.length,
  public: clients.value.filter((client) => client.public).length,
  confidential: clients.value.filter((client) => !client.public).length,
  verified: clients.value.filter((client) => client.verified).length,
  mfa: clients.value.filter((client) => client.require_mfa).length,
}))

const redirectList = computed(() => parseLines(redirects.value))
const allowedOriginList = computed(() => {
  const explicit = parseLines(allowedOrigins.value)
  if (explicit.length) {
    return explicit
  }
  return Array.from(
    new Set(
      redirectList.value
        .map((value) => {
          try {
            return new URL(value).origin
          } catch {
            return ''
          }
        })
        .filter(Boolean),
    ),
  )
})
const audienceList = computed(() => parseLines(audiences.value))

function parseLines(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function applyTemplate(id: string) {
  const template = templates.find((item) => item.id === id) ?? templates[0]!
  selectedTemplate.value = template.id
  name.value = template.name
  clientId.value = ''
  description.value = ''
  logoUrl.value = ''
  homepageUrl.value = ''
  privacyPolicyUrl.value = ''
  termsUrl.value = ''
  publisherName.value = ''
  verifiedClient.value = false
  publicClient.value = template.public
  redirects.value = template.redirects
  allowedOrigins.value = ''
  audiences.value = template.audiences
  scopes.value = [...template.scopes]
  mcpResourceUri.value = template.id === 'mcp' ? template.audiences : ''
  requireMfa.value = false
  trustedDeviceMfaBypass.value = false
  sessionIdleTimeoutMinutes.value = null
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [setupStatus, clientRows] = await Promise.all([api.setupStatus(), api.clients()])
    setup.value = setupStatus
    clients.value = clientRows
    clientIdleTimeouts.value = Object.fromEntries(
      clientRows.map((client) => [client.id, client.session_idle_timeout_minutes || null]),
    )
    clientMetadataDrafts.value = Object.fromEntries(
      clientRows.map((client) => [
        client.id,
        {
          name: client.name,
          description: client.description || '',
          logo_url: client.logo_url || '',
          homepage_url: client.homepage_url || '',
          privacy_policy_url: client.privacy_policy_url || '',
          terms_url: client.terms_url || '',
          publisher_name: client.publisher_name || '',
          verified: client.verified,
        },
      ]),
    )
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load clients'
  } finally {
    loading.value = false
  }
}

async function create() {
  saving.value = true
  error.value = ''
  oneTimeSecret.value = ''
  copied.value = false
  try {
    const client = await api.createClient({
      name: name.value,
      client_id: clientId.value.trim() || undefined,
      org_id: activeOrgId.value,
      description: description.value || null,
      logo_url: logoUrl.value || null,
      homepage_url: homepageUrl.value || null,
      privacy_policy_url: privacyPolicyUrl.value || null,
      terms_url: termsUrl.value || null,
      publisher_name: publisherName.value || null,
      verified: verifiedClient.value,
      public: publicClient.value,
      redirect_uris: redirectList.value,
      allowed_origins: allowedOriginList.value,
      audiences: audienceList.value,
      scopes: scopes.value,
      require_org_membership: requireOrgMembership.value,
      require_mfa: requireMfa.value,
      trusted_device_mfa_bypass: trustedDeviceMfaBypass.value,
      session_idle_timeout_minutes: sessionIdleTimeoutMinutes.value || null,
      mcp_resource_uri: mcpResourceUri.value || null,
    })
    oneTimeSecret.value = client.client_secret || ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create client'
  } finally {
    saving.value = false
  }
}

async function toggleClient(client: AuthClient) {
  error.value = ''
  try {
    await api.updateClient(client.id, { enabled: !client.enabled })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update client'
  }
}

async function toggleMfaPolicy(client: AuthClient) {
  error.value = ''
  try {
    await api.updateClient(client.id, { require_mfa: !client.require_mfa })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update MFA policy'
  }
}

async function toggleTrustedDevicePolicy(client: AuthClient) {
  error.value = ''
  try {
    await api.updateClient(client.id, { trusted_device_mfa_bypass: !client.trusted_device_mfa_bypass })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update trusted-device policy'
  }
}

async function saveClientIdleTimeout(client: AuthClient) {
  error.value = ''
  try {
    await api.updateClient(client.id, {
      session_idle_timeout_minutes: clientIdleTimeouts.value[client.id] || null,
    })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update idle timeout'
  }
}

async function saveClientMetadata(client: AuthClient) {
  error.value = ''
  const draft = clientMetadataDrafts.value[client.id]
  if (!draft) {
    return
  }
  try {
    await api.updateClient(client.id, {
      name: draft.name,
      description: draft.description || null,
      logo_url: draft.logo_url || null,
      homepage_url: draft.homepage_url || null,
      privacy_policy_url: draft.privacy_policy_url || null,
      terms_url: draft.terms_url || null,
      publisher_name: draft.publisher_name || null,
      verified: draft.verified,
    })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update client metadata'
  }
}

async function rotateSecret(client: AuthClient) {
  error.value = ''
  oneTimeSecret.value = ''
  copied.value = false
  try {
    const rotated = await api.rotateClientSecret(client.id)
    oneTimeSecret.value = rotated.client_secret || ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not rotate secret'
  }
}

async function deleteClient(client: AuthClient) {
  error.value = ''
  try {
    await api.deleteClient(client.id)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not delete client'
  }
}

async function copySecret() {
  await navigator.clipboard.writeText(oneTimeSecret.value)
  copied.value = true
}

function setScope(scope: string, checked: boolean) {
  scopes.value = checked ? Array.from(new Set([...scopes.value, scope])) : scopes.value.filter((item) => item !== scope)
}

function metadataDraftValue(client: AuthClient, field: keyof Omit<ClientMetadataDraft, 'verified'>): string {
  return clientMetadataDrafts.value[client.id]?.[field] || ''
}

function updateMetadataDraft(client: AuthClient, field: keyof ClientMetadataDraft, value: string | boolean) {
  const draft = clientMetadataDrafts.value[client.id]
  if (!draft) {
    return
  }
  if (field === 'verified') {
    draft.verified = Boolean(value)
    return
  }
  draft[field] = String(value)
}

function clientLinks(client: AuthClient) {
  return [
    { label: 'Homepage', href: client.homepage_url },
    { label: 'Privacy', href: client.privacy_policy_url },
    { label: 'Terms', href: client.terms_url },
  ].filter((item): item is { label: string; href: string } => Boolean(item.href))
}

function listSummary(items: string[], emptyLabel = 'not set') {
  if (!items.length) {
    return emptyLabel
  }
  if (items.length <= 2) {
    return items.join(', ')
  }
  return `${items.slice(0, 2).join(', ')} +${items.length - 2}`
}

function formatDate(value?: string | null) {
  return value ? new Date(value).toLocaleString() : 'not set'
}

function metadataDirty(client: AuthClient) {
  const draft = clientMetadataDrafts.value[client.id]
  if (!draft) {
    return false
  }
  return (
    draft.name !== client.name ||
    draft.description !== (client.description || '') ||
    draft.logo_url !== (client.logo_url || '') ||
    draft.homepage_url !== (client.homepage_url || '') ||
    draft.privacy_policy_url !== (client.privacy_policy_url || '') ||
    draft.terms_url !== (client.terms_url || '') ||
    draft.publisher_name !== (client.publisher_name || '') ||
    draft.verified !== client.verified
  )
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">OAuth clients</p>
        <h1 class="mt-3 text-2xl font-semibold leading-tight md:text-3xl">Application registration</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Register product apps, CLIs, APIs, and MCP resources from one focused inventory.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <span class="rounded-md border border-border bg-surface px-3 py-2 text-sm text-muted">
          {{ clientStats.total }} total
        </span>
        <span class="rounded-md border border-border bg-surface px-3 py-2 text-sm text-muted">
          {{ clientStats.verified }} verified
        </span>
        <span class="rounded-md border border-border bg-surface px-3 py-2 text-sm text-muted">
          {{ clientStats.mfa }} MFA
        </span>
      </div>
    </div>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading clients...</article>

    <div v-if="!loading" class="mt-8 grid gap-5">
      <article v-if="error" class="rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
        {{ error }}
      </article>

      <article
        v-if="!canManage"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        This account can list clients but cannot create, rotate, disable, or delete them. Use an owner account for setup.
      </article>

      <details class="panel overflow-hidden" :open="!clients.length">
        <summary class="cursor-pointer list-none p-5">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p class="text-sm font-semibold">Create client</p>
              <p class="mt-1 text-sm text-muted">Start from a template, then fill only the fields this app needs.</p>
            </div>
            <span class="rounded-md border border-border px-3 py-2 font-mono text-xs text-accent">
              {{ selectedTemplate }}
            </span>
          </div>
        </summary>

        <form class="grid gap-5 border-t border-border p-5" :class="{ 'opacity-60': !canManage }" @submit.prevent="create">
          <fieldset class="grid gap-5" :disabled="!canManage">
            <section class="grid gap-4 md:grid-cols-[0.8fr_1.2fr_1.2fr]">
              <label class="grid gap-2 text-sm text-muted">
                Template
                <select class="input" :value="selectedTemplate" @change="applyTemplate(($event.target as HTMLSelectElement).value)">
                  <option v-for="template in templates" :key="template.id" :value="template.id">{{ template.label }}</option>
                </select>
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Client name
                <input v-model="name" class="input" required />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Client ID
                <input v-model="clientId" class="input font-mono" placeholder="optional-stable-id" />
              </label>
            </section>

            <section class="grid gap-4 md:grid-cols-2">
              <label class="grid gap-2 text-sm text-muted md:col-span-2">
                Consent description
                <textarea v-model="description" class="input min-h-20 text-sm" maxlength="1000" />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Homepage URL
                <input v-model="homepageUrl" class="input font-mono" type="url" />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Publisher
                <input v-model="publisherName" class="input" maxlength="160" />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Logo URL
                <input v-model="logoUrl" class="input font-mono" type="url" />
              </label>
              <label class="flex min-h-12 items-center gap-2 rounded-md border border-border bg-surface px-3 text-sm text-muted">
                <input v-model="verifiedClient" type="checkbox" class="accent-[var(--color-accent)]" />
                Verified app
              </label>
            </section>

            <section class="grid gap-4 md:grid-cols-2">
              <label class="grid gap-2 text-sm text-muted">
                Redirect URIs
                <textarea v-model="redirects" class="input min-h-28 font-mono text-sm" />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Audiences
                <textarea v-model="audiences" class="input min-h-28 font-mono text-sm" />
              </label>
            </section>

            <details class="rounded-md border border-border bg-bg/40 p-4">
              <summary class="cursor-pointer text-sm font-semibold">Advanced settings</summary>
              <div class="mt-4 grid gap-5">
                <div class="grid gap-4 md:grid-cols-2">
                  <label class="grid gap-2 text-sm text-muted">
                    Privacy policy URL
                    <input v-model="privacyPolicyUrl" class="input font-mono" type="url" />
                  </label>
                  <label class="grid gap-2 text-sm text-muted">
                    Terms URL
                    <input v-model="termsUrl" class="input font-mono" type="url" />
                  </label>
                  <label class="grid gap-2 text-sm text-muted">
                    Allowed origins
                    <textarea
                      v-model="allowedOrigins"
                      class="input min-h-24 font-mono text-sm"
                      placeholder="Derived from redirects when blank"
                    />
                  </label>
                  <label class="grid gap-2 text-sm text-muted">
                    MCP resource URI
                    <input v-model="mcpResourceUri" class="input font-mono" placeholder="https://mcp.example.com" />
                  </label>
                </div>

                <div class="grid gap-3">
                  <p class="text-sm text-muted">Scopes</p>
                  <div class="flex flex-wrap gap-2">
                    <label
                      v-for="scope in availableScopes"
                      :key="scope"
                      class="inline-flex min-h-10 items-center gap-2 rounded-md border border-border bg-surface px-3 font-mono text-xs text-muted"
                    >
                      <input
                        type="checkbox"
                        :checked="scopes.includes(scope)"
                        @change="setScope(scope, ($event.target as HTMLInputElement).checked)"
                      />
                      {{ scope }}
                    </label>
                  </div>
                </div>

                <div class="grid gap-3">
                  <div class="flex flex-wrap gap-2">
                    <button
                      type="button"
                      class="btn-secondary min-h-10 px-4 text-sm"
                      :class="{ 'border-accent text-accent': publicClient }"
                      @click="publicClient = true"
                    >
                      Public
                    </button>
                    <button
                      type="button"
                      class="btn-secondary min-h-10 px-4 text-sm"
                      :class="{ 'border-accent text-accent': !publicClient }"
                      @click="publicClient = false"
                    >
                      Confidential
                    </button>
                  </div>
                  <label class="inline-flex items-center gap-2 text-sm text-muted">
                    <input v-model="requireOrgMembership" type="checkbox" />
                    Require org membership
                  </label>
                  <label class="inline-flex items-center gap-2 text-sm text-muted">
                    <input v-model="requireMfa" type="checkbox" />
                    Require authenticator MFA for user sessions
                  </label>
                  <label class="inline-flex items-center gap-2 text-sm text-muted">
                    <input v-model="trustedDeviceMfaBypass" type="checkbox" :disabled="!requireMfa" />
                    Allow trusted devices to satisfy MFA policy
                  </label>
                  <label class="grid max-w-56 gap-2 text-sm text-muted">
                    Idle timeout minutes
                    <input
                      v-model.number="sessionIdleTimeoutMinutes"
                      class="input"
                      type="number"
                      min="5"
                      max="10080"
                      placeholder="inherit"
                    />
                  </label>
                  <p class="break-all font-mono text-xs text-muted">Allowed origins preview: {{ allowedOriginList.join(', ') || 'none' }}</p>
                </div>
              </div>
            </details>
          </fieldset>

          <button class="btn-primary justify-self-start" :disabled="saving || !canManage">
            {{ saving ? 'Creating' : 'Create client' }}
          </button>
        </form>
      </details>

      <article v-if="oneTimeSecret" class="panel grid gap-3 p-4 md:grid-cols-[1fr_auto]">
        <div>
          <p class="text-sm font-semibold text-green">Client secret shown once</p>
          <p class="mt-2 break-all font-mono text-sm text-muted">{{ oneTimeSecret }}</p>
        </div>
        <button type="button" class="btn-secondary gap-2 text-sm" @click="copySecret">
          <Check v-if="copied" class="h-4 w-4" aria-hidden="true" />
          <Copy v-else class="h-4 w-4" aria-hidden="true" />
          {{ copied ? 'Copied' : 'Copy' }}
        </button>
      </article>

      <div class="grid gap-3">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p class="text-sm font-semibold">Registered clients</p>
            <p class="mt-1 text-sm text-muted">
              {{ clientStats.public }} public, {{ clientStats.confidential }} confidential.
            </p>
          </div>
        </div>

        <article v-if="!clients.length" class="panel p-4 text-sm text-muted">No clients registered yet.</article>
        <article v-for="client in clients" v-else :key="client.id" class="panel overflow-hidden">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="flex min-w-0 gap-3 p-4">
              <img
                v-if="client.logo_url"
                :src="client.logo_url"
                :alt="`${client.name} logo`"
                class="h-11 w-11 shrink-0 rounded-md border border-border object-cover"
              />
              <div class="min-w-0">
                <h2 class="font-semibold">{{ client.name }}</h2>
                <p class="mt-1 break-all font-mono text-xs text-muted">{{ client.client_id }}</p>
                <p class="mt-2 max-w-2xl text-sm leading-6 text-muted">
                  {{ client.description || 'No consent description yet.' }}
                </p>
              </div>
            </div>
            <div class="flex flex-wrap gap-2 p-4">
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
                {{ client.public ? 'public' : 'confidential' }}
              </span>
              <span
                class="inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-xs"
                :class="client.verified ? 'border-green/35 bg-green/10 text-green' : 'border-orange/45 bg-orange/10 text-orange'"
              >
                <BadgeCheck class="h-3.5 w-3.5" aria-hidden="true" />
                {{ client.verified ? 'verified' : 'unverified' }}
              </span>
              <span
                class="rounded-md border border-border px-2 py-1 font-mono text-xs"
                :class="client.require_mfa ? 'text-green' : 'text-muted'"
              >
                {{ client.require_mfa ? 'mfa required' : 'mfa optional' }}
              </span>
              <span
                class="rounded-md border border-border px-2 py-1 font-mono text-xs"
                :class="client.trusted_device_mfa_bypass ? 'text-green' : 'text-muted'"
              >
                {{ client.trusted_device_mfa_bypass ? 'trusted device ok' : 'trusted device off' }}
              </span>
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs" :class="client.enabled ? 'text-green' : 'text-red'">
                {{ client.enabled ? 'enabled' : 'disabled' }}
              </span>
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
                idle {{ client.session_idle_timeout_minutes ? `${client.session_idle_timeout_minutes}m` : 'inherit' }}
              </span>
            </div>
          </div>

          <div class="grid gap-3 border-t border-border p-4 md:grid-cols-3">
            <div>
              <p class="mono-label">Redirects</p>
              <p class="mt-2 break-all font-mono text-xs text-muted">{{ listSummary(client.redirect_uris, 'none') }}</p>
            </div>
            <div>
              <p class="mono-label">Audiences</p>
              <p class="mt-2 break-all font-mono text-xs text-muted">{{ listSummary(client.audiences, 'none') }}</p>
            </div>
            <div>
              <p class="mono-label">Scopes</p>
              <p class="mt-2 break-all font-mono text-xs text-muted">{{ listSummary(client.scopes, 'none') }}</p>
            </div>
          </div>

          <div v-if="clientLinks(client).length" class="flex flex-wrap gap-2 border-t border-border px-4 py-3">
            <a
              v-for="link in clientLinks(client)"
              :key="link.label"
              class="btn-secondary min-h-9 gap-2 px-3 text-xs"
              :href="link.href"
              target="_blank"
              rel="noreferrer"
            >
              {{ link.label }}
              <ExternalLink class="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          </div>

          <div class="grid border-t border-border md:grid-cols-3">
            <details v-if="clientMetadataDrafts[client.id]" class="border-border p-4 md:border-r">
              <summary class="cursor-pointer text-sm font-semibold">
                Consent metadata
                <span v-if="metadataDirty(client)" class="ml-2 rounded-md border border-accent/40 px-2 py-0.5 font-mono text-[0.68rem] text-accent">
                  unsaved
                </span>
              </summary>
              <form class="mt-4 grid gap-3" @submit.prevent="saveClientMetadata(client)">
                <label class="grid gap-2 text-xs text-muted">
                  Client name
                  <input
                    :value="metadataDraftValue(client, 'name')"
                    class="input text-sm"
                    :disabled="!canManage"
                    @input="updateMetadataDraft(client, 'name', ($event.target as HTMLInputElement).value)"
                  />
                </label>
                <label class="grid gap-2 text-xs text-muted">
                  Consent description
                  <textarea
                    :value="metadataDraftValue(client, 'description')"
                    class="input min-h-20 text-sm"
                    maxlength="1000"
                    :disabled="!canManage"
                    @input="updateMetadataDraft(client, 'description', ($event.target as HTMLTextAreaElement).value)"
                  />
                </label>
                <label class="grid gap-2 text-xs text-muted">
                  Homepage URL
                  <input
                    :value="metadataDraftValue(client, 'homepage_url')"
                    class="input font-mono text-sm"
                    type="url"
                    :disabled="!canManage"
                    @input="updateMetadataDraft(client, 'homepage_url', ($event.target as HTMLInputElement).value)"
                  />
                </label>
                <label class="grid gap-2 text-xs text-muted">
                  Publisher
                  <input
                    :value="metadataDraftValue(client, 'publisher_name')"
                    class="input text-sm"
                    maxlength="160"
                    :disabled="!canManage"
                    @input="updateMetadataDraft(client, 'publisher_name', ($event.target as HTMLInputElement).value)"
                  />
                </label>
                <details class="rounded-md border border-border bg-bg/40 p-3">
                  <summary class="cursor-pointer text-xs font-semibold text-muted">More consent fields</summary>
                  <div class="mt-3 grid gap-3">
                    <label class="grid gap-2 text-xs text-muted">
                      Logo URL
                      <input
                        :value="metadataDraftValue(client, 'logo_url')"
                        class="input font-mono text-sm"
                        type="url"
                        :disabled="!canManage"
                        @input="updateMetadataDraft(client, 'logo_url', ($event.target as HTMLInputElement).value)"
                      />
                    </label>
                    <label class="grid gap-2 text-xs text-muted">
                      Privacy policy URL
                      <input
                        :value="metadataDraftValue(client, 'privacy_policy_url')"
                        class="input font-mono text-sm"
                        type="url"
                        :disabled="!canManage"
                        @input="updateMetadataDraft(client, 'privacy_policy_url', ($event.target as HTMLInputElement).value)"
                      />
                    </label>
                    <label class="grid gap-2 text-xs text-muted">
                      Terms URL
                      <input
                        :value="metadataDraftValue(client, 'terms_url')"
                        class="input font-mono text-sm"
                        type="url"
                        :disabled="!canManage"
                        @input="updateMetadataDraft(client, 'terms_url', ($event.target as HTMLInputElement).value)"
                      />
                    </label>
                  </div>
                </details>
                <label class="flex min-h-10 items-center gap-2 rounded-md border border-border bg-bg px-3 text-xs text-muted">
                  <input
                    :checked="clientMetadataDrafts[client.id]?.verified"
                    type="checkbox"
                    class="accent-[var(--color-accent)]"
                    :disabled="!canManage"
                    @change="updateMetadataDraft(client, 'verified', ($event.target as HTMLInputElement).checked)"
                  />
                  Verified app
                </label>
                <button class="btn-primary min-h-10 justify-self-start px-3 text-xs" :disabled="!canManage || !metadataDirty(client)">
                  Save metadata
                </button>
              </form>
            </details>

            <details class="border-border p-4 md:border-r">
              <summary class="cursor-pointer text-sm font-semibold">Runtime policy</summary>
              <div class="mt-4 grid gap-3">
                <label class="flex min-h-10 items-center gap-2 rounded-md border border-border bg-surface px-3 text-xs text-muted">
                  Idle
                  <input
                    v-model.number="clientIdleTimeouts[client.id]"
                    class="w-20 bg-transparent font-mono text-fg outline-none"
                    type="number"
                    min="5"
                    max="10080"
                    placeholder="inherit"
                    :disabled="!canManage"
                  />
                </label>
                <button
                  type="button"
                  class="btn-secondary min-h-10 gap-2 px-3 text-xs"
                  :disabled="!canManage"
                  @click="saveClientIdleTimeout(client)"
                >
                  Save idle
                </button>
                <button
                  type="button"
                  class="btn-secondary min-h-10 gap-2 px-3 text-xs"
                  :disabled="!canManage"
                  @click="toggleMfaPolicy(client)"
                >
                  {{ client.require_mfa ? 'Make MFA optional' : 'Require MFA' }}
                </button>
                <button
                  type="button"
                  class="btn-secondary min-h-10 gap-2 px-3 text-xs"
                  :disabled="!canManage || !client.require_mfa"
                  @click="toggleTrustedDevicePolicy(client)"
                >
                  <ShieldCheck class="h-3.5 w-3.5" aria-hidden="true" />
                  {{ client.trusted_device_mfa_bypass ? 'Disable trusted device' : 'Allow trusted device' }}
                </button>
                <button type="button" class="btn-secondary min-h-10 gap-2 px-3 text-xs" :disabled="!canManage" @click="toggleClient(client)">
                  <PowerOff v-if="client.enabled" class="h-3.5 w-3.5" aria-hidden="true" />
                  <Power v-else class="h-3.5 w-3.5" aria-hidden="true" />
                  {{ client.enabled ? 'Disable' : 'Enable' }}
                </button>
              </div>
            </details>

            <details class="p-4">
              <summary class="cursor-pointer text-sm font-semibold">Integration values</summary>
              <div class="mt-4 grid gap-3 text-xs text-muted">
                <p class="break-all font-mono">redirects: {{ client.redirect_uris.join(', ') || 'none' }}</p>
                <p class="break-all font-mono">audiences: {{ client.audiences.join(', ') || 'none' }}</p>
                <p class="break-all font-mono">origins: {{ client.allowed_origins.join(', ') || 'none' }}</p>
                <p class="break-all font-mono">scopes: {{ client.scopes.join(' ') || 'none' }}</p>
                <p class="break-all font-mono">publisher: {{ client.publisher_name || 'not set' }}</p>
                <p class="break-all font-mono">verified: {{ formatDate(client.verified_at) }}</p>
                <div class="mt-2 flex flex-wrap gap-2">
                  <button
                    type="button"
                    class="btn-secondary min-h-10 gap-2 px-3 text-xs"
                    :disabled="!canManage || client.public"
                    @click="rotateSecret(client)"
                  >
                    <RotateCcw class="h-3.5 w-3.5" aria-hidden="true" />
                    Rotate secret
                  </button>
                  <button
                    type="button"
                    class="btn-secondary min-h-10 gap-2 px-3 text-xs"
                    :disabled="!canManage || client.client_id === 'gatekeeper-cli'"
                    @click="deleteClient(client)"
                  >
                    <Trash2 class="h-3.5 w-3.5" aria-hidden="true" />
                    Delete
                  </button>
                </div>
              </div>
            </details>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
