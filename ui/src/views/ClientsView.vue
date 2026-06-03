<script setup lang="ts">
import { Check, Copy, Power, PowerOff, RotateCcw, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuthClient, SetupStatus } from '@/types'

const templates = [
  {
    id: 'sentinel',
    label: 'Sentinel',
    name: 'Sentinel',
    public: false,
    redirects: 'https://sentinel.b3n.in/api/v1/auth/callback',
    audiences: 'sentinel-api',
    scopes: ['auth:read', 'token:*'],
  },
  {
    id: 'knowhere',
    label: 'Knowhere',
    name: 'Knowhere',
    public: false,
    redirects: 'https://knowhere.b3n.in/api/v1/auth/callback',
    audiences: 'knowhere-api',
    scopes: ['auth:read'],
  },
  {
    id: 'cli',
    label: 'CLI',
    name: 'GateKeeper CLI',
    public: true,
    redirects: '',
    audiences: 'gatekeeper-api',
    scopes: ['auth:read', 'token:*', 'mcp:*'],
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
    id: 'generic',
    label: 'Generic OAuth app',
    name: 'OAuth app',
    public: true,
    redirects: 'http://localhost:3000/callback',
    audiences: 'gatekeeper-api',
    scopes: ['openid', 'profile', 'email', 'auth:read'],
  },
]

const availableScopes = ['openid', 'profile', 'email', 'auth:read', 'token:*', 'mcp:*', 'mcp:tools', 'mcp:resources']

const setup = ref<SetupStatus | null>(null)
const clients = ref<AuthClient[]>([])
const selectedTemplate = ref('sentinel')
const name = ref('Sentinel')
const publicClient = ref(false)
const redirects = ref('https://sentinel.b3n.in/api/v1/auth/callback')
const allowedOrigins = ref('')
const audiences = ref('sentinel-api')
const scopes = ref<string[]>(['auth:read', 'token:*'])
const mcpResourceUri = ref('')
const requireOrgMembership = ref(true)
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const oneTimeSecret = ref('')
const copied = ref(false)

const canManage = computed(() => Boolean(setup.value?.can_manage_clients))
const activeOrgId = computed(() => setup.value?.org?.id || setup.value?.orgs[0]?.id || null)

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
  publicClient.value = template.public
  redirects.value = template.redirects
  allowedOrigins.value = ''
  audiences.value = template.audiences
  scopes.value = [...template.scopes]
  mcpResourceUri.value = template.id === 'mcp' ? template.audiences : ''
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [setupStatus, clientRows] = await Promise.all([api.setupStatus(), api.clients()])
    setup.value = setupStatus
    clients.value = clientRows
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
      org_id: activeOrgId.value,
      public: publicClient.value,
      redirect_uris: redirectList.value,
      allowed_origins: allowedOriginList.value,
      audiences: audienceList.value,
      scopes: scopes.value,
      require_org_membership: requireOrgMembership.value,
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

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <p class="mono-label">OAuth clients</p>
    <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">Application registration</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
      Register UI apps, service clients, CLIs, and MCP resources with explicit redirects, origins, audiences, and scopes.
    </p>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading clients...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <article
        v-if="!canManage"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        This account can list clients but cannot create, rotate, disable, or delete them. Use an owner account for setup.
      </article>

      <form class="panel grid gap-5 p-5" :class="{ 'opacity-60': !canManage }" @submit.prevent="create">
        <div class="grid gap-4 md:grid-cols-[0.8fr_1.2fr]">
          <label class="grid gap-2 text-sm text-muted">
            Template
            <select class="input" :value="selectedTemplate" :disabled="!canManage" @change="applyTemplate(($event.target as HTMLSelectElement).value)">
              <option v-for="template in templates" :key="template.id" :value="template.id">{{ template.label }}</option>
            </select>
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Client name
            <input v-model="name" class="input" :disabled="!canManage" required />
          </label>
        </div>

        <div class="flex flex-wrap gap-2">
          <button
            type="button"
            class="btn-secondary min-h-10 px-4 text-sm"
            :class="{ 'border-accent text-accent': publicClient }"
            :disabled="!canManage"
            @click="publicClient = true"
          >
            Public
          </button>
          <button
            type="button"
            class="btn-secondary min-h-10 px-4 text-sm"
            :class="{ 'border-accent text-accent': !publicClient }"
            :disabled="!canManage"
            @click="publicClient = false"
          >
            Confidential
          </button>
        </div>

        <div class="grid gap-4 md:grid-cols-2">
          <label class="grid gap-2 text-sm text-muted">
            Redirect URIs
            <textarea v-model="redirects" class="input min-h-28 font-mono text-sm" :disabled="!canManage" />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Audiences
            <textarea v-model="audiences" class="input min-h-28 font-mono text-sm" :disabled="!canManage" />
          </label>
        </div>

        <div class="grid gap-4 md:grid-cols-2">
          <label class="grid gap-2 text-sm text-muted">
            Allowed origins
            <textarea
              v-model="allowedOrigins"
              class="input min-h-24 font-mono text-sm"
              placeholder="Derived from redirects when blank"
              :disabled="!canManage"
            />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            MCP resource URI
            <input v-model="mcpResourceUri" class="input font-mono" :disabled="!canManage" placeholder="https://mcp.example.com" />
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
                :disabled="!canManage"
                @change="setScope(scope, ($event.target as HTMLInputElement).checked)"
              />
              {{ scope }}
            </label>
          </div>
        </div>

        <div class="grid gap-2">
          <label class="inline-flex items-center gap-2 text-sm text-muted">
            <input v-model="requireOrgMembership" type="checkbox" :disabled="!canManage" />
            Require org membership
          </label>
          <p class="break-all font-mono text-xs text-muted">Allowed origins preview: {{ allowedOriginList.join(', ') || 'none' }}</p>
        </div>

        <button class="btn-primary justify-self-start" :disabled="saving || !canManage">
          {{ saving ? 'Creating' : 'Create client' }}
        </button>
      </form>

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
        <article v-if="!clients.length" class="panel p-4 text-sm text-muted">No clients registered yet.</article>
        <article v-for="client in clients" v-else :key="client.id" class="panel p-4">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 class="font-semibold">{{ client.name }}</h2>
              <p class="mt-1 break-all font-mono text-xs text-muted">{{ client.client_id }}</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
                {{ client.public ? 'public' : 'confidential' }}
              </span>
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs" :class="client.enabled ? 'text-green' : 'text-red'">
                {{ client.enabled ? 'enabled' : 'disabled' }}
              </span>
            </div>
          </div>
          <div class="mt-4 grid gap-2 text-xs text-muted md:grid-cols-2">
            <p class="break-all font-mono">redirects: {{ client.redirect_uris.join(', ') || 'none' }}</p>
            <p class="break-all font-mono">audiences: {{ client.audiences.join(', ') || 'none' }}</p>
            <p class="break-all font-mono">origins: {{ client.allowed_origins.join(', ') || 'none' }}</p>
            <p class="break-all font-mono">scopes: {{ client.scopes.join(' ') || 'none' }}</p>
          </div>
          <div class="mt-4 flex flex-wrap gap-2">
            <button type="button" class="btn-secondary min-h-10 gap-2 px-3 text-xs" :disabled="!canManage" @click="toggleClient(client)">
              <PowerOff v-if="client.enabled" class="h-3.5 w-3.5" aria-hidden="true" />
              <Power v-else class="h-3.5 w-3.5" aria-hidden="true" />
              {{ client.enabled ? 'Disable' : 'Enable' }}
            </button>
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
        </article>
      </div>
    </div>
  </section>
</template>
