<script setup lang="ts">
import { Check, Copy, RotateCcw, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { ApiToken, AuthClient, Project, SetupStatus } from '@/types'

const scopeOptions = ['auth:read', 'token:*', 'mcp:*', 'mcp:tools', 'mcp:resources', 'admin:*']
const tokenTypes = ['personal', 'service', 'project', 'admin', 'machine']

const setup = ref<SetupStatus | null>(null)
const tokens = ref<ApiToken[]>([])
const clients = ref<AuthClient[]>([])
const projects = ref<Project[]>([])
const resources = ref<Array<{ id: string; name: string; resource_uri: string; scopes: string[] }>>([])
const name = ref('Service token')
const tokenType = ref('service')
const selectedScopes = ref<string[]>(['auth:read'])
const selectedAudience = ref('gatekeeper-api')
const projectId = ref('')
const clientId = ref('')
const expiresAt = ref('')
const createdToken = ref('')
const copied = ref(false)
const loading = ref(true)
const saving = ref(false)
const error = ref('')

const canIssue = computed(() => Boolean(setup.value?.can_issue_tokens))
const activeOrgId = computed(() => setup.value?.org?.id || setup.value?.orgs[0]?.id || null)
const audienceOptions = computed(() => {
  const values = new Set<string>(['gatekeeper-api'])
  for (const client of clients.value) {
    for (const audience of client.audiences) {
      values.add(audience)
    }
  }
  for (const project of projects.value) {
    values.add(project.audience)
  }
  for (const resource of resources.value) {
    values.add(resource.resource_uri)
  }
  return Array.from(values).sort()
})

function checked(event: Event) {
  return Boolean((event.target as HTMLInputElement).checked)
}

function setScope(scope: string, isChecked: boolean) {
  selectedScopes.value = isChecked
    ? Array.from(new Set([...selectedScopes.value, scope]))
    : selectedScopes.value.filter((item) => item !== scope)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const setupStatus = await api.setupStatus()
    setup.value = setupStatus
    const [tokenRows, clientRows, projectRows] = await Promise.all([
      api.tokens(),
      api.clients(),
      api.projects(setupStatus.org?.id),
    ])
    tokens.value = tokenRows
    clients.value = clientRows
    projects.value = projectRows
    if (setupStatus.scopes.includes('*') || setupStatus.scopes.includes('mcp:*')) {
      resources.value = await api.mcpResources()
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load tokens'
  } finally {
    loading.value = false
  }
}

async function create() {
  saving.value = true
  error.value = ''
  copied.value = false
  createdToken.value = ''
  try {
    const token = await api.createToken({
      name: name.value,
      token_type: tokenType.value,
      org_id: activeOrgId.value,
      project_id: projectId.value || null,
      client_id: clientId.value || null,
      scopes: selectedScopes.value,
      audiences: selectedAudience.value ? [selectedAudience.value] : [],
      expires_at: expiresAt.value ? new Date(expiresAt.value).toISOString() : null,
    })
    createdToken.value = token.token || ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create token'
  } finally {
    saving.value = false
  }
}

async function revoke(id: string) {
  error.value = ''
  try {
    await api.revokeToken(id)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not revoke token'
  }
}

async function rotate(id: string) {
  error.value = ''
  copied.value = false
  createdToken.value = ''
  try {
    const token = await api.rotateToken(id)
    createdToken.value = token.token || ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not rotate token'
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
    <p class="mono-label">API tokens</p>
    <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">Scoped credentials</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
      Issue copy-once personal, service, project, admin, and machine tokens with explicit audiences and expiries.
    </p>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading tokens...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <article
        v-if="!canIssue"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        This account can inspect token metadata but cannot issue, rotate, or revoke tokens. Use an owner account for setup.
      </article>

      <form class="panel grid gap-5 p-5" :class="{ 'opacity-60': !canIssue }" @submit.prevent="create">
        <div class="grid gap-4 md:grid-cols-3">
          <label class="grid gap-2 text-sm text-muted">
            Name
            <input v-model="name" class="input" :disabled="!canIssue" required />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Type
            <select v-model="tokenType" class="input" :disabled="!canIssue">
              <option v-for="type in tokenTypes" :key="type" :value="type">{{ type }}</option>
            </select>
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Audience
            <select v-model="selectedAudience" class="input font-mono" :disabled="!canIssue">
              <option v-for="audience in audienceOptions" :key="audience" :value="audience">{{ audience }}</option>
            </select>
          </label>
        </div>

        <div class="grid gap-4 md:grid-cols-3">
          <label class="grid gap-2 text-sm text-muted">
            Project
            <select v-model="projectId" class="input" :disabled="!canIssue">
              <option value="">No project binding</option>
              <option v-for="project in projects" :key="project.id" :value="project.id">{{ project.name }}</option>
            </select>
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Client
            <select v-model="clientId" class="input" :disabled="!canIssue">
              <option value="">No client binding</option>
              <option v-for="client in clients" :key="client.id" :value="client.id">{{ client.name }}</option>
            </select>
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Expiry
            <input v-model="expiresAt" class="input" type="datetime-local" :disabled="!canIssue" />
          </label>
        </div>

        <div class="grid gap-3">
          <p class="text-sm text-muted">Scopes</p>
          <div class="flex flex-wrap gap-2">
            <label
              v-for="scope in scopeOptions"
              :key="scope"
              class="inline-flex min-h-10 items-center gap-2 rounded-md border border-border bg-surface px-3 font-mono text-xs text-muted"
            >
              <input
                type="checkbox"
                :checked="selectedScopes.includes(scope)"
                :disabled="!canIssue"
                @change="setScope(scope, checked($event))"
              />
              {{ scope }}
            </label>
          </div>
        </div>

        <button class="btn-primary justify-self-start" :disabled="saving || !canIssue">
          {{ saving ? 'Creating' : 'Create token' }}
        </button>
      </form>

      <article v-if="createdToken" class="panel grid gap-3 p-4 md:grid-cols-[1fr_auto]">
        <div>
          <p class="text-sm font-semibold text-green">Token value shown once</p>
          <p class="mt-2 break-all font-mono text-sm text-muted">{{ createdToken }}</p>
        </div>
        <button type="button" class="btn-secondary gap-2 text-sm" @click="copyCreatedToken">
          <Check v-if="copied" class="h-4 w-4" aria-hidden="true" />
          <Copy v-else class="h-4 w-4" aria-hidden="true" />
          {{ copied ? 'Copied' : 'Copy' }}
        </button>
      </article>

      <div class="grid gap-3">
        <article v-if="!tokens.length" class="panel p-4 text-sm text-muted">No tokens created yet.</article>
        <article v-for="token in tokens" v-else :key="token.id" class="panel p-4">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 class="font-semibold">{{ token.name }}</h2>
              <p class="mt-1 font-mono text-xs text-muted">
                {{ token.token_type }} / hint {{ token.token_hint }} / {{ token.scopes.join(' ') || 'no scopes' }}
              </p>
            </div>
            <span class="rounded-md border border-border px-2 py-1 font-mono text-xs" :class="token.revoked_at ? 'text-red' : 'text-green'">
              {{ token.revoked_at ? 'revoked' : 'active' }}
            </span>
          </div>
          <div class="mt-4 grid gap-2 text-xs text-muted md:grid-cols-3">
            <p class="break-all font-mono">audiences: {{ token.audiences.join(', ') || 'none' }}</p>
            <p>expires: {{ token.expires_at ? new Date(token.expires_at).toLocaleString() : 'never' }}</p>
            <p>last used: {{ token.last_used_at ? new Date(token.last_used_at).toLocaleString() : 'never' }}</p>
          </div>
          <div class="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              class="btn-secondary min-h-10 gap-2 px-3 text-xs"
              :disabled="!canIssue || Boolean(token.revoked_at)"
              @click="rotate(token.id)"
            >
              <RotateCcw class="h-3.5 w-3.5" aria-hidden="true" />
              Rotate
            </button>
            <button
              type="button"
              class="btn-secondary min-h-10 gap-2 px-3 text-xs"
              :disabled="!canIssue || Boolean(token.revoked_at)"
              @click="revoke(token.id)"
            >
              <Trash2 class="h-3.5 w-3.5" aria-hidden="true" />
              Revoke
            </button>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
