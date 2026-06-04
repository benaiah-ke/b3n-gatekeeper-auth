<script setup lang="ts">
import {
  KeyRound,
  Pencil,
  PlugZap,
  Power,
  PowerOff,
  RefreshCw,
  RotateCcw,
  Save,
  Trash2,
} from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { OAuthProviderAdmin, OAuthProviderAdminCreate, OAuthProviderAdminUpdate, SetupStatus } from '@/types'

const defaultScopes = ['openid', 'email', 'profile']

const setup = ref<SetupStatus | null>(null)
const providers = ref<OAuthProviderAdmin[]>([])
const loading = ref(true)
const saving = ref(false)
const actionLoading = ref('')
const error = ref('')
const notice = ref('')
const formMode = ref<'create' | 'edit'>('create')

const providerId = ref('example')
const name = ref('Example Login')
const enabled = ref(true)
const clientId = ref('')
const clientSecret = ref('')
const authorizationUrl = ref('https://login.example.com/oauth/authorize')
const tokenUrl = ref('https://login.example.com/oauth/token')
const userinfoUrl = ref('https://login.example.com/userinfo')
const redirectUri = ref('')
const scopesText = ref(defaultScopes.join('\n'))
const subjectClaim = ref('sub')
const emailClaim = ref('email')
const nameClaim = ref('name')
const emailVerifiedClaim = ref('email_verified')
const allowEmailLinking = ref(true)
const requireVerifiedEmail = ref(true)

const managedProviders = computed(() => providers.value.filter((provider) => provider.source === 'database'))
const envProviders = computed(() => providers.value.filter((provider) => provider.source === 'env'))
const configuredCount = computed(() => providers.value.filter((provider) => provider.configured && provider.enabled).length)
const issuer = computed(() => setup.value?.issuer || window.location.origin)
const defaultCallback = computed(() => `${issuer.value}/api/v1/auth/oauth/${providerId.value || 'provider'}/callback`)
const canSubmit = computed(() => Boolean(providerId.value.trim() && name.value.trim() && authorizationUrl.value && tokenUrl.value && userinfoUrl.value))

function parseScopes(value: string) {
  const scopes = value
    .split(/[\n,]/)
    .map((scope) => scope.trim())
    .filter(Boolean)
  return scopes.length ? Array.from(new Set(scopes)) : [...defaultScopes]
}

function setCreateMode() {
  formMode.value = 'create'
  providerId.value = 'example'
  name.value = 'Example Login'
  enabled.value = true
  clientId.value = ''
  clientSecret.value = ''
  authorizationUrl.value = 'https://login.example.com/oauth/authorize'
  tokenUrl.value = 'https://login.example.com/oauth/token'
  userinfoUrl.value = 'https://login.example.com/userinfo'
  redirectUri.value = ''
  scopesText.value = defaultScopes.join('\n')
  subjectClaim.value = 'sub'
  emailClaim.value = 'email'
  nameClaim.value = 'name'
  emailVerifiedClaim.value = 'email_verified'
  allowEmailLinking.value = true
  requireVerifiedEmail.value = true
  notice.value = ''
}

function editProvider(provider: OAuthProviderAdmin) {
  if (provider.read_only) {
    return
  }
  formMode.value = 'edit'
  providerId.value = provider.provider_id
  name.value = provider.name
  enabled.value = provider.enabled
  clientId.value = provider.client_id
  clientSecret.value = ''
  authorizationUrl.value = provider.authorization_url
  tokenUrl.value = provider.token_url
  userinfoUrl.value = provider.userinfo_url
  redirectUri.value = provider.redirect_uri.includes(`/api/v1/auth/oauth/${provider.provider_id}/callback`)
    ? ''
    : provider.redirect_uri
  scopesText.value = provider.scopes.join('\n')
  subjectClaim.value = provider.subject_claim
  emailClaim.value = provider.email_claim
  nameClaim.value = provider.name_claim
  emailVerifiedClaim.value = provider.email_verified_claim
  allowEmailLinking.value = provider.allow_email_linking
  requireVerifiedEmail.value = provider.require_verified_email
  notice.value = ''
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [setupStatus, providerRows] = await Promise.all([api.setupStatus(), api.oauthProvidersAdmin()])
    setup.value = setupStatus
    providers.value = providerRows
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load providers'
  } finally {
    loading.value = false
  }
}

async function saveProvider() {
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    if (formMode.value === 'create') {
      const payload: OAuthProviderAdminCreate = {
        provider_id: providerId.value.trim(),
        name: name.value.trim(),
        enabled: enabled.value,
        client_id: clientId.value.trim(),
        client_secret: clientSecret.value.trim() || null,
        authorization_url: authorizationUrl.value.trim(),
        token_url: tokenUrl.value.trim(),
        userinfo_url: userinfoUrl.value.trim(),
        redirect_uri: redirectUri.value.trim(),
        scopes: parseScopes(scopesText.value),
        subject_claim: subjectClaim.value.trim() || 'sub',
        email_claim: emailClaim.value.trim() || 'email',
        name_claim: nameClaim.value.trim() || 'name',
        email_verified_claim: emailVerifiedClaim.value.trim() || 'email_verified',
        allow_email_linking: allowEmailLinking.value,
        require_verified_email: requireVerifiedEmail.value,
      }
      await api.createOAuthProvider(payload)
      notice.value = 'Provider created.'
    } else {
      const payload: OAuthProviderAdminUpdate = {
        name: name.value.trim(),
        enabled: enabled.value,
        client_id: clientId.value.trim(),
        authorization_url: authorizationUrl.value.trim(),
        token_url: tokenUrl.value.trim(),
        userinfo_url: userinfoUrl.value.trim(),
        redirect_uri: redirectUri.value.trim(),
        scopes: parseScopes(scopesText.value),
        subject_claim: subjectClaim.value.trim() || 'sub',
        email_claim: emailClaim.value.trim() || 'email',
        name_claim: nameClaim.value.trim() || 'name',
        email_verified_claim: emailVerifiedClaim.value.trim() || 'email_verified',
        allow_email_linking: allowEmailLinking.value,
        require_verified_email: requireVerifiedEmail.value,
      }
      if (clientSecret.value.trim()) {
        payload.client_secret = clientSecret.value.trim()
      }
      await api.updateOAuthProvider(providerId.value, payload)
      notice.value = 'Provider updated.'
    }
    clientSecret.value = ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not save provider'
  } finally {
    saving.value = false
  }
}

async function toggleProvider(provider: OAuthProviderAdmin) {
  if (provider.read_only) {
    return
  }
  actionLoading.value = provider.provider_id
  error.value = ''
  notice.value = ''
  try {
    await api.updateOAuthProvider(provider.provider_id, { enabled: !provider.enabled })
    notice.value = provider.enabled ? 'Provider disabled.' : 'Provider enabled.'
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update provider'
  } finally {
    actionLoading.value = ''
  }
}

async function clearSecret(provider: OAuthProviderAdmin) {
  if (provider.read_only) {
    return
  }
  actionLoading.value = provider.provider_id
  error.value = ''
  notice.value = ''
  try {
    await api.updateOAuthProvider(provider.provider_id, { client_secret: null })
    notice.value = 'Provider secret cleared.'
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not clear provider secret'
  } finally {
    actionLoading.value = ''
  }
}

async function deleteProvider(provider: OAuthProviderAdmin) {
  if (provider.read_only) {
    return
  }
  actionLoading.value = provider.provider_id
  error.value = ''
  notice.value = ''
  try {
    await api.deleteOAuthProvider(provider.provider_id)
    notice.value = 'Provider deleted.'
    if (formMode.value === 'edit' && providerId.value === provider.provider_id) {
      setCreateMode()
    }
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not delete provider'
  } finally {
    actionLoading.value = ''
  }
}

function formatSource(provider: OAuthProviderAdmin) {
  return provider.source === 'env' ? 'env bootstrap' : 'managed'
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="mono-label">Social auth</p>
        <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">OIDC providers</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
          Manage the sign-in providers shown on hosted and product-owned auth screens.
        </p>
      </div>
      <button type="button" class="btn-secondary gap-2 text-sm" :disabled="loading || saving" @click="load">
        <RefreshCw class="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
    </div>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading providers...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <div class="grid gap-4 md:grid-cols-3">
        <article class="panel p-5">
          <p class="text-sm text-muted">Visible providers</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ providers.length }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">{{ configuredCount }} ready</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Managed</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ managedProviders.length }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">database config</p>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Bootstrap</p>
          <h2 class="mt-2 text-2xl font-semibold">{{ envProviders.length }}</h2>
          <p class="mt-2 font-mono text-xs text-muted">read-only env</p>
        </article>
      </div>

      <p v-if="notice" class="rounded-md border border-green/40 bg-green/10 p-3 text-sm text-green">{{ notice }}</p>

      <form class="panel grid gap-5 p-5" @submit.prevent="saveProvider">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p class="mono-label">{{ formMode === 'edit' ? 'Edit provider' : 'New provider' }}</p>
            <h2 class="mt-2 text-xl font-semibold">{{ formMode === 'edit' ? name || providerId : 'Provider config' }}</h2>
          </div>
          <button type="button" class="btn-secondary gap-2 text-sm" :disabled="saving" @click="setCreateMode">
            <RotateCcw class="h-4 w-4" aria-hidden="true" />
            New
          </button>
        </div>

        <div class="grid gap-4 md:grid-cols-3">
          <label class="grid gap-2 text-sm text-muted">
            Provider ID
            <input
              v-model="providerId"
              class="input font-mono"
              pattern="[a-z0-9][a-z0-9_-]*"
              :disabled="formMode === 'edit' || saving"
              required
            />
          </label>
          <label class="grid gap-2 text-sm text-muted md:col-span-2">
            Name
            <input v-model="name" class="input" :disabled="saving" required />
          </label>
        </div>

        <div class="grid gap-4 md:grid-cols-2">
          <label class="grid gap-2 text-sm text-muted">
            Client ID
            <input v-model="clientId" class="input font-mono" :disabled="saving" autocomplete="off" />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Client secret
            <input
              v-model="clientSecret"
              class="input font-mono"
              type="password"
              :placeholder="formMode === 'edit' ? 'leave blank to keep stored secret' : ''"
              :disabled="saving"
              autocomplete="new-password"
            />
          </label>
        </div>

        <div class="grid gap-4">
          <label class="grid gap-2 text-sm text-muted">
            Authorization URL
            <input v-model="authorizationUrl" class="input font-mono" type="url" :disabled="saving" required />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Token URL
            <input v-model="tokenUrl" class="input font-mono" type="url" :disabled="saving" required />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Userinfo URL
            <input v-model="userinfoUrl" class="input font-mono" type="url" :disabled="saving" required />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Redirect URI
            <input
              v-model="redirectUri"
              class="input font-mono"
              type="url"
              :placeholder="defaultCallback"
              :disabled="saving"
            />
          </label>
        </div>

        <div class="grid gap-4 md:grid-cols-[1.2fr_0.8fr]">
          <label class="grid gap-2 text-sm text-muted">
            Scopes
            <textarea v-model="scopesText" class="input min-h-28 font-mono text-sm" :disabled="saving" />
          </label>
          <div class="grid content-start gap-3">
            <label class="inline-flex min-h-10 items-center gap-2 text-sm text-muted">
              <input v-model="enabled" type="checkbox" :disabled="saving" />
              Enabled
            </label>
            <label class="inline-flex min-h-10 items-center gap-2 text-sm text-muted">
              <input v-model="allowEmailLinking" type="checkbox" :disabled="saving" />
              Link by verified email
            </label>
            <label class="inline-flex min-h-10 items-center gap-2 text-sm text-muted">
              <input v-model="requireVerifiedEmail" type="checkbox" :disabled="saving" />
              Require verified email
            </label>
            <p class="break-all font-mono text-xs text-muted">Default callback: {{ defaultCallback }}</p>
          </div>
        </div>

        <div class="grid gap-4 md:grid-cols-4">
          <label class="grid gap-2 text-sm text-muted">
            Subject claim
            <input v-model="subjectClaim" class="input font-mono" :disabled="saving" />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Email claim
            <input v-model="emailClaim" class="input font-mono" :disabled="saving" />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Name claim
            <input v-model="nameClaim" class="input font-mono" :disabled="saving" />
          </label>
          <label class="grid gap-2 text-sm text-muted">
            Verified claim
            <input v-model="emailVerifiedClaim" class="input font-mono" :disabled="saving" />
          </label>
        </div>

        <button type="submit" class="btn-primary justify-self-start gap-2 text-sm" :disabled="saving || !canSubmit">
          <Save class="h-4 w-4" aria-hidden="true" />
          {{ saving ? 'Saving' : formMode === 'edit' ? 'Save provider' : 'Create provider' }}
        </button>
      </form>

      <section class="grid gap-3">
        <p class="mono-label">Provider registry</p>
        <article v-if="!providers.length" class="panel p-4 text-sm text-muted">No providers configured yet.</article>
        <article v-for="provider in providers" v-else :key="`${provider.source}:${provider.provider_id}`" class="panel p-4">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div class="flex items-center gap-2">
                <PlugZap class="h-4 w-4 text-accent" aria-hidden="true" />
                <h2 class="font-semibold">{{ provider.name }}</h2>
              </div>
              <p class="mt-1 break-all font-mono text-xs text-muted">{{ provider.provider_id }}</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
                {{ formatSource(provider) }}
              </span>
              <span
                class="rounded-md border border-border px-2 py-1 font-mono text-xs"
                :class="provider.enabled ? 'text-green' : 'text-red'"
              >
                {{ provider.enabled ? 'enabled' : 'disabled' }}
              </span>
              <span
                class="rounded-md border border-border px-2 py-1 font-mono text-xs"
                :class="provider.configured ? 'text-green' : 'text-orange'"
              >
                {{ provider.configured ? 'configured' : 'missing secret' }}
              </span>
            </div>
          </div>

          <div class="mt-4 grid gap-2 text-xs text-muted md:grid-cols-2">
            <p class="break-all font-mono">authorize: {{ provider.authorization_url }}</p>
            <p class="break-all font-mono">token: {{ provider.token_url }}</p>
            <p class="break-all font-mono">userinfo: {{ provider.userinfo_url }}</p>
            <p class="break-all font-mono">callback: {{ provider.redirect_uri }}</p>
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <span v-for="scope in provider.scopes" :key="scope" class="rounded-md border border-border px-2 py-1 font-mono text-xs">
              {{ scope }}
            </span>
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <button type="button" class="btn-secondary min-h-10 gap-2 px-3 text-xs" :disabled="provider.read_only" @click="editProvider(provider)">
              <Pencil class="h-4 w-4" aria-hidden="true" />
              Edit
            </button>
            <button
              type="button"
              class="btn-secondary min-h-10 gap-2 px-3 text-xs"
              :disabled="provider.read_only || actionLoading === provider.provider_id"
              @click="toggleProvider(provider)"
            >
              <PowerOff v-if="provider.enabled" class="h-4 w-4" aria-hidden="true" />
              <Power v-else class="h-4 w-4" aria-hidden="true" />
              {{ provider.enabled ? 'Disable' : 'Enable' }}
            </button>
            <button
              type="button"
              class="btn-secondary min-h-10 gap-2 px-3 text-xs"
              :disabled="provider.read_only || !provider.client_secret_configured || actionLoading === provider.provider_id"
              @click="clearSecret(provider)"
            >
              <KeyRound class="h-4 w-4" aria-hidden="true" />
              Clear secret
            </button>
            <button
              type="button"
              class="btn-secondary min-h-10 gap-2 px-3 text-xs"
              :disabled="provider.read_only || actionLoading === provider.provider_id"
              @click="deleteProvider(provider)"
            >
              <Trash2 class="h-4 w-4" aria-hidden="true" />
              Delete
            </button>
          </div>
        </article>
      </section>
    </div>
  </section>
</template>
