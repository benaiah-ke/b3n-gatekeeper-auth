<script setup lang="ts">
import { AlertTriangle, BadgeCheck, CheckCircle2, ExternalLink, ShieldCheck, XCircle } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api, gatekeeperApiUrl } from '@/services/api'
import type { AuthorizeContext } from '@/types'

const context = ref<AuthorizeContext | null>(null)
const loading = ref(true)
const error = ref('')
const selectedOrgId = ref('')

const selectedOrg = computed(() =>
  context.value?.orgs.find((org) => org.id === selectedOrgId.value) || null,
)
const clientLinks = computed(() => {
  const client = context.value?.client
  if (!client) {
    return []
  }
  return [
    { label: 'Homepage', href: client.homepage_url },
    { label: 'Privacy', href: client.privacy_policy_url },
    { label: 'Terms', href: client.terms_url },
  ].filter((item): item is { label: string; href: string } => Boolean(item.href))
})
const origin = computed(() => {
  if (!context.value?.redirect_uri) {
    return ''
  }
  try {
    return new URL(context.value.redirect_uri).origin
  } catch {
    return context.value.redirect_uri
  }
})
const permissionItems = computed(() => {
  const scopes = new Set(context.value?.scopes || [])
  const items: string[] = []
  if (scopes.has('openid')) {
    items.push('Confirm that you are signed in')
  }
  if (scopes.has('profile')) {
    items.push('Share your basic profile')
  }
  if (scopes.has('email')) {
    items.push('Share your email address')
  }
  if (scopes.has('auth:read')) {
    items.push('Verify your GateKeeper account access')
  }
  if (!items.length) {
    items.push('Continue with your GateKeeper account')
  }
  return items
})

function currentQuery() {
  return new URLSearchParams(window.location.search)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const result = await api.authorizeContext(window.location.search)
    context.value = result
    selectedOrgId.value = result.selected_org_id || ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load authorization request'
  } finally {
    loading.value = false
  }
}

function approve() {
  const params = currentQuery()
  params.set('approve', 'true')
  if (selectedOrgId.value) {
    params.set('org_id', selectedOrgId.value)
  } else {
    params.delete('org_id')
  }
  window.location.assign(gatekeeperApiUrl(`/oauth/authorize?${params.toString()}`))
}

function deny() {
  if (!context.value) {
    return
  }
  const redirect = new URL(context.value.redirect_uri)
  redirect.searchParams.set('error', 'access_denied')
  redirect.searchParams.set('error_description', 'The user denied the authorization request.')
  if (context.value.state) {
    redirect.searchParams.set('state', context.value.state)
  }
  window.location.assign(redirect.toString())
}

onMounted(load)
</script>

<template>
  <section class="grid min-h-svh place-items-center px-4 py-8">
    <article v-if="loading" class="panel w-full max-w-xl p-6 text-sm text-muted">Loading sign-in request...</article>
    <article v-else-if="error" class="w-full max-w-xl rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
      {{ error }}
    </article>
    <article v-else-if="context" class="panel w-full max-w-xl p-6">
      <div class="flex items-start gap-4">
        <span
          v-if="context.client.logo_url"
          class="grid h-12 w-12 shrink-0 place-items-center overflow-hidden rounded-md border border-border bg-surface"
        >
          <img :src="context.client.logo_url" :alt="`${context.client.name} logo`" class="h-full w-full object-cover" />
        </span>
        <span v-else class="grid h-12 w-12 shrink-0 place-items-center rounded-md border border-border bg-surface">
          <ExternalLink class="h-5 w-5 text-accent" aria-hidden="true" />
        </span>
        <div class="min-w-0 flex-1">
          <p class="mono-label">GateKeeper sign-in</p>
          <h1 class="mt-2 break-words text-2xl font-semibold leading-tight">Continue to {{ context.client.name }}</h1>
          <p class="mt-3 text-sm leading-6 text-muted">
            GateKeeper will securely sign you in. Continue only if you recognize this app.
          </p>
          <div class="mt-4 flex flex-wrap gap-2">
            <span
              class="inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 font-mono text-xs"
              :class="context.client.verified ? 'border-green/35 bg-green/10 text-green' : 'border-orange/45 bg-orange/10 text-orange'"
            >
              <BadgeCheck class="h-4 w-4" aria-hidden="true" />
              {{ context.client.verified ? 'trusted app' : 'needs review' }}
            </span>
            <span v-if="context.client.publisher_name" class="inline-flex min-h-8 items-center rounded-md border border-border px-2.5 font-mono text-xs text-muted">
              {{ context.client.publisher_name }}
            </span>
          </div>
        </div>
      </div>

      <section v-if="context.client.description || clientLinks.length" class="mt-6 rounded-md border border-border bg-bg/40 p-4">
        <p v-if="context.client.description" class="text-sm leading-6 text-muted">{{ context.client.description }}</p>
        <div v-if="clientLinks.length" class="mt-3 flex flex-wrap gap-2">
          <a
            v-for="link in clientLinks"
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
      </section>

      <div
        v-if="!context.client.verified"
        class="mt-6 flex gap-3 rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        <AlertTriangle class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
        <p>This app has not been marked trusted yet. Check that the app name and website look right before continuing.</p>
      </div>

      <section class="mt-7 rounded-md border border-border bg-bg/40 p-4">
        <p class="text-sm font-semibold">This app can</p>
        <ul class="mt-3 grid gap-2 text-sm leading-6 text-muted">
          <li v-for="item in permissionItems" :key="item" class="flex gap-2">
            <CheckCircle2 class="mt-1 h-4 w-4 shrink-0 text-green" aria-hidden="true" />
            <span>{{ item }}</span>
          </li>
        </ul>
      </section>

      <section class="mt-4 rounded-md border border-border bg-bg/40 p-4 text-sm">
        <p class="font-semibold">Use account</p>
        <div class="mt-3">
          <div v-if="context.orgs.length > 1 || !context.client.require_org_membership">
            <select
              v-model="selectedOrgId"
              class="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-fg outline-none focus:border-accent"
            >
              <option v-if="!context.client.require_org_membership" value="">Personal account</option>
              <option v-for="org in context.orgs" :key="org.id" :value="org.id">
                {{ org.name }}
              </option>
            </select>
          </div>
          <div v-else class="text-fg">{{ selectedOrg?.name || 'No organization selected' }}</div>
        </div>
      </section>

      <div
        v-if="context.client.require_org_membership"
        class="mt-6 flex gap-3 rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        <AlertTriangle class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
        <p>This app is available only to members of the selected organization.</p>
      </div>

      <div
        v-if="context.client.require_mfa"
        class="mt-3 flex gap-3 rounded-md border border-green/35 bg-green/10 p-4 text-sm leading-6 text-green"
      >
        <ShieldCheck class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
        <p>This app requires authenticator verification for stronger account protection.</p>
      </div>

      <details class="mt-5 rounded-md border border-border bg-bg/40 p-4 text-sm text-muted">
        <summary class="cursor-pointer text-fg">Technical details</summary>
        <dl class="mt-4 grid gap-3">
          <div>
            <dt class="mono-label">Application id</dt>
            <dd class="mt-1 break-all font-mono text-xs text-fg">{{ context.client.client_id }}</dd>
          </div>
          <div>
            <dt class="mono-label">Website</dt>
            <dd class="mt-1 break-all font-mono text-xs text-fg">{{ origin }}</dd>
          </div>
          <div>
            <dt class="mono-label">Audience</dt>
            <dd class="mt-1 break-all font-mono text-xs text-fg">{{ context.audience || context.client.audiences.join(', ') }}</dd>
          </div>
          <div>
            <dt class="mono-label">Scopes</dt>
            <dd class="mt-2 flex flex-wrap gap-2">
              <span v-for="scope in context.scopes" :key="scope" class="rounded-md border border-border px-2 py-1 font-mono text-xs text-fg">
                {{ scope }}
              </span>
              <span v-if="!context.scopes.length" class="text-xs text-muted">No scopes requested.</span>
            </dd>
          </div>
        </dl>
      </details>

      <div class="mt-7 flex flex-wrap justify-end gap-3">
        <button type="button" class="btn-secondary gap-2" @click="deny">
          <XCircle class="h-4 w-4" aria-hidden="true" />
          Cancel
        </button>
        <button type="button" class="btn-primary gap-2" @click="approve">
          <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
          Continue
        </button>
      </div>
    </article>
  </section>
</template>
