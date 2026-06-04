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
  <section class="mx-auto grid min-h-[calc(100svh-4rem)] max-w-3xl place-items-center px-4 py-8 md:px-8">
    <article v-if="loading" class="panel w-full p-6 text-sm text-muted">Loading authorization request...</article>
    <article v-else-if="error" class="w-full rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
      {{ error }}
    </article>
    <article v-else-if="context" class="panel w-full p-6">
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="mono-label">Authorize application</p>
          <h1 class="mt-3 font-serif text-4xl leading-tight">{{ context.client.name }}</h1>
          <p class="mt-3 max-w-xl text-sm leading-6 text-muted">
            Review this request before GateKeeper shares an authorization code and remembers this app grant.
          </p>
          <div class="mt-4 flex flex-wrap gap-2">
            <span
              class="inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 font-mono text-xs"
              :class="context.client.verified ? 'border-green/35 bg-green/10 text-green' : 'border-orange/45 bg-orange/10 text-orange'"
            >
              <BadgeCheck class="h-4 w-4" aria-hidden="true" />
              {{ context.client.verified ? 'verified app' : 'unverified app' }}
            </span>
            <span v-if="context.client.publisher_name" class="inline-flex min-h-8 items-center rounded-md border border-border px-2.5 font-mono text-xs text-muted">
              {{ context.client.publisher_name }}
            </span>
          </div>
        </div>
        <span
          v-if="context.client.logo_url"
          class="grid h-14 w-14 shrink-0 place-items-center overflow-hidden rounded-md border border-border bg-surface"
        >
          <img :src="context.client.logo_url" :alt="`${context.client.name} logo`" class="h-full w-full object-cover" />
        </span>
        <span v-else class="grid h-11 w-11 shrink-0 place-items-center rounded-md border border-border bg-surface">
          <ExternalLink class="h-5 w-5 text-accent" aria-hidden="true" />
        </span>
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
        <p>This app is not marked verified by the organization operator. Check the redirect origin and links before approving.</p>
      </div>

      <dl class="mt-7 grid gap-4 text-sm">
        <div class="rounded-md border border-border bg-bg/40 p-4">
          <dt class="mono-label">Application</dt>
          <dd class="mt-2 font-mono text-fg">{{ context.client.client_id }}</dd>
        </div>
        <div class="rounded-md border border-border bg-bg/40 p-4">
          <dt class="mono-label">Redirect origin</dt>
          <dd class="mt-2 break-all font-mono text-fg">{{ origin }}</dd>
        </div>
        <div class="rounded-md border border-border bg-bg/40 p-4">
          <dt class="mono-label">Audience</dt>
          <dd class="mt-2 break-all font-mono text-fg">{{ context.audience || context.client.audiences.join(', ') }}</dd>
        </div>
        <div class="rounded-md border border-border bg-bg/40 p-4">
          <dt class="mono-label">Account scope</dt>
          <dd v-if="context.orgs.length > 1 || !context.client.require_org_membership" class="mt-3">
            <select
              v-model="selectedOrgId"
              class="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-fg outline-none focus:border-accent"
            >
              <option v-if="!context.client.require_org_membership" value="">Personal account</option>
              <option v-for="org in context.orgs" :key="org.id" :value="org.id">
                {{ org.name }}
              </option>
            </select>
          </dd>
          <dd v-else class="mt-2 text-fg">{{ selectedOrg?.name || 'No organization selected' }}</dd>
        </div>
      </dl>

      <section class="mt-6">
        <p class="mono-label">Requested scopes</p>
        <div class="mt-3 flex flex-wrap gap-2">
          <span v-for="scope in context.scopes" :key="scope" class="rounded-md border border-border px-2 py-1 font-mono text-xs">
            {{ scope }}
          </span>
          <span v-if="!context.scopes.length" class="text-sm text-muted">No scopes requested.</span>
        </div>
      </section>

      <div
        v-if="context.client.require_org_membership"
        class="mt-6 flex gap-3 rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        <AlertTriangle class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
        <p>This client requires organization membership. GateKeeper will bind this authorization to the selected organization.</p>
      </div>

      <div
        v-if="context.client.require_mfa"
        class="mt-3 flex gap-3 rounded-md border border-green/35 bg-green/10 p-4 text-sm leading-6 text-green"
      >
        <ShieldCheck class="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
        <p>This client requires authenticator MFA before GateKeeper issues app or device tokens.</p>
      </div>

      <div class="mt-7 flex flex-wrap justify-end gap-3">
        <button type="button" class="btn-secondary gap-2" @click="deny">
          <XCircle class="h-4 w-4" aria-hidden="true" />
          Deny
        </button>
        <button type="button" class="btn-primary gap-2" @click="approve">
          <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
          Approve
        </button>
      </div>
    </article>
  </section>
</template>
