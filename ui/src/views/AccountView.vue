<script setup lang="ts">
import {
  BadgeCheck,
  CheckCircle2,
  Code2,
  Copy,
  Download,
  Gauge,
  Globe,
  KeyRound,
  Link2,
  ListChecks,
  LockKeyhole,
  Mail,
  MonitorCog,
  MonitorSmartphone,
  Save,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Trash2,
  UserPlus,
  UserRound,
  Users,
  UserX,
} from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

import { api, clearTokens } from '@/services/api'
import type { ApiToken, AuthClient, LinkedIdentity, MfaStatus, OAuthProvider, Project, SetupStatus, TotpSetup } from '@/types'

const router = useRouter()
const status = ref<SetupStatus | null>(null)
const clients = ref<AuthClient[]>([])
const tokens = ref<ApiToken[]>([])
const projects = ref<Project[]>([])
const mcpResources = ref<Array<{ id: string; name: string; resource_uri: string; scopes: string[] }>>([])
const linkedIdentities = ref<LinkedIdentity[]>([])
const oauthProviders = ref<OAuthProvider[]>([])
const displayName = ref('')
const accountNotice = ref('')
const accountLoading = ref(false)
const emailChangeNewEmail = ref('')
const emailChangePassword = ref('')
const emailChangeCode = ref('')
const emailChangePending = ref(false)
const emailChangeNotice = ref('')
const emailChangeLoading = ref(false)
const currentPassword = ref('')
const newPassword = ref('')
const passwordNotice = ref('')
const passwordLoading = ref(false)
const exportNotice = ref('')
const exportLoading = ref(false)
const deactivatePassword = ref('')
const deactivateTotpCode = ref('')
const deactivateRecoveryCode = ref('')
const deactivateConfirm = ref('')
const deactivateNotice = ref('')
const deactivateLoading = ref(false)
const identityNotice = ref('')
const identityLoading = ref('')
const mfa = ref<MfaStatus | null>(null)
const totpSetup = ref<TotpSetup | null>(null)
const totpCode = ref('')
const recoveryCodes = ref<string[]>([])
const mfaNotice = ref('')
const mfaLoading = ref(false)
const loading = ref(true)
const error = ref('')
const copiedKey = ref('')

const activeOrg = computed(() => status.value?.org || status.value?.orgs[0] || null)
const role = computed(() => activeOrg.value?.role || 'none')
const permissions = computed(() => activeOrg.value?.permissions || [])
const configuredOAuthProviders = computed(() => oauthProviders.value.filter((provider) => provider.configured))
const unlinkedOAuthProviders = computed(() =>
  configuredOAuthProviders.value.filter(
    (provider) => !linkedIdentities.value.some((identity) => identity.provider === provider.id),
  ),
)
const canManageMcp = computed(() => status.value?.scopes.includes('*') || status.value?.scopes.includes('mcp:*'))
const activeTokens = computed(() => tokens.value.filter((token) => !token.revoked_at))
const cliClient = computed(() => clients.value.find((client) => client.client_id === 'gatekeeper-cli'))
const webClient = computed(() => clients.value.find((client) => client.redirect_uris.length && client.audiences.length))
const protectedApi = computed(() => projects.value[0] || null)
const mcpResource = computed(() => mcpResources.value[0] || null)
const suggestedAudience = computed(
  () => protectedApi.value?.audience || webClient.value?.audiences[0] || 'example-api',
)
const suggestedRedirectUri = computed(() => webClient.value?.redirect_uris[0] || 'https://app.example.com/auth/callback')
const suggestedScopes = computed(() => {
  const values = webClient.value?.scopes?.length ? webClient.value.scopes : ['openid', 'profile', 'email', 'api:read']
  return values.join(' ')
})

const sessionSummary = computed(() => {
  if (!status.value?.access_expires_at) {
    return 'Cookie or API-token session'
  }
  return `Access token expires ${new Date(status.value.access_expires_at).toLocaleString()}`
})

const mfaStateLabel = computed(() => {
  if (mfa.value?.totp_enabled) {
    return 'enabled'
  }
  if (mfa.value?.totp_pending || totpSetup.value) {
    return 'setup pending'
  }
  return 'not configured'
})

const mfaDetail = computed(() => {
  if (mfa.value?.totp_enabled) {
    const enabledAt = mfa.value.totp_enabled_at ? new Date(mfa.value.totp_enabled_at).toLocaleString() : 'enabled'
    return `Authenticator 2FA active since ${enabledAt}. ${mfa.value.recovery_codes_remaining} recovery codes remain.`
  }
  if (mfa.value?.totp_pending || totpSetup.value) {
    return 'Verify an authenticator code to finish setup'
  }
  return 'Add authenticator 2FA before inviting operators or connecting production apps'
})

const recoveryCodesText = computed(() => recoveryCodes.value.join('\n'))

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
    title: 'Authenticator 2FA',
    done: Boolean(mfa.value?.totp_enabled),
    detail: mfaDetail.value,
    to: '/account',
  },
  {
    title: 'Session policy',
    done: Boolean(activeOrg.value?.require_mfa || clients.value.some((client) => client.require_mfa)),
    detail: activeOrg.value?.require_mfa ? 'Organization apps require MFA' : 'Set org or app MFA rules before production use',
    to: '/policy',
  },
  {
    title: 'Protected API audience',
    done: Boolean(protectedApi.value),
    detail: protectedApi.value?.audience || 'Create a project or resource audience such as example-api',
    to: '/projects',
  },
  {
    title: 'Web app client',
    done: Boolean(webClient.value),
    detail: webClient.value?.client_id || 'Register a web app with exact redirects, origins, scopes, and audience',
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

const completedSetupCount = computed(() => setupSteps.value.filter((step) => step.done).length)
const setupCompletionPercent = computed(() =>
  Math.round((completedSetupCount.value / Math.max(setupSteps.value.length, 1)) * 100),
)
const nextSetupStep = computed(() => setupSteps.value.find((step) => !step.done) || null)

const policyHealthItems = computed(() => {
  if (!status.value) {
    return []
  }
  const mfaEnforced = Boolean(activeOrg.value?.require_mfa || clients.value.some((client) => client.require_mfa))
  const idleTimeoutSet = Boolean(
    activeOrg.value?.session_idle_timeout_minutes || clients.value.some((client) => client.session_idle_timeout_minutes),
  )
  return [
    {
      key: 'owner',
      label: 'Owner access',
      severity: status.value.owner_exists && status.value.can_manage_clients ? 'ready' : 'blocker',
      detail: status.value.can_manage_clients
        ? `${role.value} can register clients and configure setup`
        : 'Use an owner account before first production setup',
      to: '/roles',
    },
    {
      key: 'email',
      label: 'Email delivery',
      severity: status.value.smtp_configured && !status.value.email_dev_mode ? 'ready' : 'warning',
      detail: status.value.smtp_configured ? 'SMTP is configured' : 'Configure SMTP before relying on reset, invite, and verification emails',
      to: '/account',
    },
    {
      key: 'api',
      label: 'Protected API',
      severity: protectedApi.value ? 'ready' : 'blocker',
      detail: protectedApi.value
        ? `${protectedApi.value.audience} is available for backend verification`
        : 'Create a project audience before integrating product APIs',
      to: '/projects',
    },
    {
      key: 'client',
      label: 'Application client',
      severity: webClient.value ? 'ready' : 'warning',
      detail: webClient.value
        ? `${webClient.value.client_id} has redirect and audience settings`
        : 'Register a web client for hosted auth and frontend SDK flows',
      to: '/clients',
    },
    {
      key: 'mfa',
      label: 'MFA enrollment',
      severity: mfa.value?.totp_enabled ? 'ready' : 'warning',
      detail: mfaDetail.value,
      to: '/account',
    },
    {
      key: 'policy',
      label: 'Session rules',
      severity: mfaEnforced && idleTimeoutSet ? 'ready' : 'warning',
      detail: mfaEnforced
        ? idleTimeoutSet
          ? 'MFA and idle timeout policies are configured'
          : 'Add an idle timeout for browser, CLI, and MCP sessions'
        : 'Enable org or app MFA before production use',
      to: '/policy',
    },
    {
      key: 'admin-step-up',
      label: 'Admin step-up',
      severity: activeOrg.value?.admin_step_up_mfa_required ? 'ready' : 'warning',
      detail: activeOrg.value?.admin_step_up_mfa_required
        ? 'Sensitive organization mutations require MFA'
        : 'Require MFA before changing clients, users, roles, providers, and tokens',
      to: '/policy',
    },
    {
      key: 'tokens',
      label: 'API credentials',
      severity: activeTokens.value.length ? 'ready' : 'warning',
      detail: activeTokens.value.length
        ? `${activeTokens.value.length} active copy-once credentials`
        : 'Create scoped personal, service, or project tokens for API callers',
      to: '/tokens',
    },
  ]
})

const readinessBlockers = computed(() => policyHealthItems.value.filter((item) => item.severity === 'blocker'))
const readinessWarnings = computed(() => policyHealthItems.value.filter((item) => item.severity === 'warning'))
const readinessState = computed(() => {
  if (readinessBlockers.value.length) {
    return 'blocked'
  }
  if (readinessWarnings.value.length) {
    return 'needs review'
  }
  return 'ready'
})

const operatorShortcuts = computed(() => [
  {
    key: 'users',
    icon: Users,
    title: 'Users',
    detail: 'Review accounts, roles, suspension, and MFA reset',
    to: '/users',
    enabled: Boolean(status.value?.can_manage_roles),
  },
  {
    key: 'invites',
    icon: UserPlus,
    title: 'Invites',
    detail: 'Send owner, admin, developer, and viewer invitations',
    to: '/invitations',
    enabled: Boolean(status.value?.can_manage_roles),
  },
  {
    key: 'sessions',
    icon: MonitorSmartphone,
    title: 'Sessions',
    detail: 'Label, trust, revoke, and sign out devices',
    to: '/sessions',
    enabled: Boolean(status.value?.user),
  },
  {
    key: 'policy',
    icon: SlidersHorizontal,
    title: 'Policy',
    detail: 'Set MFA, trusted-device reuse, step-up, and idle timeout',
    to: '/policy',
    enabled: Boolean(status.value?.can_manage_roles),
  },
  {
    key: 'providers',
    icon: BadgeCheck,
    title: 'Providers',
    detail: 'Configure social/OIDC login for hosted and API flows',
    to: '/providers',
    enabled: Boolean(status.value?.scopes.includes('*')),
  },
  {
    key: 'audit',
    icon: ScrollText,
    title: 'Audit',
    detail: 'Inspect setup, token, user, policy, and session events',
    to: '/audit',
    enabled: Boolean(status.value?.can_manage_roles),
  },
])

function severityClass(severity: string) {
  if (severity === 'ready') {
    return 'border-green/35 bg-green/10 text-green'
  }
  if (severity === 'blocker') {
    return 'border-red/40 bg-red/10 text-red'
  }
  return 'border-orange/45 bg-orange/10 text-orange'
}

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
    `GATEKEEPER_AUDIENCE=${suggestedAudience.value}`,
    'GATEKEEPER_REQUIRED_SCOPES=api:read',
  ].join('\n')
})

const hostedAuthSnippet = computed(() => {
  if (!status.value) {
    return ''
  }
  const clientId = webClient.value?.client_id || 'create-web-client'
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: suggestedRedirectUri.value,
    scope: suggestedScopes.value,
    code_challenge: '<pkce-code-challenge>',
    code_challenge_method: 'S256',
  })
  params.set('audience', suggestedAudience.value)
  return `${status.value.issuer}/oauth/authorize?${params.toString()}`
})

const vueSnippet = computed(() => {
  if (!status.value) {
    return ''
  }
  return [
    "createGateKeeper({",
    `  issuer: '${status.value.issuer}',`,
    `  clientId: '${webClient.value?.client_id || 'create-web-client'}',`,
    `  redirectUri: '${suggestedRedirectUri.value}',`,
    `  audience: '${suggestedAudience.value}',`,
    `  scope: '${suggestedScopes.value}',`,
    '})',
  ].join('\n')
})

const cliMcpSnippet = computed(() => {
  if (!status.value) {
    return ''
  }
  const cliClientId = cliClient.value?.client_id || 'gatekeeper-cli'
  return [
    `gatekeeper doctor --url ${status.value.issuer}`,
    `gatekeeper login --url ${status.value.issuer} --client-id ${cliClientId} --scope "openid profile email cli:read"`,
    `MCP_RESOURCE_URI=${mcpResource.value?.resource_uri || 'https://mcp.example.com'}`,
    `MCP_PROTECTED_RESOURCE=${status.value.issuer}/.well-known/oauth-protected-resource`,
  ].join('\n')
})

const tokenSnippet = computed(() => {
  const audience = suggestedAudience.value
  return [
    `Authorization: Bearer <${audience}-token>`,
    `audience=${audience}`,
    'required_scope=api:read',
    'rotation=copy-once-token-value',
  ].join('\n')
})

const integrationSurfaces = computed(() => [
  {
    key: 'api',
    icon: Server,
    title: 'API backend',
    status: protectedApi.value ? 'ready' : 'needs audience',
    to: '/projects',
    cta: protectedApi.value ? 'View audiences' : 'Create audience',
    snippet: integrationSnippet.value,
  },
  {
    key: 'hosted',
    icon: Globe,
    title: 'Hosted auth',
    status: webClient.value ? 'ready' : 'needs client',
    to: '/clients',
    cta: webClient.value ? 'View client' : 'Create web client',
    snippet: hostedAuthSnippet.value,
  },
  {
    key: 'vue',
    icon: Code2,
    title: 'Vue/Nuxt SDK',
    status: webClient.value ? 'ready' : 'needs client',
    to: '/clients',
    cta: 'Client settings',
    snippet: vueSnippet.value,
  },
  {
    key: 'keys',
    icon: KeyRound,
    title: 'API keys',
    status: activeTokens.value.length ? 'ready' : 'needs token',
    to: '/tokens',
    cta: activeTokens.value.length ? 'View tokens' : 'Create token',
    snippet: tokenSnippet.value,
  },
  {
    key: 'cli-mcp',
    icon: Terminal,
    title: 'CLI / MCP',
    status: cliClient.value || mcpResource.value ? 'ready' : 'needs app',
    to: cliClient.value ? '/device' : '/clients',
    cta: cliClient.value ? 'Approve device' : 'Create CLI/MCP app',
    snippet: cliMcpSnippet.value,
  },
])

async function load() {
  loading.value = true
  error.value = ''
  mfaNotice.value = ''
  accountNotice.value = ''
  emailChangeNotice.value = ''
  passwordNotice.value = ''
  exportNotice.value = ''
  deactivateNotice.value = ''
  identityNotice.value = ''
  recoveryCodes.value = []
  try {
    const setup = await api.setupStatus()
    status.value = setup
    displayName.value = setup.user?.display_name || ''
    emailChangeNewEmail.value = setup.user?.email || ''
    const [clientRows, tokenRows, projectRows, mfaStatus, identities, providers] = await Promise.all([
      api.clients(),
      api.tokens(),
      api.projects(setup.org?.id),
      api.mfaStatus(),
      api.linkedIdentities(),
      api.oauthProviders(),
    ])
    clients.value = clientRows
    tokens.value = tokenRows
    projects.value = projectRows
    mfa.value = mfaStatus
    linkedIdentities.value = identities
    oauthProviders.value = providers
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
  await copyText('env', integrationSnippet.value)
}

async function copyText(key: string, value: string) {
  await navigator.clipboard.writeText(value)
  copiedKey.value = key
}

async function saveProfile() {
  accountLoading.value = true
  accountNotice.value = ''
  error.value = ''
  try {
    const user = await api.updateMe({ display_name: displayName.value.trim() || null })
    if (status.value) {
      status.value.user = user
    }
    displayName.value = user.display_name || ''
    accountNotice.value = 'Profile updated.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not update profile'
  } finally {
    accountLoading.value = false
  }
}

async function requestEmailChange() {
  emailChangeLoading.value = true
  emailChangeNotice.value = ''
  error.value = ''
  try {
    await api.requestEmailChange({
      new_email: emailChangeNewEmail.value.trim(),
      current_password: emailChangePassword.value || null,
    })
    emailChangePending.value = true
    emailChangeNotice.value = 'Verification code sent.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not request email change'
  } finally {
    emailChangeLoading.value = false
  }
}

async function confirmEmailChange() {
  emailChangeLoading.value = true
  emailChangeNotice.value = ''
  error.value = ''
  try {
    const result = await api.confirmEmailChange({
      new_email: emailChangeNewEmail.value.trim(),
      code: emailChangeCode.value.trim(),
      revoke_other_sessions: true,
    })
    if (status.value?.user) {
      status.value.user.email = result.email
      status.value.user.email_verified = true
    }
    emailChangePassword.value = ''
    emailChangeCode.value = ''
    emailChangePending.value = false
    if (result.revoked_count) {
      const sessions = result.revoked_count === 1 ? '1 other session' : `${result.revoked_count} other sessions`
      emailChangeNotice.value = `Email updated. Revoked ${sessions}.`
    } else {
      emailChangeNotice.value = 'Email updated.'
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not confirm email change'
  } finally {
    emailChangeLoading.value = false
  }
}

async function changePassword() {
  passwordLoading.value = true
  passwordNotice.value = ''
  error.value = ''
  try {
    const result = await api.changePassword({
      current_password: currentPassword.value,
      new_password: newPassword.value,
      revoke_other_sessions: true,
    })
    currentPassword.value = ''
    newPassword.value = ''
    if (result.revoked_count) {
      const sessions = result.revoked_count === 1 ? '1 other session' : `${result.revoked_count} other sessions`
      passwordNotice.value = `Password updated. Revoked ${sessions}.`
    } else {
      passwordNotice.value = 'Password updated.'
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not change password'
  } finally {
    passwordLoading.value = false
  }
}

async function unlinkIdentity(identity: LinkedIdentity) {
  identityLoading.value = identity.id
  identityNotice.value = ''
  error.value = ''
  try {
    await api.unlinkIdentity(identity.id)
    linkedIdentities.value = linkedIdentities.value.filter((item) => item.id !== identity.id)
    identityNotice.value = `${identity.provider} identity unlinked.`
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not unlink identity'
  } finally {
    identityLoading.value = ''
  }
}

async function linkIdentity(provider: OAuthProvider) {
  identityLoading.value = `link:${provider.id}`
  identityNotice.value = ''
  error.value = ''
  try {
    const started = await api.startIdentityLink(provider.id, '/account')
    window.location.assign(started.authorization_url)
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not start identity link'
    identityLoading.value = ''
  }
}

async function exportAccount() {
  exportLoading.value = true
  exportNotice.value = ''
  error.value = ''
  try {
    const payload = await api.exportAccount()
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `gatekeeper-account-${payload.user.email}-${new Date().toISOString().slice(0, 10)}.json`
    anchor.click()
    URL.revokeObjectURL(url)
    exportNotice.value = 'Account export downloaded.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not export account'
  } finally {
    exportLoading.value = false
  }
}

async function deactivateAccount() {
  deactivateLoading.value = true
  deactivateNotice.value = ''
  error.value = ''
  try {
    const result = await api.deactivateAccount({
      current_password: deactivatePassword.value || null,
      totp_code: deactivateTotpCode.value || null,
      recovery_code: deactivateRecoveryCode.value || null,
    })
    deactivateNotice.value = `Account deactivated. Revoked ${result.revoked_sessions} sessions.`
    clearTokens()
    router.push({ path: '/login' })
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not deactivate account'
  } finally {
    deactivateLoading.value = false
  }
}

async function setupTotp() {
  mfaLoading.value = true
  error.value = ''
  mfaNotice.value = ''
  try {
    totpSetup.value = await api.setupTotp()
    mfa.value = await api.mfaStatus()
    mfaNotice.value = 'Authenticator setup generated.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not start 2FA setup'
  } finally {
    mfaLoading.value = false
  }
}

async function enableTotp() {
  mfaLoading.value = true
  error.value = ''
  mfaNotice.value = ''
  try {
    const enabled = await api.enableTotp(totpCode.value)
    mfa.value = enabled
    recoveryCodes.value = enabled.recovery_codes || []
    totpSetup.value = null
    totpCode.value = ''
    mfaNotice.value = 'Authenticator 2FA enabled.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not enable 2FA'
  } finally {
    mfaLoading.value = false
  }
}

async function regenerateRecoveryCodes() {
  mfaLoading.value = true
  error.value = ''
  mfaNotice.value = ''
  try {
    const result = await api.regenerateRecoveryCodes(totpCode.value)
    recoveryCodes.value = result.recovery_codes
    if (mfa.value) {
      mfa.value.recovery_codes_remaining = result.recovery_codes_remaining
    }
    totpCode.value = ''
    mfaNotice.value = 'Recovery codes regenerated.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not regenerate recovery codes'
  } finally {
    mfaLoading.value = false
  }
}

async function disableTotp() {
  mfaLoading.value = true
  error.value = ''
  mfaNotice.value = ''
  try {
    mfa.value = await api.disableTotp(totpCode.value)
    totpSetup.value = null
    recoveryCodes.value = []
    totpCode.value = ''
    mfaNotice.value = 'Authenticator 2FA disabled.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not disable 2FA'
  } finally {
    mfaLoading.value = false
  }
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
          Confirm the owner path, protect APIs, register product clients, issue scoped credentials, and copy integration values.
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
          <h2 class="mt-2 break-words text-lg font-semibold leading-snug">{{ status.user?.email || 'Unknown user' }}</h2>
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

      <section class="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
        <article class="panel p-5">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="mono-label">Readiness</p>
              <h2 class="mt-2 text-3xl font-semibold">{{ setupCompletionPercent }}%</h2>
            </div>
            <span
              class="inline-flex min-h-9 items-center gap-2 rounded-md border px-3 font-mono text-xs"
              :class="severityClass(readinessState === 'ready' ? 'ready' : readinessState === 'blocked' ? 'blocker' : 'warning')"
            >
              <Gauge class="h-4 w-4" aria-hidden="true" />
              {{ readinessState }}
            </span>
          </div>
          <div class="mt-4 h-2 overflow-hidden rounded-full bg-surface">
            <div class="h-full rounded-full bg-accent" :style="{ width: `${setupCompletionPercent}%` }"></div>
          </div>
          <p class="mt-3 font-mono text-xs text-muted">
            {{ completedSetupCount }}/{{ setupSteps.length }} setup checks complete
          </p>
          <RouterLink
            v-if="nextSetupStep"
            :to="nextSetupStep.to"
            class="btn-secondary mt-5 justify-start gap-2 text-sm"
          >
            <ListChecks class="h-4 w-4" aria-hidden="true" />
            Next: {{ nextSetupStep.title }}
          </RouterLink>
          <p v-else class="mt-5 text-sm text-green">Core setup checks are complete.</p>
        </article>

        <article class="panel p-5">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="mono-label">Policy health</p>
              <h2 class="mt-2 text-xl font-semibold">Production signals</h2>
            </div>
            <p class="font-mono text-xs text-muted">
              {{ readinessBlockers.length }} blockers / {{ readinessWarnings.length }} warnings
            </p>
          </div>
          <div class="mt-4 divide-y divide-border">
            <RouterLink
              v-for="item in policyHealthItems"
              :key="item.key"
              :to="item.to"
              class="grid gap-3 py-3 transition hover:text-fg md:grid-cols-[auto_1fr_auto]"
            >
              <span
                class="mt-0.5 grid h-7 w-7 place-items-center rounded-md border"
                :class="severityClass(item.severity)"
              >
                <CheckCircle2 v-if="item.severity === 'ready'" class="h-4 w-4" aria-hidden="true" />
                <ShieldAlert v-else class="h-4 w-4" aria-hidden="true" />
              </span>
              <span>
                <span class="block font-semibold">{{ item.label }}</span>
                <span class="mt-1 block text-sm leading-6 text-muted">{{ item.detail }}</span>
              </span>
              <span class="self-center font-mono text-xs text-muted">{{ item.severity }}</span>
            </RouterLink>
          </div>
        </article>
      </section>

      <section class="grid gap-3">
        <div class="flex items-center justify-between gap-3">
          <p class="mono-label">Operator shortcuts</p>
          <span class="font-mono text-xs text-muted">{{ operatorShortcuts.length }} surfaces</span>
        </div>
        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <RouterLink
            v-for="shortcut in operatorShortcuts"
            :key="shortcut.key"
            :to="shortcut.to"
            class="panel grid gap-3 p-4 transition hover:border-border-active"
            :class="{ 'pointer-events-none opacity-50': !shortcut.enabled }"
          >
            <div class="flex items-start justify-between gap-3">
              <span class="grid h-9 w-9 place-items-center rounded-md border border-border bg-surface text-accent">
                <component :is="shortcut.icon" class="h-4 w-4" aria-hidden="true" />
              </span>
              <span class="font-mono text-xs text-muted">{{ shortcut.enabled ? 'open' : 'locked' }}</span>
            </div>
            <div>
              <h2 class="font-semibold">{{ shortcut.title }}</h2>
              <p class="mt-1 text-sm leading-6 text-muted">{{ shortcut.detail }}</p>
            </div>
          </RouterLink>
        </div>
      </section>

      <div class="grid gap-6 lg:grid-cols-[1fr_0.85fr]">
        <section class="grid gap-3">
          <div class="flex items-center justify-between gap-3">
            <p class="mono-label">First-run wizard</p>
            <span class="font-mono text-xs text-muted">
              {{ completedSetupCount }}/{{ setupSteps.length }}
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
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Hosted auth</p>
                <h2 class="mt-2 text-xl font-semibold">Social providers</h2>
              </div>
              <Globe class="h-5 w-5 text-accent" aria-hidden="true" />
            </div>
            <p class="mt-3 text-sm leading-6 text-muted">
              Configured providers appear on hosted login and signup, and product-owned auth screens can start them through the provider API.
            </p>
            <div class="mt-4 grid gap-3">
              <article v-if="!oauthProviders.length" class="rounded-md border border-border bg-surface p-3 text-sm text-muted">
                No social providers configured.
              </article>
              <template v-else>
                <article
                  v-for="provider in oauthProviders"
                  :key="provider.id"
                  class="rounded-md border border-border bg-surface p-3"
                >
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div class="min-w-0">
                      <h3 class="font-semibold">{{ provider.name }}</h3>
                      <p class="mt-1 break-all font-mono text-xs text-muted">{{ provider.id }}</p>
                      <p class="mt-2 text-xs text-muted">
                        {{ provider.scopes.join(' ') || 'default scopes' }}
                      </p>
                    </div>
                    <span
                      class="rounded-md border px-2 py-1 font-mono text-xs"
                      :class="provider.configured ? 'border-green/50 text-green' : 'border-border text-muted'"
                    >
                      {{ provider.configured ? 'configured' : 'incomplete' }}
                    </span>
                  </div>
                </article>
              </template>
            </div>
            <p v-if="configuredOAuthProviders.length" class="mt-3 text-xs text-muted">
              {{ configuredOAuthProviders.length }} provider{{ configuredOAuthProviders.length === 1 ? '' : 's' }} ready for hosted auth.
            </p>
          </article>

          <article class="panel p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Account</p>
                <h2 class="mt-2 text-xl font-semibold">Linked identities</h2>
              </div>
              <Globe class="h-5 w-5 text-accent" aria-hidden="true" />
            </div>

            <p class="mt-3 text-sm leading-6 text-muted">
              Review social identities connected to this account. Password accounts can unlink external identities; federated-only accounts must add another sign-in method first.
            </p>
            <p v-if="identityNotice" class="mt-3 text-sm text-green">{{ identityNotice }}</p>
            <div v-if="unlinkedOAuthProviders.length" class="mt-4 flex flex-wrap gap-2">
              <button
                v-for="provider in unlinkedOAuthProviders"
                :key="provider.id"
                type="button"
                class="btn-secondary gap-2 text-sm"
                :disabled="identityLoading === `link:${provider.id}`"
                @click="linkIdentity(provider)"
              >
                <Link2 class="h-4 w-4" aria-hidden="true" />
                Link {{ provider.name }}
              </button>
            </div>
            <div class="mt-4 grid gap-3">
              <article v-if="!linkedIdentities.length" class="rounded-md border border-border bg-surface p-3 text-sm text-muted">
                No external identities linked.
              </article>
              <article
                v-for="identity in linkedIdentities"
                :key="identity.id"
                class="rounded-md border border-border bg-surface p-3"
              >
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div class="min-w-0">
                    <h3 class="font-semibold capitalize">{{ identity.provider }}</h3>
                    <p class="mt-1 break-all font-mono text-xs text-muted">{{ identity.email || 'No provider email' }}</p>
                    <p class="mt-2 text-xs text-muted">
                      linked {{ new Date(identity.created_at).toLocaleString() }}
                    </p>
                  </div>
                  <button
                    type="button"
                    class="btn-secondary gap-2 text-sm"
                    :disabled="identityLoading === identity.id"
                    @click="unlinkIdentity(identity)"
                  >
                    <Trash2 class="h-4 w-4" aria-hidden="true" />
                    Unlink
                  </button>
                </div>
              </article>
            </div>
          </article>

          <article class="panel p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Account</p>
                <h2 class="mt-2 text-xl font-semibold">Export and deactivation</h2>
              </div>
              <UserX class="h-5 w-5 text-accent" aria-hidden="true" />
            </div>

            <div class="mt-4 grid gap-3 rounded-md border border-border bg-surface p-3 text-sm leading-6 text-muted">
              <p>
                Export returns profile, memberships, session metadata, connected apps, API-token metadata, linked identities, and recent audit events.
              </p>
              <button type="button" class="btn-secondary gap-2 text-sm" :disabled="exportLoading" @click="exportAccount">
                <Download class="h-4 w-4" aria-hidden="true" />
                Download export
              </button>
              <p v-if="exportNotice" class="text-green">{{ exportNotice }}</p>
            </div>

            <form class="mt-4 grid gap-3 border-t border-border pt-4" @submit.prevent="deactivateAccount">
              <label class="grid gap-2 text-sm text-muted">
                Current password
                <input
                  v-model="deactivatePassword"
                  class="input"
                  type="password"
                  autocomplete="current-password"
                  placeholder="Required for password accounts"
                />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Authenticator code
                <input
                  v-model="deactivateTotpCode"
                  class="input font-mono"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  placeholder="Required if 2FA is enabled"
                />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Recovery code
                <input
                  v-model="deactivateRecoveryCode"
                  class="input font-mono"
                  autocomplete="one-time-code"
                  placeholder="Optional backup code"
                />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Confirmation
                <input v-model="deactivateConfirm" class="input font-mono" placeholder="DEACTIVATE" />
              </label>
              <p class="text-sm text-muted">
                Deactivation suspends this account, revokes sessions, user-owned API tokens, and connected-app grants. Last owners must transfer ownership first.
              </p>
              <p v-if="deactivateNotice" class="text-sm text-green">{{ deactivateNotice }}</p>
              <button
                type="submit"
                class="btn-secondary gap-2 text-sm"
                :disabled="deactivateLoading || deactivateConfirm !== 'DEACTIVATE'"
              >
                <UserX class="h-4 w-4" aria-hidden="true" />
                Deactivate account
              </button>
            </form>
          </article>

          <article class="panel p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Account</p>
                <h2 class="mt-2 text-xl font-semibold">Email</h2>
              </div>
              <Mail class="h-5 w-5 text-accent" aria-hidden="true" />
            </div>

            <form class="mt-4 grid gap-3" @submit.prevent="requestEmailChange">
              <label class="grid gap-2 text-sm text-muted">
                New email
                <input
                  v-model="emailChangeNewEmail"
                  class="input"
                  type="email"
                  autocomplete="email"
                  placeholder="you@example.com"
                  required
                />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                Current password
                <input
                  v-model="emailChangePassword"
                  class="input"
                  type="password"
                  autocomplete="current-password"
                  placeholder="Required for password accounts"
                />
              </label>
              <button
                type="submit"
                class="btn-primary gap-2 text-sm"
                :disabled="emailChangeLoading || !emailChangeNewEmail || emailChangeNewEmail === status.user?.email"
              >
                <Mail class="h-4 w-4" aria-hidden="true" />
                Send verification code
              </button>
            </form>

            <form class="mt-4 grid gap-3 border-t border-border pt-4" @submit.prevent="confirmEmailChange">
              <label class="grid gap-2 text-sm text-muted">
                Verification code
                <input
                  v-model="emailChangeCode"
                  class="input font-mono"
                  inputmode="text"
                  autocomplete="one-time-code"
                  placeholder="ABC12345"
                />
              </label>
              <p v-if="emailChangeNotice" class="text-sm text-green">{{ emailChangeNotice }}</p>
              <button
                type="submit"
                class="btn-secondary gap-2 text-sm"
                :disabled="emailChangeLoading || !emailChangePending || !emailChangeCode"
              >
                <CheckCircle2 class="h-4 w-4" aria-hidden="true" />
                Confirm email change
              </button>
            </form>
          </article>

          <article class="panel p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Account</p>
                <h2 class="mt-2 text-xl font-semibold">Profile</h2>
              </div>
              <UserRound class="h-5 w-5 text-accent" aria-hidden="true" />
            </div>

            <form class="mt-4 grid gap-3" @submit.prevent="saveProfile">
              <label class="grid gap-2 text-sm text-muted">
                Display name
                <input
                  v-model="displayName"
                  class="input"
                  autocomplete="name"
                  maxlength="160"
                  placeholder="Example User"
                />
              </label>
              <p class="break-words font-mono text-xs text-muted">{{ status.user?.email }}</p>
              <p v-if="accountNotice" class="text-sm text-green">{{ accountNotice }}</p>
              <button type="submit" class="btn-primary gap-2 text-sm" :disabled="accountLoading">
                <Save class="h-4 w-4" aria-hidden="true" />
                Save profile
              </button>
            </form>
          </article>

          <article class="panel p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Account</p>
                <h2 class="mt-2 text-xl font-semibold">Password</h2>
              </div>
              <LockKeyhole class="h-5 w-5 text-accent" aria-hidden="true" />
            </div>

            <form class="mt-4 grid gap-3" @submit.prevent="changePassword">
              <label class="grid gap-2 text-sm text-muted">
                Current password
                <input
                  v-model="currentPassword"
                  class="input"
                  type="password"
                  autocomplete="current-password"
                />
              </label>
              <label class="grid gap-2 text-sm text-muted">
                New password
                <input
                  v-model="newPassword"
                  class="input"
                  type="password"
                  minlength="12"
                  autocomplete="new-password"
                />
              </label>
              <p v-if="passwordNotice" class="text-sm text-green">{{ passwordNotice }}</p>
              <button
                type="submit"
                class="btn-primary gap-2 text-sm"
                :disabled="passwordLoading || !currentPassword || newPassword.length < 12"
              >
                <KeyRound class="h-4 w-4" aria-hidden="true" />
                Change password
              </button>
            </form>
          </article>

          <article class="panel p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="mono-label">Security</p>
                <h2 class="mt-2 text-xl font-semibold">Authenticator 2FA</h2>
              </div>
              <span class="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-muted">
                {{ mfaStateLabel }}
              </span>
            </div>

            <div class="mt-4 flex gap-3 rounded-md border border-border bg-surface p-3 text-sm leading-6 text-muted">
              <ShieldCheck class="mt-0.5 h-5 w-5 shrink-0 text-green" aria-hidden="true" />
              <p>{{ mfaDetail }}</p>
            </div>

            <p v-if="mfaNotice" class="mt-3 text-sm text-green">{{ mfaNotice }}</p>

            <div v-if="recoveryCodes.length" class="mt-4 grid gap-3 rounded-md border border-green/35 bg-green/10 p-3">
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p class="font-mono text-xs text-green">copy-once recovery codes</p>
                  <p class="mt-1 text-sm text-muted">Store these now. Each code works once if the authenticator is unavailable.</p>
                </div>
                <button
                  type="button"
                  class="btn-secondary min-h-8 gap-2 px-2.5 text-xs"
                  @click="copyText('recovery-codes', recoveryCodesText)"
                >
                  <Copy class="h-3.5 w-3.5" aria-hidden="true" />
                  {{ copiedKey === 'recovery-codes' ? 'Copied' : 'Copy' }}
                </button>
              </div>
              <pre class="overflow-x-auto rounded-md bg-bg p-3 font-mono text-xs leading-5 text-muted">{{ recoveryCodesText }}</pre>
            </div>

            <div v-if="totpSetup" class="mt-4 grid gap-3">
              <div class="grid gap-2">
                <div class="flex items-center justify-between gap-3">
                  <span class="font-mono text-xs text-muted">secret</span>
                  <button
                    type="button"
                    class="btn-secondary min-h-8 gap-2 px-2.5 text-xs"
                    @click="copyText('totp-secret', totpSetup.secret)"
                  >
                    <Copy class="h-3.5 w-3.5" aria-hidden="true" />
                    {{ copiedKey === 'totp-secret' ? 'Copied' : 'Copy' }}
                  </button>
                </div>
                <pre class="overflow-x-auto rounded-md bg-bg p-3 font-mono text-xs text-muted">{{ totpSetup.secret }}</pre>
              </div>

              <div class="grid gap-2">
                <div class="flex items-center justify-between gap-3">
                  <span class="font-mono text-xs text-muted">otpauth uri</span>
                  <button
                    type="button"
                    class="btn-secondary min-h-8 gap-2 px-2.5 text-xs"
                    @click="copyText('totp-uri', totpSetup.otpauth_uri)"
                  >
                    <Copy class="h-3.5 w-3.5" aria-hidden="true" />
                    {{ copiedKey === 'totp-uri' ? 'Copied' : 'Copy' }}
                  </button>
                </div>
                <pre class="max-h-24 overflow-auto rounded-md bg-bg p-3 font-mono text-xs leading-5 text-muted">{{ totpSetup.otpauth_uri }}</pre>
              </div>
            </div>

            <div class="mt-4 grid gap-3">
              <label class="grid gap-2 text-sm text-muted">
                Authenticator code
                <input
                  v-model="totpCode"
                  class="input font-mono"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  placeholder="123456"
                />
              </label>
              <div class="flex flex-wrap gap-2">
                <button
                  v-if="!mfa?.totp_enabled && !totpSetup"
                  type="button"
                  class="btn-secondary gap-2 text-sm"
                  :disabled="mfaLoading"
                  @click="setupTotp"
                >
                  <KeyRound class="h-4 w-4" aria-hidden="true" />
                  {{ mfa?.totp_pending ? 'Restart setup' : 'Start setup' }}
                </button>
                <button
                  v-if="totpSetup"
                  type="button"
                  class="btn-primary gap-2 text-sm"
                  :disabled="mfaLoading || !totpCode"
                  @click="enableTotp"
                >
                  <ShieldCheck class="h-4 w-4" aria-hidden="true" />
                  Enable 2FA
                </button>
                <button
                  v-if="mfa?.totp_enabled"
                  type="button"
                  class="btn-secondary gap-2 text-sm"
                  :disabled="mfaLoading || !totpCode"
                  @click="regenerateRecoveryCodes"
                >
                  <KeyRound class="h-4 w-4" aria-hidden="true" />
                  Regenerate recovery codes
                </button>
                <button
                  v-if="mfa?.totp_enabled"
                  type="button"
                  class="btn-secondary gap-2 text-sm"
                  :disabled="mfaLoading || !totpCode"
                  @click="disableTotp"
                >
                  <ShieldAlert class="h-4 w-4" aria-hidden="true" />
                  Disable 2FA
                </button>
              </div>
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
                to="/providers"
                class="btn-secondary justify-start gap-2 text-sm"
                :class="{ 'pointer-events-none opacity-60': !status.scopes.includes('*') }"
              >
                <Globe class="h-4 w-4" aria-hidden="true" />
                Configure social provider
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
                {{ copiedKey === 'env' ? 'Copied' : 'Copy' }}
              </button>
            </div>
            <pre class="mt-4 overflow-x-auto rounded-md bg-bg p-3 text-xs text-muted">{{ integrationSnippet }}</pre>
          </article>
        </section>
      </div>

      <section class="grid gap-3">
        <div class="flex items-center justify-between gap-3">
          <p class="mono-label">Integration surfaces</p>
          <span class="font-mono text-xs text-muted">{{ integrationSurfaces.length }} paths</span>
        </div>
        <div class="grid gap-4 xl:grid-cols-2">
          <article
            v-for="surface in integrationSurfaces"
            :key="surface.key"
            class="panel grid gap-4 p-4"
          >
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div class="flex items-start gap-3">
                <span class="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-border bg-surface text-accent">
                  <component :is="surface.icon" class="h-4 w-4" aria-hidden="true" />
                </span>
                <div>
                  <h2 class="font-semibold">{{ surface.title }}</h2>
                  <p class="mt-1 font-mono text-xs text-muted">{{ surface.status }}</p>
                </div>
              </div>
              <RouterLink :to="surface.to" class="btn-secondary min-h-9 px-3 text-xs">
                {{ surface.cta }}
              </RouterLink>
            </div>
            <div class="grid gap-2">
              <div class="flex items-center justify-between gap-3">
                <span class="font-mono text-xs text-muted">copy block</span>
                <button
                  type="button"
                  class="btn-secondary min-h-8 gap-2 px-2.5 text-xs"
                  @click="copyText(surface.key, surface.snippet)"
                >
                  <Copy class="h-3.5 w-3.5" aria-hidden="true" />
                  {{ copiedKey === surface.key ? 'Copied' : 'Copy' }}
                </button>
              </div>
              <pre class="min-h-28 overflow-x-auto rounded-md bg-bg p-3 text-xs leading-5 text-muted">{{ surface.snippet }}</pre>
            </div>
          </article>
        </div>
      </section>

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
