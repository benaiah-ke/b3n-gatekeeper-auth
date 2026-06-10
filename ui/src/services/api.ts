import type {
  AdminUser,
  AccountDeactivateResult,
  AccountExport,
  ApiToken,
  AuditEvent,
  AuditPruneResult,
  AuthorizeContext,
  AuthClient,
  EmailChangeResult,
  Invitation,
  LinkedIdentity,
  MfaRecoveryCodes,
  MfaStatus,
  OAuthGrant,
  OAuthProvider,
  OAuthProviderAdmin,
  OAuthProviderAdminCreate,
  OAuthProviderAdminUpdate,
  Org,
  PasswordChangeResult,
  Project,
  Role,
  Session,
  SetupStatus,
  TokenResponse,
  TotpEnable,
  TotpSetup,
  User,
  UserDeleteResult,
  UserProvisionResult,
  Workspace,
} from '@/types'

const API_BASE = import.meta.env.VITE_GATEKEEPER_API_URL || ''
const ACCESS_KEY = 'gatekeeper.access_token'
const REFRESH_KEY = 'gatekeeper.refresh_token'

export function gatekeeperApiUrl(path: string) {
  return `${API_BASE}${path}`
}

export class GateKeeperApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'GateKeeperApiError'
    this.status = status
  }
}

function fallbackForStatus(status: number, statusText: string) {
  if (status === 0) {
    return 'GateKeeper API is unreachable. Check the API URL and container status.'
  }
  if (status === 400 || status === 422) {
    return 'Please check the form fields and try again.'
  }
  if (status === 401) {
    return 'Authentication failed. Sign in again and retry.'
  }
  if (status === 403) {
    return 'You do not have permission to perform this action.'
  }
  if (status === 404) {
    return 'The requested GateKeeper resource was not found.'
  }
  if (status === 409) {
    return 'This value already exists.'
  }
  if (status === 429) {
    return 'Too many attempts. Wait a moment and try again.'
  }
  if (status >= 500) {
    return 'GateKeeper is unavailable. Try again shortly.'
  }
  return statusText || 'GateKeeper request failed.'
}

function labelFromLocation(location: unknown) {
  if (!Array.isArray(location)) {
    return ''
  }

  return location
    .filter((part) => part !== 'body' && part !== 'query' && part !== 'path')
    .map((part) => String(part).replace(/_/g, ' '))
    .join(' ')
}

function messageFromErrorItem(item: unknown, fallback: string): string {
  if (typeof item === 'string') {
    return item
  }
  if (!item || typeof item !== 'object') {
    return ''
  }

  const record = item as Record<string, unknown>
  const message = [record.msg, record.message, record.detail, record.error].find(
    (value): value is string => typeof value === 'string' && value.trim().length > 0,
  )
  if (!message) {
    return ''
  }

  const location = labelFromLocation(record.loc)
  return location ? `${location}: ${message}` : message || fallback
}

function messageFromApiError(payload: unknown, fallback: string): string {
  if (typeof payload === 'string') {
    return payload
  }

  if (Array.isArray(payload)) {
    const messages = payload
      .map((item) => messageFromErrorItem(item, fallback))
      .filter((message) => message.length > 0)

    if (messages.length) {
      return messages.slice(0, 3).join(' ')
    }
    return fallback
  }

  if (!payload || typeof payload !== 'object') {
    return fallback
  }

  const record = payload as Record<string, unknown>
  if (record.detail !== undefined) {
    return messageFromApiError(record.detail, fallback)
  }

  const directMessage = [record.message, record.error, record.reason].find(
    (value): value is string => typeof value === 'string' && value.trim().length > 0,
  )
  if (directMessage) {
    return directMessage
  }

  const fieldMessages = Object.entries(record)
    .filter(([, value]) => typeof value === 'string' && value.trim().length > 0)
    .map(([field, value]) => `${field.replace(/_/g, ' ')}: ${value}`)

  return fieldMessages.length ? fieldMessages.slice(0, 3).join(' ') : fallback
}

export function getAccessToken() {
  return localStorage.getItem(ACCESS_KEY)
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_KEY)
}

export function saveTokens(response: TokenResponse) {
  localStorage.setItem(ACCESS_KEY, response.access_token)
  if (response.refresh_token) {
    localStorage.setItem(REFRESH_KEY, response.refresh_token)
  }
  cookieSessionVerified = true
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
  cookieSessionVerified = false
}

let cookieSessionVerified = false

async function refreshAccessToken() {
  const refreshToken = getRefreshToken()
  const body = refreshToken ? { refresh_token: refreshToken } : {}

  const response = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    clearTokens()
    return false
  }

  saveTokens((await response.json()) as TokenResponse)
  return true
}

async function request<T>(path: string, options: RequestInit = {}, allowRefresh = true): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Content-Type', 'application/json')
  const token = getAccessToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      credentials: 'include',
    })
  } catch {
    throw new GateKeeperApiError(fallbackForStatus(0, ''), 0)
  }
  if (response.status === 401 && allowRefresh && path !== '/api/v1/auth/refresh') {
    const refreshed = await refreshAccessToken()
    if (refreshed) {
      return request<T>(path, options, false)
    }
  }
  if (!response.ok) {
    const fallback = fallbackForStatus(response.status, response.statusText)
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    throw new GateKeeperApiError(messageFromApiError(body, fallback), response.status)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return response.json() as Promise<T>
}

export async function hasAuthenticatedSession() {
  if (cookieSessionVerified) {
    return true
  }

  if (getAccessToken()) {
    try {
      await request('/api/v1/auth/me', {}, false)
      cookieSessionVerified = true
      return true
    } catch {
      return refreshAccessToken()
    }
  }

  if (getRefreshToken() && (await refreshAccessToken())) {
    return true
  }

  try {
    await request('/api/v1/auth/me', {}, false)
    cookieSessionVerified = true
    return true
  } catch {
    return refreshAccessToken()
  }
}

export const api = {
  async signup(email: string, password: string, displayName?: string) {
    const body = { email, password, display_name: displayName || null }
    const result = await request<TokenResponse>('/api/v1/auth/signup', {
      method: 'POST',
      body: JSON.stringify(body),
    })
    saveTokens(result)
    return result
  },
  async login(
    email: string,
    password: string,
    totpCode?: string,
    recoveryCode?: string,
    context: { clientId?: string | null; scope?: string | null; audience?: string | null } = {},
  ) {
    const result = await request<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password,
        client_id: context.clientId || null,
        scope: context.scope || null,
        audience: context.audience || null,
        totp_code: totpCode || null,
        recovery_code: recoveryCode || null,
      }),
    })
    saveTokens(result)
    return result
  },
  async acceptInvitation(
    email: string,
    password: string,
    token: string,
    displayName?: string,
    totpCode?: string,
    recoveryCode?: string,
  ) {
    const result = await request<TokenResponse>('/api/v1/auth/invitations/accept', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password,
        token,
        display_name: displayName || null,
        totp_code: totpCode || null,
        recovery_code: recoveryCode || null,
      }),
    })
    saveTokens(result)
    return result
  },
  async logout() {
    try {
      await request('/api/v1/auth/logout', { method: 'POST' }, false)
    } finally {
      clearTokens()
    }
  },
  me() {
    return request<{ user: User | null; scopes: string[]; org_id?: string | null }>('/api/v1/auth/me')
  },
  updateMe(payload: { display_name?: string | null }) {
    return request<User>('/api/v1/auth/me', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },
  changePassword(payload: { current_password: string; new_password: string; revoke_other_sessions?: boolean }) {
    return request<PasswordChangeResult>('/api/v1/auth/password/change', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  requestEmailChange(payload: { new_email: string; current_password?: string | null }) {
    return request<{ status: string }>('/api/v1/auth/email/change/request', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  confirmEmailChange(payload: { new_email: string; code: string; revoke_other_sessions?: boolean }) {
    return request<EmailChangeResult>('/api/v1/auth/email/change/confirm', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  linkedIdentities() {
    return request<LinkedIdentity[]>('/api/v1/auth/identities')
  },
  unlinkIdentity(id: string) {
    return request<{ status: string; id: string }>(`/api/v1/auth/identities/${id}`, { method: 'DELETE' })
  },
  oauthProviders() {
    return request<OAuthProvider[]>('/api/v1/auth/oauth/providers')
  },
  startOAuthProvider(id: string, redirect?: string) {
    const suffix = redirect ? `?${new URLSearchParams({ redirect }).toString()}` : ''
    return request<{ provider: string; state: string; authorization_url: string }>(
      `/api/v1/auth/oauth/${id}/start${suffix}`,
    )
  },
  startIdentityLink(id: string, redirect?: string) {
    const suffix = redirect ? `?${new URLSearchParams({ redirect }).toString()}` : ''
    return request<{ provider: string; state: string; authorization_url: string }>(
      `/api/v1/auth/identities/${id}/link/start${suffix}`,
    )
  },
  oauthProvidersAdmin() {
    return request<OAuthProviderAdmin[]>('/api/v1/auth/oauth/providers/admin')
  },
  createOAuthProvider(payload: OAuthProviderAdminCreate) {
    return request<OAuthProviderAdmin>('/api/v1/auth/oauth/providers/admin', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  updateOAuthProvider(providerId: string, payload: OAuthProviderAdminUpdate) {
    return request<OAuthProviderAdmin>(`/api/v1/auth/oauth/providers/admin/${providerId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },
  deleteOAuthProvider(providerId: string) {
    return request<{ status: string; id: string }>(`/api/v1/auth/oauth/providers/admin/${providerId}`, {
      method: 'DELETE',
    })
  },
  exportAccount() {
    return request<AccountExport>('/api/v1/auth/account/export')
  },
  deactivateAccount(payload: { current_password?: string | null; totp_code?: string | null; recovery_code?: string | null }) {
    return request<AccountDeactivateResult>('/api/v1/auth/account/deactivate', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  setupStatus() {
    return request<SetupStatus>('/api/v1/setup/status')
  },
  mfaStatus() {
    return request<MfaStatus>('/api/v1/auth/mfa/status')
  },
  setupTotp() {
    return request<TotpSetup>('/api/v1/auth/mfa/totp/setup', { method: 'POST' })
  },
  enableTotp(code: string) {
    return request<TotpEnable>('/api/v1/auth/mfa/totp/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  },
  regenerateRecoveryCodes(code: string) {
    return request<MfaRecoveryCodes>('/api/v1/auth/mfa/recovery-codes/regenerate', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  },
  disableTotp(code: string) {
    return request<MfaStatus>('/api/v1/auth/mfa/totp/disable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  },
  users(params: { orgId?: string; q?: string } = {}) {
    const query = new URLSearchParams()
    if (params.orgId) query.set('org_id', params.orgId)
    if (params.q) query.set('q', params.q)
    const suffix = query.toString() ? `?${query.toString()}` : ''
    return request<AdminUser[]>(`/api/v1/users${suffix}`)
  },
  updateUser(id: string, payload: { display_name?: string | null; email_verified?: boolean; disabled?: boolean }) {
    return request<AdminUser>(`/api/v1/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },
  updateUserMembership(id: string, payload: { org_id: string; role_id?: string | null; role?: string | null; status: string }) {
    return request<AdminUser>(`/api/v1/users/${id}/membership`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    })
  },
  provisionUser(payload: {
    org_id: string
    email: string
    display_name?: string | null
    email_verified?: boolean | null
    disabled?: boolean | null
    role_id?: string | null
    role?: string | null
    status?: string
  }) {
    return request<UserProvisionResult>('/api/v1/users/provision', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  revokeUserSessions(id: string) {
    return request<{ status: string; revoked_count: number }>(`/api/v1/users/${id}/sessions/revoke`, {
      method: 'POST',
    })
  },
  resetUserTotp(id: string) {
    return request<{ status: string; revoked_count: number; user: AdminUser }>(`/api/v1/users/${id}/mfa/totp/reset`, {
      method: 'POST',
    })
  },
  deleteUser(id: string, payload: { dry_run?: boolean; confirm_email?: string | null }) {
    return request<UserDeleteResult>(`/api/v1/users/${id}/delete`, {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  invitations(params: { orgId?: string; includeInactive?: boolean } = {}) {
    const query = new URLSearchParams()
    if (params.orgId) query.set('org_id', params.orgId)
    if (params.includeInactive) query.set('include_inactive', 'true')
    const suffix = query.toString() ? `?${query.toString()}` : ''
    return request<Invitation[]>(`/api/v1/invitations${suffix}`)
  },
  createInvitation(payload: {
    email: string
    org_id: string
    role_id?: string | null
    role?: string | null
    expires_in_days?: number
  }) {
    return request<Invitation>('/api/v1/invitations', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  revokeInvitation(id: string) {
    return request<{ status: string; id: string }>(`/api/v1/invitations/${id}`, { method: 'DELETE' })
  },
  orgs() {
    return request<Org[]>('/api/v1/orgs')
  },
  async switchOrg(payload: {
    org_id: string
    client_id?: string | null
    scope?: string | null
    audience?: string | null
    revoke_current_session?: boolean
  }) {
    const result = await request<TokenResponse>('/api/v1/auth/session/switch-org', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    saveTokens(result)
    return result
  },
  updateOrg(
    id: string,
    payload: {
      name?: string
      require_mfa?: boolean
      trusted_device_mfa_bypass?: boolean
      admin_step_up_mfa_required?: boolean
      session_idle_timeout_minutes?: number | null
      audit_retention_days?: number | null
      allow_user_hard_delete?: boolean
    },
  ) {
    return request<Org>(`/api/v1/orgs/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },
  authorizeContext(query: string) {
    const suffix = query.startsWith('?') || !query ? query : `?${query}`
    return request<AuthorizeContext>(`/api/v1/oauth/authorize/context${suffix}`)
  },
  oauthGrants() {
    return request<OAuthGrant[]>('/api/v1/oauth/grants')
  },
  oauthGrantsAdmin(params: { orgId?: string; clientId?: string; userId?: string; includeRevoked?: boolean } = {}) {
    const query = new URLSearchParams()
    if (params.orgId) query.set('org_id', params.orgId)
    if (params.clientId) query.set('client_id', params.clientId)
    if (params.userId) query.set('user_id', params.userId)
    if (params.includeRevoked) query.set('include_revoked', 'true')
    const suffix = query.toString() ? `?${query.toString()}` : ''
    return request<OAuthGrant[]>(`/api/v1/oauth/grants/admin${suffix}`)
  },
  revokeOAuthGrant(id: string) {
    return request<{ status: string; id: string }>(`/api/v1/oauth/grants/${id}`, { method: 'DELETE' })
  },
  revokeOAuthGrantAdmin(id: string) {
    return request<{ status: string; id: string }>(`/api/v1/oauth/grants/admin/${id}`, { method: 'DELETE' })
  },
  requestCode(email: string, purpose = 'login') {
    return request<{ status: string }>('/api/v1/auth/email-code/request', {
      method: 'POST',
      body: JSON.stringify({ email, purpose }),
    })
  },
  verifyCode(email: string, code: string, purpose = 'login') {
    return request<TokenResponse>('/api/v1/auth/email-code/verify', {
      method: 'POST',
      body: JSON.stringify({ email, code, purpose }),
    }).then((result) => {
      saveTokens(result)
      return result
    })
  },
  approveDevice(userCode: string, approve = true, orgId?: string, totpCode?: string, recoveryCode?: string) {
    return request<{ status: string }>('/api/v1/auth/device/approve', {
      method: 'POST',
      body: JSON.stringify({
        user_code: userCode,
        approve,
        org_id: orgId || null,
        totp_code: totpCode || null,
        recovery_code: recoveryCode || null,
      }),
    })
  },
  clients() {
    return request<AuthClient[]>('/api/v1/clients')
  },
  createClient(
    payload: Partial<AuthClient> & {
      name: string
      org_id?: string | null
      mcp_resource_uri?: string | null
      session_idle_timeout_minutes?: number | null
    },
  ) {
    return request<AuthClient>('/api/v1/clients', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  updateClient(id: string, payload: Partial<AuthClient>) {
    return request<AuthClient>(`/api/v1/clients/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },
  rotateClientSecret(id: string) {
    return request<AuthClient>(`/api/v1/clients/${id}/rotate-secret`, { method: 'POST' })
  },
  deleteClient(id: string) {
    return request<{ status: string; id: string }>(`/api/v1/clients/${id}`, { method: 'DELETE' })
  },
  workspaces(orgId?: string) {
    const query = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ''
    return request<Workspace[]>(`/api/v1/workspaces${query}`)
  },
  createWorkspace(payload: { org_id: string; name: string; slug: string }) {
    return request<Workspace>('/api/v1/workspaces', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  projects(orgId?: string) {
    const query = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ''
    return request<Project[]>(`/api/v1/projects${query}`)
  },
  createProject(payload: {
    org_id: string
    workspace_id?: string | null
    name: string
    slug: string
    audience: string
  }) {
    return request<Project>('/api/v1/projects', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  roles(orgId?: string) {
    const query = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ''
    return request<Role[]>(`/api/v1/roles${query}`)
  },
  createRole(payload: { org_id?: string | null; name: string; permissions: string[] }) {
    return request<Role>('/api/v1/roles', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  tokens() {
    return request<ApiToken[]>('/api/v1/tokens')
  },
  createToken(payload: {
    name: string
    token_type: string
    scopes: string[]
    audiences: string[]
    org_id?: string | null
    project_id?: string | null
    client_id?: string | null
    expires_at?: string | null
  }) {
    return request<ApiToken>('/api/v1/tokens', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  revokeToken(id: string) {
    return request(`/api/v1/tokens/${id}`, { method: 'DELETE' })
  },
  rotateToken(id: string) {
    return request<ApiToken>(`/api/v1/tokens/${id}/rotate`, { method: 'POST' })
  },
  sessions() {
    return request<Session[]>('/api/v1/sessions')
  },
  revokeSession(id: string) {
    return request(`/api/v1/sessions/${id}`, { method: 'DELETE' })
  },
  updateSessionDevice(
    id: string,
    payload: { device_label?: string | null; trusted?: boolean; trusted_until?: string | null },
  ) {
    return request<Session>(`/api/v1/sessions/${id}/device`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },
  revokeAllSessions(includeCurrent = true) {
    return request<{ status: string; revoked_count: number; include_current: boolean }>('/api/v1/sessions/revoke-all', {
      method: 'POST',
      body: JSON.stringify({ include_current: includeCurrent }),
    })
  },
  mcpResources() {
    return request<Array<{ id: string; name: string; resource_uri: string; scopes: string[] }>>('/api/v1/mcp/resources')
  },
  createMcpResource(payload: { name: string; org_id?: string | null; resource_uri: string; scopes: string[] }) {
    return request<{ id: string; resource_uri: string; scopes: string[] }>('/api/v1/mcp/resources', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  audit(filters: Record<string, string> = {}) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(filters)) {
      if (value) {
        params.set(key, value)
      }
    }
    const query = params.toString() ? `?${params.toString()}` : ''
    return request<AuditEvent[]>(`/api/v1/audit${query}`)
  },
  pruneAudit(payload: { org_id?: string | null; dry_run?: boolean }) {
    return request<AuditPruneResult>('/api/v1/audit/prune', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
}
