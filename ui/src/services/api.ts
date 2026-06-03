import type {
  ApiToken,
  AuditEvent,
  AuthClient,
  Org,
  Project,
  Role,
  Session,
  SetupStatus,
  TokenResponse,
  User,
  Workspace,
} from '@/types'

const API_BASE = import.meta.env.VITE_GATEKEEPER_API_URL || ''
const ACCESS_KEY = 'gatekeeper.access_token'
const REFRESH_KEY = 'gatekeeper.refresh_token'

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
  if (!refreshToken) {
    return false
  }

  const response = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ refresh_token: refreshToken }),
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
  if (getAccessToken() || getRefreshToken() || cookieSessionVerified) {
    return true
  }

  try {
    await request('/api/v1/auth/me', {}, false)
    cookieSessionVerified = true
    return true
  } catch {
    return false
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
  async login(email: string, password: string) {
    const result = await request<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
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
  setupStatus() {
    return request<SetupStatus>('/api/v1/setup/status')
  },
  orgs() {
    return request<Org[]>('/api/v1/orgs')
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
  approveDevice(userCode: string, approve = true, orgId?: string) {
    return request<{ status: string }>('/api/v1/auth/device/approve', {
      method: 'POST',
      body: JSON.stringify({ user_code: userCode, approve, org_id: orgId || null }),
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
}
