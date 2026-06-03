import type { ApiToken, AuditEvent, AuthClient, Org, TokenResponse, User } from '@/types'

const API_BASE = import.meta.env.VITE_GATEKEEPER_API_URL || ''
const ACCESS_KEY = 'gatekeeper.access_token'
const REFRESH_KEY = 'gatekeeper.refresh_token'

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
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Content-Type', 'application/json')
  const token = getAccessToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: 'include',
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    throw new Error(body.detail || response.statusText)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return response.json() as Promise<T>
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
    await request('/api/v1/auth/logout', { method: 'POST' })
    clearTokens()
  },
  me() {
    return request<{ user: User | null; scopes: string[]; org_id?: string | null }>('/api/v1/auth/me')
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
  createClient(payload: Partial<AuthClient> & { name: string }) {
    return request<AuthClient>('/api/v1/clients', {
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
  }) {
    return request<ApiToken>('/api/v1/tokens', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  revokeToken(id: string) {
    return request(`/api/v1/tokens/${id}`, { method: 'DELETE' })
  },
  audit() {
    return request<AuditEvent[]>('/api/v1/audit')
  },
}

