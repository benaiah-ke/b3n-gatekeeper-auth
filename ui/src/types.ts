export interface User {
  id: string
  email: string
  display_name?: string | null
  email_verified: boolean
}

export interface Org {
  id: string
  name: string
  slug: string
  role?: string | null
  permissions: string[]
}

export interface TokenResponse {
  access_token: string
  refresh_token?: string | null
  expires_in: number
  scope: string
  user?: User | null
  orgs: Org[]
}

export interface AuthClient {
  id: string
  name: string
  client_id: string
  public: boolean
  enabled: boolean
  redirect_uris: string[]
  allowed_origins: string[]
  audiences: string[]
  scopes: string[]
  require_org_membership: boolean
  mcp_resource_uri?: string | null
  client_secret?: string
}

export interface ApiToken {
  id: string
  name: string
  token_type: string
  token_hint: string
  scopes: string[]
  audiences: string[]
  created_at: string
  expires_at?: string | null
  revoked_at?: string | null
  last_used_at?: string | null
  token?: string | null
}

export interface AuditEvent {
  id: string
  action: string
  actor_user_id?: string | null
  org_id?: string | null
  target_type?: string | null
  target_id?: string | null
  details: Record<string, unknown>
  created_at: string
}

