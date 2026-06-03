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

export interface SetupStatus {
  issuer: string
  jwks_uri: string
  user?: User | null
  org?: Org | null
  orgs: Org[]
  auth_type: string
  scopes: string[]
  owner_exists: boolean
  can_manage_clients: boolean
  can_issue_tokens: boolean
  can_manage_projects: boolean
  can_manage_roles: boolean
  access_expires_at?: string | null
  smtp_configured: boolean
  email_dev_mode: boolean
  dynamic_client_registration_enabled: boolean
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

export interface Workspace {
  id: string
  org_id: string
  name: string
  slug: string
}

export interface Project {
  id: string
  org_id: string
  workspace_id?: string | null
  name: string
  slug: string
  audience: string
}

export interface Role {
  id: string
  org_id?: string | null
  name: string
  permissions: string[]
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

export interface Session {
  id: string
  user_id: string
  org_id?: string | null
  ip_address?: string | null
  user_agent?: string | null
  expires_at: string
  revoked_at?: string | null
  created_at: string
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
