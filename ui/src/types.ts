export interface User {
  id: string
  email: string
  display_name?: string | null
  email_verified: boolean
  mfa_totp_enabled: boolean
}

export interface UserMembership {
  id: string
  org_id: string
  org_name: string
  role_id: string
  role: string
  permissions: string[]
  status: string
  created_at: string
  updated_at: string
}

export interface Invitation {
  id: string
  org_id: string
  org_name: string
  email: string
  role_id: string
  role: string
  permissions: string[]
  invited_by_user_id?: string | null
  accepted_user_id?: string | null
  token_hint: string
  token?: string
  expires_at: string
  accepted_at?: string | null
  revoked_at?: string | null
  created_at: string
  updated_at: string
}

export interface AdminUser extends User {
  disabled: boolean
  created_at: string
  updated_at: string
  mfa_totp_enabled_at?: string | null
  memberships: UserMembership[]
}

export interface LinkedIdentity {
  id: string
  provider: string
  email?: string | null
  created_at: string
  updated_at: string
}

export interface OAuthProvider {
  id: string
  name: string
  configured: boolean
  scopes: string[]
  start_url: string
  authorization_url: string
  require_verified_email: boolean
  allow_email_linking: boolean
}

export interface OAuthProviderAdmin {
  id: string
  provider_id: string
  source: 'database' | 'env'
  read_only: boolean
  name: string
  enabled: boolean
  configured: boolean
  client_id: string
  client_secret_configured: boolean
  authorization_url: string
  token_url: string
  userinfo_url: string
  redirect_uri: string
  scopes: string[]
  subject_claim: string
  email_claim: string
  name_claim: string
  email_verified_claim: string
  allow_email_linking: boolean
  require_verified_email: boolean
  created_at?: string | null
  updated_at?: string | null
}

export interface OAuthProviderAdminCreate {
  provider_id: string
  name: string
  enabled?: boolean
  client_id?: string
  client_secret?: string | null
  authorization_url: string
  token_url: string
  userinfo_url: string
  redirect_uri?: string
  scopes?: string[]
  subject_claim?: string
  email_claim?: string
  name_claim?: string
  email_verified_claim?: string
  allow_email_linking?: boolean
  require_verified_email?: boolean
}

export type OAuthProviderAdminUpdate = Partial<Omit<OAuthProviderAdminCreate, 'provider_id'>>

export interface Org {
  id: string
  name: string
  slug: string
  require_mfa: boolean
  trusted_device_mfa_bypass: boolean
  admin_step_up_mfa_required: boolean
  session_idle_timeout_minutes?: number | null
  audit_retention_days?: number | null
  allow_user_hard_delete: boolean
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

export interface PasswordChangeResult {
  status: string
  revoked_count: number
  current_session_kept: boolean
}

export interface EmailChangeResult {
  status: string
  email: string
  revoked_count: number
  current_session_kept: boolean
}

export interface AccountExport {
  exported_at: string
  user: User
  memberships: Org[]
  mfa: {
    totp_enabled: boolean
    totp_enabled_at?: string | null
    recovery_codes_remaining: number
  }
  sessions: Session[]
  api_tokens: ApiToken[]
  oauth_grants: OAuthGrant[]
  identities: Array<{
    id: string
    provider: string
    email?: string | null
    created_at: string
  }>
  recent_audit_events: AuditEvent[]
}

export interface AccountDeactivateResult {
  status: string
  revoked_sessions: number
  revoked_tokens: number
  revoked_grants: number
}

export interface UserDeleteResult {
  status: string
  dry_run: boolean
  user_id: string
  email: string
  counts: Record<string, number>
  policy_org_ids: string[]
}

export interface UserProvisionResult {
  status: 'created' | 'updated'
  created_user: boolean
  created_membership: boolean
  revoked_sessions: number
  user: AdminUser
}

export interface MfaStatus {
  totp_enabled: boolean
  totp_enabled_at?: string | null
  totp_pending: boolean
  recovery_codes_remaining: number
}

export interface TotpSetup {
  secret: string
  otpauth_uri: string
  issuer: string
  account: string
}

export interface TotpEnable extends MfaStatus {
  recovery_codes: string[]
}

export interface MfaRecoveryCodes {
  recovery_codes: string[]
  recovery_codes_remaining: number
}

export interface AuthClient {
  id: string
  org_id?: string | null
  name: string
  description?: string | null
  logo_url?: string | null
  homepage_url?: string | null
  privacy_policy_url?: string | null
  terms_url?: string | null
  publisher_name?: string | null
  verified: boolean
  verified_at?: string | null
  client_id: string
  public: boolean
  enabled: boolean
  redirect_uris: string[]
  allowed_origins: string[]
  audiences: string[]
  scopes: string[]
  require_org_membership: boolean
  require_mfa: boolean
  trusted_device_mfa_bypass: boolean
  session_idle_timeout_minutes?: number | null
  mcp_resource_uri?: string | null
  client_secret?: string
}

export interface AuthorizeContext {
  client: {
    id: string
    name: string
    description?: string | null
    logo_url?: string | null
    homepage_url?: string | null
    privacy_policy_url?: string | null
    terms_url?: string | null
    publisher_name?: string | null
    verified: boolean
    verified_at?: string | null
    client_id: string
    public: boolean
    allowed_origins: string[]
    audiences: string[]
    require_org_membership: boolean
    require_mfa: boolean
  }
  redirect_uri: string
  scopes: string[]
  audience?: string | null
  state?: string | null
  orgs: Org[]
  selected_org_id?: string | null
  code_challenge_method: string
}

export interface OAuthGrant {
  id: string
  auth_client_id: string
  client_id: string
  client_name: string
  user_id?: string | null
  user_email?: string | null
  org_id?: string | null
  audience?: string | null
  scopes: string[]
  last_authorized_at: string
  revoked_at?: string | null
  created_at: string
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
  org_id?: string | null
  user_id?: string | null
  project_id?: string | null
  client_id?: string | null
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
  auth_client_id?: string | null
  client_id?: string | null
  client_name?: string | null
  client_public?: boolean | null
  current: boolean
  ip_address?: string | null
  user_agent?: string | null
  device_label?: string | null
  amr: string[]
  trusted: boolean
  trusted_at?: string | null
  trusted_until?: string | null
  last_seen_at?: string | null
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

export interface AuditPruneResult {
  org_id: string
  retention_days: number
  cutoff_at: string
  pruned_count: number
  dry_run: boolean
}
