export interface GateKeeperConfig {
  issuer: string
  clientId?: string
  redirectUri?: string
  audience?: string
  scope?: string
  fetcher?: typeof fetch
}

export interface GateKeeperTokenResponse {
  access_token: string
  refresh_token?: string | null
  token_type: string
  expires_in: number
  scope: string
  user?: GateKeeperUser | null
  orgs?: GateKeeperOrg[]
}

export interface GateKeeperTokens {
  accessToken: string
  refreshToken?: string | null
  tokenType: string
  expiresAt: number
  scope: string
}

export type TokenResponse = GateKeeperTokenResponse
export type StoredTokens = GateKeeperTokens
export type GateKeeperEmailCodePurpose = 'login' | 'verify_email' | 'reset_password'

export interface GateKeeperSignupParams {
  email: string
  password: string
  displayName?: string | null
  display_name?: string | null
}

export interface GateKeeperLoginParams {
  email: string
  password: string
  clientId?: string | null
  client_id?: string | null
  scope?: string | null
  audience?: string | null
  totpCode?: string | null
  totp_code?: string | null
  recoveryCode?: string | null
  recovery_code?: string | null
}

export interface GateKeeperInvitationAcceptParams {
  email: string
  password: string
  token: string
  displayName?: string | null
  display_name?: string | null
  totpCode?: string | null
  totp_code?: string | null
  recoveryCode?: string | null
  recovery_code?: string | null
}

export interface GateKeeperEmailCodeRequestParams {
  email: string
  purpose?: GateKeeperEmailCodePurpose
}

export interface GateKeeperEmailCodeVerifyParams {
  email: string
  code: string
  purpose?: GateKeeperEmailCodePurpose
}

export interface GateKeeperPasswordResetConfirmParams {
  email: string
  code: string
  newPassword?: string
  new_password?: string
}

export interface GateKeeperPasswordChangeParams {
  currentPassword?: string
  current_password?: string
  newPassword?: string
  new_password?: string
  revokeOtherSessions?: boolean
  revoke_other_sessions?: boolean
}

export interface GateKeeperPasswordChangeResponse {
  status: string
  revoked_count: number
  current_session_kept: boolean
}

export interface GateKeeperUser {
  id: string
  email: string
  display_name?: string | null
  email_verified: boolean
}

export interface GateKeeperUserMembership {
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

export interface GateKeeperAdminUser extends GateKeeperUser {
  disabled: boolean
  created_at: string
  updated_at: string
  mfa_totp_enabled_at?: string | null
  memberships: GateKeeperUserMembership[]
}

export interface GateKeeperProfileUpdateParams {
  displayName?: string | null
  display_name?: string | null
}

export interface GateKeeperOrg {
  id: string
  name: string
  slug: string
  require_mfa?: boolean
  trusted_device_mfa_bypass?: boolean
  admin_step_up_mfa_required?: boolean
  session_idle_timeout_minutes?: number | null
  audit_retention_days?: number | null
  allow_user_hard_delete?: boolean
  role?: string | null
  permissions: string[]
}

export interface GateKeeperMe {
  subject: string
  auth_type: string
  scopes: string[]
  org_id?: string | null
  user?: GateKeeperUser | null
}

export interface GateKeeperEmailChangeResponse {
  status: string
  email: string
  revoked_count: number
  current_session_kept: boolean
}

export interface GateKeeperLinkedIdentity {
  id: string
  provider: string
  email?: string | null
  created_at: string
  updated_at: string
}

export interface GateKeeperOAuthProvider {
  id: string
  name: string
  configured: boolean
  scopes: string[]
  start_url: string
  authorization_url: string
  require_verified_email: boolean
  allow_email_linking: boolean
}

export interface GateKeeperOAuthStartResponse {
  provider: string
  state: string
  authorization_url: string
}

export interface GateKeeperOAuthProviderAdmin {
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

export interface GateKeeperOAuthProviderCreate {
  providerId: string
  name: string
  enabled?: boolean
  clientId?: string
  clientSecret?: string | null
  authorizationUrl: string
  tokenUrl: string
  userinfoUrl: string
  redirectUri?: string
  scopes?: string[]
  subjectClaim?: string
  emailClaim?: string
  nameClaim?: string
  emailVerifiedClaim?: string
  allowEmailLinking?: boolean
  requireVerifiedEmail?: boolean
}

export interface GateKeeperOAuthProviderUpdate {
  name?: string
  enabled?: boolean
  clientId?: string
  clientSecret?: string | null
  authorizationUrl?: string
  tokenUrl?: string
  userinfoUrl?: string
  redirectUri?: string | null
  scopes?: string[]
  subjectClaim?: string
  emailClaim?: string
  nameClaim?: string
  emailVerifiedClaim?: string
  allowEmailLinking?: boolean
  requireVerifiedEmail?: boolean
}

export interface GateKeeperAccountExport {
  exported_at: string
  user: GateKeeperUser
  memberships: GateKeeperOrg[]
  mfa: {
    totp_enabled: boolean
    totp_enabled_at?: string | null
    recovery_codes_remaining: number
  }
  sessions: GateKeeperSession[]
  api_tokens: unknown[]
  oauth_grants: GateKeeperOAuthGrant[]
  identities: Array<{
    id: string
    provider: string
    email?: string | null
    created_at: string
  }>
  recent_audit_events: unknown[]
}

export interface GateKeeperAccountDeactivateResponse {
  status: string
  revoked_sessions: number
  revoked_tokens: number
  revoked_grants: number
}

export interface GateKeeperUserDeleteResponse {
  status: string
  dry_run: boolean
  user_id: string
  email: string
  counts: Record<string, number>
  policy_org_ids: string[]
}

export interface GateKeeperUserProvisionParams {
  orgId?: string
  org_id?: string
  email: string
  displayName?: string | null
  display_name?: string | null
  emailVerified?: boolean | null
  email_verified?: boolean | null
  disabled?: boolean | null
  roleId?: string | null
  role_id?: string | null
  role?: string | null
  status?: 'active' | 'suspended' | 'revoked'
}

export interface GateKeeperUserProvisionResponse {
  status: 'created' | 'updated'
  created_user: boolean
  created_membership: boolean
  revoked_sessions: number
  user: GateKeeperAdminUser
}

export interface GateKeeperSession {
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

export interface GateKeeperOAuthGrant {
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

export interface GateKeeperOAuthGrantAdminListOptions {
  orgId?: string
  clientId?: string
  userId?: string
  includeRevoked?: boolean
}

export interface GateKeeperApiTokenValidateParams {
  token: string
  audience?: string | null
  requiredScopes?: string[]
  orgId?: string | null
  projectId?: string | null
}

export interface GateKeeperApiTokenValidation {
  active: boolean
  reason?: string | null
  token_id?: string | null
  token_type?: string | null
  token_hint?: string | null
  org_id?: string | null
  org_name?: string | null
  org_slug?: string | null
  user_id?: string | null
  user_email?: string | null
  user_display_name?: string | null
  project_id?: string | null
  project_name?: string | null
  project_audience?: string | null
  auth_client_id?: string | null
  scopes: string[]
  audiences: string[]
  missing_scopes: string[]
  audience_ok: boolean
  scope_ok: boolean
  expires_at?: string | null
  last_used_at?: string | null
}

export interface GateKeeperApiToken {
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

export interface GateKeeperApiTokenCreate {
  name: string
  tokenType?: string
  token_type?: string
  scopes?: string[]
  audiences?: string[]
  orgId?: string | null
  org_id?: string | null
  projectId?: string | null
  project_id?: string | null
  clientId?: string | null
  client_id?: string | null
  expiresAt?: string | null
  expires_at?: string | null
}

export interface ProtectedResourceMetadata {
  resource: string
  authorization_servers: string[]
  scopes_supported: string[]
}

export interface GateKeeperJwtClaims {
  iss: string
  sub: string
  aud?: string | string[]
  exp: number
  iat?: number
  nbf?: number
  azp?: string | null
  scope?: string
  token_type?: string
  email?: string | null
  display_name?: string | null
  email_verified?: boolean
  mfa_totp_enabled?: boolean
  org_id?: string | null
  org_slug?: string | null
  org_role?: string | null
  permissions?: string[]
  amr?: string[]
  [claim: string]: unknown
}

export interface GateKeeperPrincipal {
  subject: string
  scopes: string[]
  audience: string[]
  claims: GateKeeperJwtClaims
  orgId?: string | null
  orgSlug?: string | null
  orgRole?: string | null
  email?: string | null
  displayName?: string | null
  emailVerified?: boolean
  mfaTotpEnabled?: boolean
  permissions: string[]
  amr: string[]
  authorizedParty?: string | null
}

export interface GateKeeperJwk extends JsonWebKey {
  kid?: string
}

export interface GateKeeperJwks {
  keys: GateKeeperJwk[]
}

export interface GateKeeperJwtVerifierConfig {
  issuer: string
  audience?: string | string[]
  requiredScopes?: string[]
  cacheSeconds?: number
  fetcher?: typeof fetch
  jwks?: GateKeeperJwks
}

export interface GateKeeperJwtVerifyOptions {
  audience?: string | string[]
  requiredScopes?: string[]
  now?: Date | number
  leewaySeconds?: number
}

export interface AuthorizationUrlParams {
  codeChallenge: string
  codeChallengeMethod?: 'S256' | 'plain'
  scope?: string
  state?: string
  audience?: string
  orgId?: string
  clientId?: string
  redirectUri?: string
}

export interface AuthorizationStartParams extends Omit<AuthorizationUrlParams, 'codeChallenge' | 'codeChallengeMethod'> {
  codeVerifier?: string
}

export interface AuthorizationStart {
  url: string
  codeVerifier: string
  state: string
}

export interface ExchangeCodeParams {
  code: string
  codeVerifier: string
  clientId?: string
  redirectUri?: string
}

export interface ClientCredentialsParams {
  clientSecret: string
  clientId?: string
  scope?: string
  audience?: string
}

export interface SwitchOrgParams {
  orgId: string
  clientId?: string
  scope?: string
  audience?: string
  revokeCurrentSession?: boolean
}

export interface TokenStore {
  load(): GateKeeperTokens | null
  save(response: GateKeeperTokenResponse): GateKeeperTokens
  clear(): void
}

function defaultFetch() {
  if (!globalThis.fetch) {
    throw new Error('GateKeeperClient requires fetch or a configured fetcher')
  }
  return globalThis.fetch.bind(globalThis)
}

function browserCrypto() {
  if (!globalThis.crypto?.getRandomValues || !globalThis.crypto?.subtle) {
    throw new Error('PKCE generation requires Web Crypto')
  }
  return globalThis.crypto
}

function base64Url(bytes: Uint8Array) {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  if (!globalThis.btoa) {
    throw new Error('Base64url encoding requires btoa')
  }
  return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function randomString(byteLength = 32) {
  const bytes = new Uint8Array(byteLength)
  browserCrypto().getRandomValues(bytes)
  return base64Url(bytes)
}

export async function createPkceChallenge(codeVerifier = randomString(32)) {
  const digest = await browserCrypto().subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
  return {
    codeVerifier,
    codeChallenge: base64Url(new Uint8Array(digest)),
    codeChallengeMethod: 'S256' as const,
  }
}

export const createPkcePair = createPkceChallenge

export function tokenResponseToStoredTokens(
  response: GateKeeperTokenResponse,
  now = Date.now(),
): GateKeeperTokens {
  return {
    accessToken: response.access_token,
    refreshToken: response.refresh_token || null,
    tokenType: response.token_type || 'Bearer',
    expiresAt: now + response.expires_in * 1000,
    scope: response.scope || '',
  }
}

function normalizeIssuer(issuer: string) {
  return issuer.replace(/\/$/, '')
}

function normalizeList(value?: string | string[] | null) {
  if (!value) {
    return []
  }
  return Array.isArray(value) ? value : [value]
}

function tokenHeaders(accessToken?: string | null) {
  const headers = new Headers()
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`)
  }
  return headers
}

function oauthProviderCreateBody(params: GateKeeperOAuthProviderCreate) {
  return {
    provider_id: params.providerId,
    name: params.name,
    enabled: params.enabled ?? true,
    client_id: params.clientId ?? '',
    client_secret: params.clientSecret ?? null,
    authorization_url: params.authorizationUrl,
    token_url: params.tokenUrl,
    userinfo_url: params.userinfoUrl,
    redirect_uri: params.redirectUri ?? '',
    scopes: params.scopes ?? ['openid', 'email', 'profile'],
    subject_claim: params.subjectClaim ?? 'sub',
    email_claim: params.emailClaim ?? 'email',
    name_claim: params.nameClaim ?? 'name',
    email_verified_claim: params.emailVerifiedClaim ?? 'email_verified',
    allow_email_linking: params.allowEmailLinking ?? true,
    require_verified_email: params.requireVerifiedEmail ?? true,
  }
}

function oauthProviderUpdateBody(params: GateKeeperOAuthProviderUpdate) {
  const body: Record<string, unknown> = {}
  if ('name' in params) body.name = params.name
  if ('enabled' in params) body.enabled = params.enabled
  if ('clientId' in params) body.client_id = params.clientId
  if ('clientSecret' in params) body.client_secret = params.clientSecret ?? null
  if ('authorizationUrl' in params) body.authorization_url = params.authorizationUrl
  if ('tokenUrl' in params) body.token_url = params.tokenUrl
  if ('userinfoUrl' in params) body.userinfo_url = params.userinfoUrl
  if ('redirectUri' in params) body.redirect_uri = params.redirectUri ?? ''
  if ('scopes' in params) body.scopes = params.scopes
  if ('subjectClaim' in params) body.subject_claim = params.subjectClaim
  if ('emailClaim' in params) body.email_claim = params.emailClaim
  if ('nameClaim' in params) body.name_claim = params.nameClaim
  if ('emailVerifiedClaim' in params) body.email_verified_claim = params.emailVerifiedClaim
  if ('allowEmailLinking' in params) body.allow_email_linking = params.allowEmailLinking
  if ('requireVerifiedEmail' in params) body.require_verified_email = params.requireVerifiedEmail
  return body
}

async function parseJsonResponse<T>(response: Response, fallback: string): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const detail = typeof body?.detail === 'string' ? body.detail : fallback
    throw new Error(detail)
  }
  return response.json() as Promise<T>
}

function base64UrlToBytes(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  if (!globalThis.atob) {
    throw new Error('JWT decoding requires atob')
  }
  const binary = globalThis.atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

function decodeJwtSegment<T>(value: string): T {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value))) as T
}

function nowSeconds(value?: Date | number) {
  if (value instanceof Date) {
    return Math.floor(value.getTime() / 1000)
  }
  if (typeof value === 'number') {
    return value > 10_000_000_000 ? Math.floor(value / 1000) : Math.floor(value)
  }
  return Math.floor(Date.now() / 1000)
}

function jwtAudiences(claims: GateKeeperJwtClaims) {
  return normalizeList(claims.aud)
}

function stringListClaim(value: unknown) {
  return Array.isArray(value) ? value.map((item) => String(item)) : []
}

function scopesFromClaims(claims: GateKeeperJwtClaims) {
  return String(claims.scope || '')
    .split(/\s+/)
    .filter((scope) => scope.length > 0)
}

function assertRequiredScopes(scopes: string[], requiredScopes: string[]) {
  if (!requiredScopes.length || scopes.includes('*')) {
    return
  }
  const missing = requiredScopes.filter((scope) => !scopes.includes(scope))
  if (missing.length) {
    throw new Error(`GateKeeper token is missing required scopes: ${missing.join(', ')}`)
  }
}

function authorizationHeaderToken(header?: string | null) {
  if (!header) {
    return null
  }
  const [scheme, token] = header.trim().split(/\s+/, 2)
  return scheme?.toLowerCase() === 'bearer' && token ? token : null
}

export function bearerTokenFromAuthorizationHeader(header?: string | null) {
  return authorizationHeaderToken(header)
}

export class BrowserTokenStore implements TokenStore {
  private key: string

  constructor(key = 'gatekeeper.tokens') {
    this.key = key
  }

  load(): GateKeeperTokens | null {
    if (!globalThis.localStorage) {
      return null
    }
    const raw = globalThis.localStorage.getItem(this.key)
    if (!raw) {
      return null
    }
    try {
      return JSON.parse(raw) as GateKeeperTokens
    } catch {
      this.clear()
      return null
    }
  }

  save(response: GateKeeperTokenResponse): GateKeeperTokens {
    if (!globalThis.localStorage) {
      throw new Error('BrowserTokenStore requires localStorage')
    }
    const tokens = tokenResponseToStoredTokens(response)
    globalThis.localStorage.setItem(this.key, JSON.stringify(tokens))
    return tokens
  }

  clear() {
    if (globalThis.localStorage) {
      globalThis.localStorage.removeItem(this.key)
    }
  }
}

export class GateKeeperJwtVerifier {
  private issuer: string
  private audience: string[]
  private requiredScopes: string[]
  private cacheSeconds: number
  private fetcher: typeof fetch
  private cachedJwks?: GateKeeperJwks
  private expiresAt = 0

  constructor(config: GateKeeperJwtVerifierConfig) {
    this.issuer = normalizeIssuer(config.issuer)
    this.audience = normalizeList(config.audience)
    this.requiredScopes = config.requiredScopes || []
    this.cacheSeconds = config.cacheSeconds ?? 3600
    this.fetcher = config.fetcher || defaultFetch()
    this.cachedJwks = config.jwks
    this.expiresAt = config.jwks ? Number.POSITIVE_INFINITY : 0
  }

  clearCache() {
    this.cachedJwks = undefined
    this.expiresAt = 0
  }

  async jwks() {
    if (this.cachedJwks && this.expiresAt > Date.now()) {
      return this.cachedJwks
    }
    const response = await this.fetcher(`${this.issuer}/oauth/jwks.json`)
    this.cachedJwks = await parseJsonResponse<GateKeeperJwks>(response, 'Could not load GateKeeper JWKS')
    this.expiresAt = Date.now() + this.cacheSeconds * 1000
    return this.cachedJwks
  }

  async verify(token: string, options: GateKeeperJwtVerifyOptions = {}): Promise<GateKeeperPrincipal> {
    const parts = token.split('.')
    if (parts.length !== 3) {
      throw new Error('GateKeeper token must be a JWT')
    }

    const header = decodeJwtSegment<{ alg?: string; kid?: string }>(parts[0])
    if (header.alg !== 'RS256') {
      throw new Error('GateKeeper token must use RS256')
    }
    if (!header.kid) {
      throw new Error('GateKeeper token is missing a signing key id')
    }

    let jwks = await this.jwks()
    let jwk = jwks.keys.find((item) => item.kid === header.kid)
    if (!jwk) {
      this.clearCache()
      jwks = await this.jwks()
      jwk = jwks.keys.find((item) => item.kid === header.kid)
    }
    if (!jwk) {
      throw new Error('Unknown GateKeeper signing key')
    }

    const key = await globalThis.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    )
    const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    const signature = base64UrlToBytes(parts[2])
    const valid = await globalThis.crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signed)
    if (!valid) {
      throw new Error('Invalid GateKeeper token signature')
    }

    const claims = decodeJwtSegment<GateKeeperJwtClaims>(parts[1])
    const clock = nowSeconds(options.now)
    const leeway = options.leewaySeconds ?? 0
    if (claims.iss !== this.issuer) {
      throw new Error('GateKeeper token issuer did not match')
    }
    if (typeof claims.exp !== 'number' || claims.exp <= clock - leeway) {
      throw new Error('GateKeeper token is expired')
    }
    if (typeof claims.nbf === 'number' && claims.nbf > clock + leeway) {
      throw new Error('GateKeeper token is not active yet')
    }

    const expectedAudiences = normalizeList(options.audience).length ? normalizeList(options.audience) : this.audience
    const audiences = jwtAudiences(claims)
    if (expectedAudiences.length && !expectedAudiences.some((audience) => audiences.includes(audience))) {
      throw new Error('GateKeeper token audience did not match')
    }

    const scopes = scopesFromClaims(claims)
    const requiredScopes = options.requiredScopes || this.requiredScopes
    assertRequiredScopes(scopes, requiredScopes)

    return {
      subject: String(claims.sub || ''),
      scopes,
      audience: audiences,
      claims,
      orgId: claims.org_id,
      orgSlug: claims.org_slug,
      orgRole: claims.org_role,
      email: claims.email,
      displayName: claims.display_name,
      emailVerified: claims.email_verified,
      mfaTotpEnabled: claims.mfa_totp_enabled,
      permissions: stringListClaim(claims.permissions),
      amr: stringListClaim(claims.amr),
      authorizedParty: claims.azp,
    }
  }

  async verifyAuthorizationHeader(
    header?: string | null,
    options: GateKeeperJwtVerifyOptions = {},
  ): Promise<GateKeeperPrincipal> {
    const token = authorizationHeaderToken(header)
    if (!token) {
      throw new Error('Bearer token required')
    }
    return this.verify(token, options)
  }
}

export function createGateKeeperVerifier(config: GateKeeperJwtVerifierConfig) {
  return new GateKeeperJwtVerifier(config)
}

export class GateKeeperClient {
  private issuer: string
  private clientId?: string
  private redirectUri?: string
  private audience?: string
  private scope?: string
  private fetcher: typeof fetch

  constructor(config: GateKeeperConfig) {
    this.issuer = normalizeIssuer(config.issuer)
    this.clientId = config.clientId
    this.redirectUri = config.redirectUri
    this.audience = config.audience
    this.scope = config.scope
    this.fetcher = config.fetcher || defaultFetch()
  }

  verifier(options: Omit<GateKeeperJwtVerifierConfig, 'issuer' | 'fetcher'> = {}) {
    return new GateKeeperJwtVerifier({
      issuer: this.issuer,
      audience: options.audience || this.audience,
      requiredScopes: options.requiredScopes,
      cacheSeconds: options.cacheSeconds,
      fetcher: this.fetcher,
      jwks: options.jwks,
    })
  }

  authorizationUrl(params: AuthorizationUrlParams) {
    const clientId = params.clientId || this.clientId
    const redirectUri = params.redirectUri || this.redirectUri
    if (!clientId || !redirectUri) {
      throw new Error('clientId and redirectUri are required')
    }
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: params.codeChallenge,
      code_challenge_method: params.codeChallengeMethod || 'S256',
      scope: params.scope || this.scope || 'openid profile email',
    })
    const audience = params.audience || this.audience
    if (params.state) query.set('state', params.state)
    if (audience) query.set('audience', audience)
    if (params.orgId) query.set('org_id', params.orgId)
    return `${this.issuer}/oauth/authorize?${query.toString()}`
  }

  async startAuthorization(params: AuthorizationStartParams = {}): Promise<AuthorizationStart> {
    const pkce = await createPkceChallenge(params.codeVerifier)
    const state = params.state || randomString(24)
    return {
      url: this.authorizationUrl({
        ...params,
        state,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: pkce.codeChallengeMethod,
      }),
      codeVerifier: pkce.codeVerifier,
      state,
    }
  }

  async signup(params: GateKeeperSignupParams): Promise<GateKeeperTokenResponse> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/signup`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        password: params.password,
        display_name: params.display_name ?? params.displayName ?? null,
      }),
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not sign up with GateKeeper')
  }

  async login(params: GateKeeperLoginParams): Promise<GateKeeperTokenResponse> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/login`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        password: params.password,
        client_id: params.client_id ?? params.clientId ?? this.clientId ?? null,
        scope: params.scope ?? this.scope ?? null,
        audience: params.audience ?? this.audience ?? null,
        totp_code: params.totp_code ?? params.totpCode ?? null,
        recovery_code: params.recovery_code ?? params.recoveryCode ?? null,
      }),
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not sign in with GateKeeper')
  }

  async acceptInvitation(params: GateKeeperInvitationAcceptParams): Promise<GateKeeperTokenResponse> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/invitations/accept`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        password: params.password,
        token: params.token,
        display_name: params.display_name ?? params.displayName ?? null,
        totp_code: params.totp_code ?? params.totpCode ?? null,
        recovery_code: params.recovery_code ?? params.recoveryCode ?? null,
      }),
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not accept GateKeeper invitation')
  }

  async requestEmailCode(params: GateKeeperEmailCodeRequestParams): Promise<{ status: string }> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/email-code/request`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        purpose: params.purpose || 'login',
      }),
    })
    return parseJsonResponse(response, 'Could not request GateKeeper email code')
  }

  async verifyEmailCode(params: GateKeeperEmailCodeVerifyParams): Promise<GateKeeperTokenResponse> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/email-code/verify`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        code: params.code,
        purpose: params.purpose || 'login',
      }),
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not verify GateKeeper email code')
  }

  async requestPasswordReset(params: GateKeeperEmailCodeRequestParams): Promise<{ status: string }> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/password/reset/request`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        purpose: params.purpose || 'reset_password',
      }),
    })
    return parseJsonResponse(response, 'Could not request GateKeeper password reset')
  }

  async confirmPasswordReset(params: GateKeeperPasswordResetConfirmParams): Promise<{ status: string }> {
    const newPassword = params.new_password ?? params.newPassword
    if (!newPassword) {
      throw new Error('newPassword is required')
    }
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/password/reset/confirm`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        email: params.email,
        code: params.code,
        new_password: newPassword,
      }),
    })
    return parseJsonResponse(response, 'Could not confirm GateKeeper password reset')
  }

  async exchangeCode(params: ExchangeCodeParams): Promise<GateKeeperTokenResponse> {
    const clientId = params.clientId || this.clientId
    const redirectUri = params.redirectUri || this.redirectUri
    if (!clientId || !redirectUri) {
      throw new Error('clientId and redirectUri are required')
    }
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      redirect_uri: redirectUri,
      code: params.code,
      code_verifier: params.codeVerifier,
    })
    const response = await this.fetcher(`${this.issuer}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not exchange authorization code')
  }

  async refresh(refreshToken: string, clientId = this.clientId): Promise<GateKeeperTokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    })
    if (clientId) {
      body.set('client_id', clientId)
    }
    const response = await this.fetcher(`${this.issuer}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not refresh GateKeeper token')
  }

  async clientCredentialsToken(params: ClientCredentialsParams): Promise<GateKeeperTokenResponse> {
    const clientId = params.clientId || this.clientId
    if (!clientId) {
      throw new Error('clientId is required')
    }
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: params.clientSecret,
      scope: params.scope || this.scope || '',
    })
    const audience = params.audience || this.audience
    if (audience) {
      body.set('audience', audience)
    }
    const response = await this.fetcher(`${this.issuer}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not create client credentials token')
  }

  async validateApiToken(params: GateKeeperApiTokenValidateParams): Promise<GateKeeperApiTokenValidation> {
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/tokens/validate`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        token: params.token,
        audience: params.audience || null,
        required_scopes: params.requiredScopes || [],
        org_id: params.orgId || null,
        project_id: params.projectId || null,
      }),
    })
    return parseJsonResponse<GateKeeperApiTokenValidation>(response, 'Could not validate GateKeeper API token')
  }

  async apiTokens(accessToken: string): Promise<GateKeeperApiToken[]> {
    const response = await this.fetcher(`${this.issuer}/api/v1/tokens`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperApiToken[]>(response, 'Could not load GateKeeper API tokens')
  }

  async createApiToken(accessToken: string, params: GateKeeperApiTokenCreate): Promise<GateKeeperApiToken> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/tokens`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        name: params.name,
        token_type: params.token_type || params.tokenType || 'personal',
        scopes: params.scopes || [],
        audiences: params.audiences || [],
        org_id: params.org_id ?? params.orgId ?? null,
        project_id: params.project_id ?? params.projectId ?? null,
        client_id: params.client_id ?? params.clientId ?? null,
        expires_at: params.expires_at ?? params.expiresAt ?? null,
      }),
    })
    return parseJsonResponse<GateKeeperApiToken>(response, 'Could not create GateKeeper API token')
  }

  async rotateApiToken(accessToken: string, tokenId: string): Promise<GateKeeperApiToken> {
    const response = await this.fetcher(`${this.issuer}/api/v1/tokens/${tokenId}/rotate`, {
      method: 'POST',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperApiToken>(response, 'Could not rotate GateKeeper API token')
  }

  async revokeApiToken(accessToken: string, tokenId: string): Promise<{ status: string; id: string }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/tokens/${tokenId}`, {
      method: 'DELETE',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not revoke GateKeeper API token')
  }

  async logout(accessToken?: string | null): Promise<{ status: string; session_revoked?: boolean }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/logout`, {
      method: 'POST',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not log out')
  }

  async protectedResource(path = ''): Promise<ProtectedResourceMetadata> {
    const suffix = path ? `/${path.replace(/^\//, '')}` : ''
    const response = await this.fetcher(`${this.issuer}/.well-known/oauth-protected-resource${suffix}`)
    return parseJsonResponse<ProtectedResourceMetadata>(response, 'Could not load protected-resource metadata')
  }

  async me(accessToken: string): Promise<GateKeeperMe> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/me`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperMe>(response, 'GateKeeper session is invalid')
  }

  async updateMe(accessToken: string, params: GateKeeperProfileUpdateParams): Promise<GateKeeperUser> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/me`, {
      method: 'PATCH',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        display_name: params.display_name ?? params.displayName ?? null,
      }),
    })
    return parseJsonResponse<GateKeeperUser>(response, 'Could not update GateKeeper profile')
  }

  async changePassword(
    accessToken: string,
    params: GateKeeperPasswordChangeParams,
  ): Promise<GateKeeperPasswordChangeResponse> {
    const currentPassword = params.current_password ?? params.currentPassword
    const newPassword = params.new_password ?? params.newPassword
    if (!currentPassword || !newPassword) {
      throw new Error('currentPassword and newPassword are required')
    }
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/password/change`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
        revoke_other_sessions: params.revoke_other_sessions ?? params.revokeOtherSessions ?? true,
      }),
    })
    return parseJsonResponse<GateKeeperPasswordChangeResponse>(response, 'Could not change GateKeeper password')
  }

  async switchOrg(accessToken: string, params: SwitchOrgParams): Promise<GateKeeperTokenResponse> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/session/switch-org`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        org_id: params.orgId,
        client_id: params.clientId || null,
        scope: params.scope || null,
        audience: params.audience || null,
        revoke_current_session: params.revokeCurrentSession ?? false,
      }),
    })
    return parseJsonResponse<GateKeeperTokenResponse>(response, 'Could not switch GateKeeper organization')
  }

  async requestEmailChange(
    accessToken: string,
    params: { newEmail: string; currentPassword?: string | null },
  ): Promise<{ status: string }> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/email/change/request`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        new_email: params.newEmail,
        current_password: params.currentPassword || null,
      }),
    })
    return parseJsonResponse(response, 'Could not request GateKeeper email change')
  }

  async confirmEmailChange(
    accessToken: string,
    params: { newEmail: string; code: string; revokeOtherSessions?: boolean },
  ): Promise<GateKeeperEmailChangeResponse> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/email/change/confirm`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        new_email: params.newEmail,
        code: params.code,
        revoke_other_sessions: params.revokeOtherSessions ?? true,
      }),
    })
    return parseJsonResponse<GateKeeperEmailChangeResponse>(response, 'Could not confirm GateKeeper email change')
  }

  async linkedIdentities(accessToken: string): Promise<GateKeeperLinkedIdentity[]> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/identities`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperLinkedIdentity[]>(response, 'Could not load GateKeeper linked identities')
  }

  async unlinkIdentity(accessToken: string, identityId: string): Promise<{ status: string; id: string }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/identities/${identityId}`, {
      method: 'DELETE',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not unlink GateKeeper identity')
  }

  async oauthProviders(): Promise<GateKeeperOAuthProvider[]> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/oauth/providers`, {
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperOAuthProvider[]>(response, 'Could not load GateKeeper OAuth providers')
  }

  async startOAuthProvider(
    providerId: string,
    params: { redirect?: string | null } = {},
  ): Promise<GateKeeperOAuthStartResponse> {
    const query = new URLSearchParams()
    if (params.redirect) {
      query.set('redirect', params.redirect)
    }
    const suffix = query.toString() ? `?${query.toString()}` : ''
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/oauth/${providerId}/start${suffix}`, {
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not start GateKeeper OAuth provider')
  }

  async startIdentityLink(
    accessToken: string,
    providerId: string,
    params: { redirect?: string | null } = {},
  ): Promise<GateKeeperOAuthStartResponse> {
    const query = new URLSearchParams()
    if (params.redirect) {
      query.set('redirect', params.redirect)
    }
    const suffix = query.toString() ? `?${query.toString()}` : ''
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/identities/${providerId}/link/start${suffix}`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not start GateKeeper identity link')
  }

  async oauthProvidersAdmin(accessToken: string): Promise<GateKeeperOAuthProviderAdmin[]> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/oauth/providers/admin`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperOAuthProviderAdmin[]>(
      response,
      'Could not load GateKeeper admin OAuth providers',
    )
  }

  async createOAuthProvider(
    accessToken: string,
    params: GateKeeperOAuthProviderCreate,
  ): Promise<GateKeeperOAuthProviderAdmin> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/oauth/providers/admin`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify(oauthProviderCreateBody(params)),
    })
    return parseJsonResponse<GateKeeperOAuthProviderAdmin>(response, 'Could not create GateKeeper OAuth provider')
  }

  async updateOAuthProvider(
    accessToken: string,
    providerId: string,
    params: GateKeeperOAuthProviderUpdate,
  ): Promise<GateKeeperOAuthProviderAdmin> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/oauth/providers/admin/${providerId}`, {
      method: 'PATCH',
      headers,
      credentials: 'include',
      body: JSON.stringify(oauthProviderUpdateBody(params)),
    })
    return parseJsonResponse<GateKeeperOAuthProviderAdmin>(response, 'Could not update GateKeeper OAuth provider')
  }

  async deleteOAuthProvider(accessToken: string, providerId: string): Promise<{ status: string; id: string }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/oauth/providers/admin/${providerId}`, {
      method: 'DELETE',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not delete GateKeeper OAuth provider')
  }

  async exportAccount(accessToken: string): Promise<GateKeeperAccountExport> {
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/account/export`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperAccountExport>(response, 'Could not export GateKeeper account')
  }

  async deactivateAccount(
    accessToken: string,
    params: { currentPassword?: string | null; totpCode?: string | null; recoveryCode?: string | null } = {},
  ): Promise<GateKeeperAccountDeactivateResponse> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/auth/account/deactivate`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        current_password: params.currentPassword || null,
        totp_code: params.totpCode || null,
        recovery_code: params.recoveryCode || null,
      }),
    })
    return parseJsonResponse<GateKeeperAccountDeactivateResponse>(response, 'Could not deactivate GateKeeper account')
  }

  async deleteUser(
    accessToken: string,
    userId: string,
    params: { dryRun?: boolean; confirmEmail?: string | null } = {},
  ): Promise<GateKeeperUserDeleteResponse> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/users/${userId}/delete`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        dry_run: params.dryRun ?? true,
        confirm_email: params.confirmEmail || null,
      }),
    })
    return parseJsonResponse<GateKeeperUserDeleteResponse>(response, 'Could not delete GateKeeper user')
  }

  async provisionUser(
    accessToken: string,
    params: GateKeeperUserProvisionParams,
  ): Promise<GateKeeperUserProvisionResponse> {
    const orgId = params.org_id ?? params.orgId
    if (!orgId) {
      throw new Error('orgId is required')
    }
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/users/provision`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({
        org_id: orgId,
        email: params.email,
        display_name: params.display_name ?? params.displayName ?? null,
        email_verified: params.email_verified ?? params.emailVerified ?? null,
        disabled: params.disabled ?? null,
        role_id: params.role_id ?? params.roleId ?? null,
        role: params.role ?? null,
        status: params.status || 'active',
      }),
    })
    return parseJsonResponse<GateKeeperUserProvisionResponse>(response, 'Could not provision GateKeeper user')
  }

  async sessions(accessToken: string): Promise<GateKeeperSession[]> {
    const response = await this.fetcher(`${this.issuer}/api/v1/sessions`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperSession[]>(response, 'Could not load GateKeeper sessions')
  }

  async revokeSession(accessToken: string, sessionId: string): Promise<{ status: string; id: string }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/sessions/${sessionId}`, {
      method: 'DELETE',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not revoke GateKeeper session')
  }

  async updateSessionDevice(
    accessToken: string,
    sessionId: string,
    params: { deviceLabel?: string | null; trusted?: boolean; trustedUntil?: string | null },
  ): Promise<GateKeeperSession> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const body: Record<string, string | boolean | null> = {}
    if ('deviceLabel' in params) {
      body.device_label = params.deviceLabel ?? null
    }
    if ('trusted' in params) {
      body.trusted = params.trusted ?? null
    }
    if ('trustedUntil' in params) {
      body.trusted_until = params.trustedUntil ?? null
    }
    const response = await this.fetcher(`${this.issuer}/api/v1/sessions/${sessionId}/device`, {
      method: 'PATCH',
      headers,
      credentials: 'include',
      body: JSON.stringify(body),
    })
    return parseJsonResponse<GateKeeperSession>(response, 'Could not update GateKeeper session device')
  }

  async revokeAllSessions(
    accessToken: string,
    includeCurrent = true,
  ): Promise<{ status: string; revoked_count: number; include_current: boolean }> {
    const headers = tokenHeaders(accessToken)
    headers.set('Content-Type', 'application/json')
    const response = await this.fetcher(`${this.issuer}/api/v1/sessions/revoke-all`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ include_current: includeCurrent }),
    })
    return parseJsonResponse(response, 'Could not revoke GateKeeper sessions')
  }

  async grants(accessToken: string): Promise<GateKeeperOAuthGrant[]> {
    const response = await this.fetcher(`${this.issuer}/api/v1/oauth/grants`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperOAuthGrant[]>(response, 'Could not load GateKeeper OAuth grants')
  }

  async revokeGrant(accessToken: string, grantId: string): Promise<{ status: string; id: string }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/oauth/grants/${grantId}`, {
      method: 'DELETE',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not revoke GateKeeper OAuth grant')
  }

  async grantsAdmin(
    accessToken: string,
    params: GateKeeperOAuthGrantAdminListOptions = {},
  ): Promise<GateKeeperOAuthGrant[]> {
    const query = new URLSearchParams()
    if (params.orgId) query.set('org_id', params.orgId)
    if (params.clientId) query.set('client_id', params.clientId)
    if (params.userId) query.set('user_id', params.userId)
    if (params.includeRevoked) query.set('include_revoked', 'true')
    const suffix = query.toString() ? `?${query}` : ''
    const response = await this.fetcher(`${this.issuer}/api/v1/oauth/grants/admin${suffix}`, {
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse<GateKeeperOAuthGrant[]>(response, 'Could not load GateKeeper admin OAuth grants')
  }

  async revokeGrantAdmin(accessToken: string, grantId: string): Promise<{ status: string; id: string }> {
    const response = await this.fetcher(`${this.issuer}/api/v1/oauth/grants/admin/${grantId}`, {
      method: 'DELETE',
      headers: tokenHeaders(accessToken),
      credentials: 'include',
    })
    return parseJsonResponse(response, 'Could not revoke GateKeeper admin OAuth grant')
  }
}
