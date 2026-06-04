import { computed, defineComponent, h, inject, onMounted, provide, ref, type App, type InjectionKey, type PropType } from 'vue'

import {
  BrowserTokenStore,
  GateKeeperClient,
  type GateKeeperApiToken,
  type GateKeeperApiTokenCreate,
  type AuthorizationStartParams,
  type GateKeeperAccountDeactivateResponse,
  type GateKeeperAccountExport,
  type GateKeeperConfig,
  type GateKeeperEmailChangeResponse,
  type GateKeeperEmailCodeRequestParams,
  type GateKeeperEmailCodeVerifyParams,
  type GateKeeperInvitationAcceptParams,
  type GateKeeperLinkedIdentity,
  type GateKeeperLoginParams,
  type GateKeeperMe,
  type GateKeeperOAuthGrant,
  type GateKeeperOAuthGrantAdminListOptions,
  type GateKeeperOAuthProviderAdmin,
  type GateKeeperOAuthProviderCreate,
  type GateKeeperOAuthProvider,
  type GateKeeperOAuthProviderUpdate,
  type GateKeeperOrg,
  type GateKeeperPasswordChangeParams,
  type GateKeeperPasswordChangeResponse,
  type GateKeeperPasswordResetConfirmParams,
  type GateKeeperProfileUpdateParams,
  type GateKeeperSession,
  type GateKeeperSignupParams,
  type GateKeeperTokenResponse,
  type GateKeeperTokens,
  type GateKeeperUser,
  type SwitchOrgParams,
  type TokenStore,
} from 'gatekeeper-js'

export interface GateKeeperPluginOptions {
  tokenStore?: TokenStore
  tokenStoreKey?: string
}

export interface GateKeeperNuxtPublicRuntimeConfig {
  gatekeeperIssuer?: string
  gatekeeperClientId?: string
  gatekeeperRedirectUri?: string
  gatekeeperAudience?: string
  gatekeeperScopes?: string
}

export interface GateKeeperNuxtRuntimeConfig {
  public?: GateKeeperNuxtPublicRuntimeConfig
}

export interface GateKeeperContext {
  client: GateKeeperClient
  tokenStore: TokenStore
}

export interface GateKeeperRedirectState {
  codeVerifier: string
  state: string
  redirectUri?: string
  createdAt: number
}

export interface UseGateKeeperAuthOptions {
  audience?: string
  scope?: string
  redirectUri?: string
  tokenStore?: TokenStore
  redirectStateKey?: string
  codeVerifier?: string
  onRedirect?: (url: string) => void
}

export interface GateKeeperHydrationOptions {
  loadUser?: boolean
  refresh?: boolean
  clearOnRefreshFailure?: boolean
}

export interface GateKeeperRequireAuthOptions extends GateKeeperHydrationOptions {
  currentPath?: string
  loginPath?: string
  redirectQueryName?: string
  publicPaths?: string[]
  onRedirect?: (url: string) => void | Promise<void>
}

const gateKeeperKey: InjectionKey<GateKeeperContext> = Symbol('GateKeeper')
const defaultRedirectStateKey = 'gatekeeper.oauth'

function createContext(config: GateKeeperConfig, options: GateKeeperPluginOptions = {}): GateKeeperContext {
  return {
    client: new GateKeeperClient(config),
    tokenStore: options.tokenStore || new BrowserTokenStore(options.tokenStoreKey),
  }
}

function browserSessionStorage() {
  return typeof window === 'undefined' ? null : window.sessionStorage
}

function currentHref() {
  if (typeof window === 'undefined') {
    throw new Error('GateKeeper redirect callback handling requires a browser URL')
  }
  return window.location.href
}

function redirectTo(url: string, onRedirect?: (url: string) => void) {
  if (onRedirect) {
    onRedirect(url)
    return
  }
  if (typeof window === 'undefined') {
    throw new Error('GateKeeper login redirect requires a browser')
  }
  window.location.assign(url)
}

function browserCallbackUrl(path = '/auth/callback') {
  if (typeof window === 'undefined') {
    return undefined
  }
  return `${window.location.origin}${path}`
}

function saveRedirectState(key: string, state: GateKeeperRedirectState) {
  browserSessionStorage()?.setItem(key, JSON.stringify(state))
}

function loadRedirectState(key: string): GateKeeperRedirectState | null {
  const raw = browserSessionStorage()?.getItem(key)
  if (!raw) {
    return null
  }
  try {
    return JSON.parse(raw) as GateKeeperRedirectState
  } catch {
    browserSessionStorage()?.removeItem(key)
    return null
  }
}

function clearRedirectState(key: string) {
  browserSessionStorage()?.removeItem(key)
}

export function gateKeeperLoginRedirectPath(
  currentPath = '/',
  loginPath = '/login',
  redirectQueryName = 'redirect',
) {
  const separator = loginPath.includes('?') ? '&' : '?'
  return `${loginPath}${separator}${encodeURIComponent(redirectQueryName)}=${encodeURIComponent(currentPath)}`
}

export function createGateKeeper(config: GateKeeperConfig, options: GateKeeperPluginOptions = {}) {
  const context = createContext(config, options)
  return {
    install(app: App) {
      app.provide(gateKeeperKey, context)
    },
    client: context.client,
    tokenStore: context.tokenStore,
  }
}

export function gateKeeperConfigFromNuxtRuntime(
  runtimeConfig: GateKeeperNuxtRuntimeConfig,
  overrides: Partial<GateKeeperConfig> = {},
): GateKeeperConfig {
  const publicConfig = runtimeConfig.public || {}
  const issuer = overrides.issuer || publicConfig.gatekeeperIssuer
  if (!issuer) {
    throw new Error('GateKeeper Nuxt runtime config requires public.gatekeeperIssuer')
  }
  return {
    issuer,
    clientId: overrides.clientId || publicConfig.gatekeeperClientId,
    redirectUri: overrides.redirectUri || publicConfig.gatekeeperRedirectUri || browserCallbackUrl(),
    audience: overrides.audience || publicConfig.gatekeeperAudience,
    scope: overrides.scope || publicConfig.gatekeeperScopes,
    fetcher: overrides.fetcher,
  }
}

export function createGateKeeperFromNuxtRuntime(
  runtimeConfig: GateKeeperNuxtRuntimeConfig,
  options: GateKeeperPluginOptions = {},
  overrides: Partial<GateKeeperConfig> = {},
) {
  return createGateKeeper(gateKeeperConfigFromNuxtRuntime(runtimeConfig, overrides), options)
}

export function provideGateKeeper(config: GateKeeperConfig, options: GateKeeperPluginOptions = {}) {
  const context = createContext(config, options)
  provide(gateKeeperKey, context)
  return context.client
}

export function useGateKeeperContext() {
  const context = inject(gateKeeperKey)
  if (!context) {
    throw new Error('GateKeeper provider is missing')
  }
  return context
}

export function useGateKeeper() {
  return useGateKeeperContext().client
}

export function useGateKeeperAuth(options: UseGateKeeperAuthOptions = {}) {
  const context = useGateKeeperContext()
  const client = context.client
  const tokenStore = options.tokenStore || context.tokenStore
  const redirectStateKey = options.redirectStateKey || defaultRedirectStateKey
  const tokens = ref<GateKeeperTokens | null>(tokenStore.load())
  const me = ref<GateKeeperMe | null>(null)
  const user = ref<GateKeeperUser | null>(null)
  const orgs = ref<GateKeeperOrg[]>([])
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const accessToken = computed(() => tokens.value?.accessToken || null)
  const isAuthenticated = computed(() => Boolean(accessToken.value))
  const needsRefresh = computed(() => {
    if (!tokens.value) {
      return false
    }
    return tokens.value.expiresAt <= Date.now() + 60_000
  })

  function setTokenResponse(response: GateKeeperTokenResponse) {
    const stored = tokenStore.save(response)
    tokens.value = stored
    user.value = response.user || user.value
    orgs.value = response.orgs || orgs.value
    return stored
  }

  function loadFromStorage() {
    tokens.value = tokenStore.load()
    return tokens.value
  }

  function clearAuthState() {
    tokenStore.clear()
    tokens.value = null
    me.value = null
    user.value = null
    orgs.value = []
  }

  async function runTokenFlow(operation: () => Promise<GateKeeperTokenResponse>, fallback: string) {
    loading.value = true
    error.value = null
    try {
      const response = await operation()
      setTokenResponse(response)
      return response
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(fallback)
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function signup(params: GateKeeperSignupParams): Promise<GateKeeperTokenResponse> {
    return runTokenFlow(() => client.signup(params), 'GateKeeper signup failed')
  }

  async function loginWithPassword(params: GateKeeperLoginParams): Promise<GateKeeperTokenResponse> {
    return runTokenFlow(() => client.login(params), 'GateKeeper password login failed')
  }

  async function acceptInvitation(params: GateKeeperInvitationAcceptParams): Promise<GateKeeperTokenResponse> {
    return runTokenFlow(() => client.acceptInvitation(params), 'GateKeeper invitation acceptance failed')
  }

  async function requestEmailCode(params: GateKeeperEmailCodeRequestParams) {
    return client.requestEmailCode(params)
  }

  async function verifyEmailCode(params: GateKeeperEmailCodeVerifyParams): Promise<GateKeeperTokenResponse> {
    return runTokenFlow(() => client.verifyEmailCode(params), 'GateKeeper email-code verification failed')
  }

  async function requestPasswordReset(params: GateKeeperEmailCodeRequestParams) {
    return client.requestPasswordReset(params)
  }

  async function confirmPasswordReset(params: GateKeeperPasswordResetConfirmParams) {
    return client.confirmPasswordReset(params)
  }

  async function loginWithRedirect(params: AuthorizationStartParams = {}) {
    const flow = await client.startAuthorization({
      audience: options.audience,
      scope: options.scope,
      redirectUri: options.redirectUri,
      ...params,
    })
    saveRedirectState(redirectStateKey, {
      codeVerifier: flow.codeVerifier,
      state: flow.state,
      redirectUri: params.redirectUri || options.redirectUri,
      createdAt: Date.now(),
    })
    redirectTo(flow.url, options.onRedirect)
    return flow
  }

  async function handleRedirectCallback(callbackUrl = currentHref(), codeVerifier = options.codeVerifier) {
    const url = new URL(callbackUrl)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    if (!code) {
      throw new Error('GateKeeper callback is missing code')
    }

    const redirectState = loadRedirectState(redirectStateKey)
    if (redirectState?.state && state !== redirectState.state) {
      throw new Error('GateKeeper callback state did not match')
    }
    const verifier = codeVerifier || redirectState?.codeVerifier
    if (!verifier) {
      throw new Error('GateKeeper callback requires the original PKCE verifier')
    }

    loading.value = true
    error.value = null
    try {
      const response = await client.exchangeCode({
        code,
        codeVerifier: verifier,
        redirectUri: redirectState?.redirectUri || options.redirectUri,
      })
      clearRedirectState(redirectStateKey)
      setTokenResponse(response)
      return response
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('GateKeeper callback failed')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function refresh() {
    if (!tokens.value?.refreshToken) {
      throw new Error('GateKeeper refresh requires a refresh token')
    }
    loading.value = true
    error.value = null
    try {
      const response = await client.refresh(tokens.value.refreshToken)
      setTokenResponse(response)
      return response
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('GateKeeper token refresh failed')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function loadUser() {
    if (!tokens.value?.accessToken) {
      return null
    }
    loading.value = true
    error.value = null
    try {
      const account = await client.me(tokens.value.accessToken)
      me.value = account
      user.value = account.user || null
      return account
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('Could not load GateKeeper account')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  function requireAccessToken() {
    if (!tokens.value?.accessToken) {
      throw new Error('GateKeeper access token is missing')
    }
    return tokens.value.accessToken
  }

  async function switchOrg(params: SwitchOrgParams): Promise<GateKeeperTokenResponse> {
    loading.value = true
    error.value = null
    try {
      const response = await client.switchOrg(requireAccessToken(), params)
      setTokenResponse(response)
      return response
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('Could not switch GateKeeper organization')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function changePassword(params: GateKeeperPasswordChangeParams): Promise<GateKeeperPasswordChangeResponse> {
    return client.changePassword(requireAccessToken(), params)
  }

  async function updateProfile(params: GateKeeperProfileUpdateParams): Promise<GateKeeperUser> {
    const updated = await client.updateMe(requireAccessToken(), params)
    user.value = updated
    if (me.value) {
      me.value.user = updated
    }
    return updated
  }

  async function requestEmailChange(params: { newEmail: string; currentPassword?: string | null }) {
    return client.requestEmailChange(requireAccessToken(), params)
  }

  async function confirmEmailChange(params: {
    newEmail: string
    code: string
    revokeOtherSessions?: boolean
  }): Promise<GateKeeperEmailChangeResponse> {
    const response = await client.confirmEmailChange(requireAccessToken(), params)
    if (user.value) {
      user.value.email = response.email
      user.value.email_verified = true
    }
    if (me.value?.user) {
      me.value.user.email = response.email
      me.value.user.email_verified = true
    }
    return response
  }

  async function linkedIdentities(): Promise<GateKeeperLinkedIdentity[]> {
    return client.linkedIdentities(requireAccessToken())
  }

  async function unlinkIdentity(identityId: string) {
    return client.unlinkIdentity(requireAccessToken(), identityId)
  }

  async function startIdentityLink(providerId: string, params: { redirect?: string | null } = {}) {
    return client.startIdentityLink(requireAccessToken(), providerId, params)
  }

  async function oauthProviders(): Promise<GateKeeperOAuthProvider[]> {
    return client.oauthProviders()
  }

  async function startOAuthProvider(providerId: string, params: { redirect?: string | null } = {}) {
    return client.startOAuthProvider(providerId, params)
  }

  async function apiTokens(): Promise<GateKeeperApiToken[]> {
    return client.apiTokens(requireAccessToken())
  }

  async function createApiToken(params: GateKeeperApiTokenCreate): Promise<GateKeeperApiToken> {
    return client.createApiToken(requireAccessToken(), params)
  }

  async function rotateApiToken(tokenId: string): Promise<GateKeeperApiToken> {
    return client.rotateApiToken(requireAccessToken(), tokenId)
  }

  async function revokeApiToken(tokenId: string) {
    return client.revokeApiToken(requireAccessToken(), tokenId)
  }

  async function oauthProvidersAdmin(): Promise<GateKeeperOAuthProviderAdmin[]> {
    return client.oauthProvidersAdmin(requireAccessToken())
  }

  async function createOAuthProvider(params: GateKeeperOAuthProviderCreate): Promise<GateKeeperOAuthProviderAdmin> {
    return client.createOAuthProvider(requireAccessToken(), params)
  }

  async function updateOAuthProvider(
    providerId: string,
    params: GateKeeperOAuthProviderUpdate,
  ): Promise<GateKeeperOAuthProviderAdmin> {
    return client.updateOAuthProvider(requireAccessToken(), providerId, params)
  }

  async function deleteOAuthProvider(providerId: string) {
    return client.deleteOAuthProvider(requireAccessToken(), providerId)
  }

  async function exportAccount(): Promise<GateKeeperAccountExport> {
    return client.exportAccount(requireAccessToken())
  }

  async function deactivateAccount(params: {
    currentPassword?: string | null
    totpCode?: string | null
    recoveryCode?: string | null
  } = {}): Promise<GateKeeperAccountDeactivateResponse> {
    const response = await client.deactivateAccount(requireAccessToken(), params)
    clearAuthState()
    return response
  }

  async function sessions(): Promise<GateKeeperSession[]> {
    return client.sessions(requireAccessToken())
  }

  async function revokeSession(sessionId: string) {
    return client.revokeSession(requireAccessToken(), sessionId)
  }

  async function updateSessionDevice(
    sessionId: string,
    params: { deviceLabel?: string | null; trusted?: boolean; trustedUntil?: string | null },
  ): Promise<GateKeeperSession> {
    return client.updateSessionDevice(requireAccessToken(), sessionId, params)
  }

  async function revokeAllSessions(includeCurrent = true) {
    const response = await client.revokeAllSessions(requireAccessToken(), includeCurrent)
    if (includeCurrent) {
      clearAuthState()
    }
    return response
  }

  async function grants(): Promise<GateKeeperOAuthGrant[]> {
    return client.grants(requireAccessToken())
  }

  async function revokeGrant(grantId: string) {
    return client.revokeGrant(requireAccessToken(), grantId)
  }

  async function grantsAdmin(params: GateKeeperOAuthGrantAdminListOptions = {}): Promise<GateKeeperOAuthGrant[]> {
    return client.grantsAdmin(requireAccessToken(), params)
  }

  async function revokeGrantAdmin(grantId: string) {
    return client.revokeGrantAdmin(requireAccessToken(), grantId)
  }

  async function logout(revoke = true) {
    const access = tokens.value?.accessToken
    try {
      if (revoke && access) {
        await client.logout(access)
      }
    } finally {
      clearAuthState()
    }
  }

  return {
    tokens,
    accessToken,
    me,
    user,
    orgs,
    loading,
    error,
    isAuthenticated,
    needsRefresh,
    signup,
    loginWithPassword,
    acceptInvitation,
    requestEmailCode,
    verifyEmailCode,
    requestPasswordReset,
    confirmPasswordReset,
    loginWithRedirect,
    handleRedirectCallback,
    loadFromStorage,
    saveTokens: setTokenResponse,
    refresh,
    loadUser,
    switchOrg,
    updateProfile,
    changePassword,
    requestEmailChange,
    confirmEmailChange,
    linkedIdentities,
    unlinkIdentity,
    startIdentityLink,
    oauthProviders,
    startOAuthProvider,
    apiTokens,
    createApiToken,
    rotateApiToken,
    revokeApiToken,
    oauthProvidersAdmin,
    createOAuthProvider,
    updateOAuthProvider,
    deleteOAuthProvider,
    exportAccount,
    deactivateAccount,
    sessions,
    revokeSession,
    updateSessionDevice,
    revokeAllSessions,
    grants,
    revokeGrant,
    grantsAdmin,
    revokeGrantAdmin,
    logout,
    clear: clearAuthState,
  }
}

export type GateKeeperAuth = ReturnType<typeof useGateKeeperAuth>

export function useGateKeeperHydration(auth: GateKeeperAuth = useGateKeeperAuth()) {
  const hydrated = ref(false)
  const hydrating = ref(false)
  const redirecting = ref(false)
  const error = ref<Error | null>(null)

  async function hydrate(options: GateKeeperHydrationOptions = {}) {
    hydrating.value = true
    error.value = null
    try {
      auth.loadFromStorage()
      if (options.refresh !== false && auth.needsRefresh.value && auth.tokens.value?.refreshToken) {
        try {
          await auth.refresh()
        } catch (err) {
          if (options.clearOnRefreshFailure !== false) {
            auth.clear()
          }
          throw err
        }
      }
      if (options.loadUser && auth.isAuthenticated.value) {
        await auth.loadUser()
      }
      hydrated.value = true
      return {
        authenticated: auth.isAuthenticated.value,
        user: auth.user.value,
        me: auth.me.value,
      }
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not hydrate GateKeeper auth')
      throw error.value
    } finally {
      hydrating.value = false
    }
  }

  async function requireAuth(options: GateKeeperRequireAuthOptions = {}) {
    const currentPath = options.currentPath || '/'
    if (options.publicPaths?.includes(currentPath)) {
      await hydrate({ ...options, loadUser: false })
      return true
    }

    const result = await hydrate({
      loadUser: options.loadUser ?? true,
      refresh: options.refresh,
      clearOnRefreshFailure: options.clearOnRefreshFailure,
    })
    if (result.authenticated) {
      return true
    }

    const redirectPath = gateKeeperLoginRedirectPath(
      currentPath,
      options.loginPath || '/login',
      options.redirectQueryName || 'redirect',
    )
    redirecting.value = true
    await options.onRedirect?.(redirectPath)
    return false
  }

  return {
    auth,
    hydrated,
    hydrating,
    redirecting,
    error,
    hydrate,
    requireAuth,
    loginRedirectPath: gateKeeperLoginRedirectPath,
  }
}

export interface UseGateKeeperResourceOptions {
  immediate?: boolean
}

function gateKeeperError(err: unknown, fallback: string) {
  return err instanceof Error ? err : new Error(fallback)
}

export function useGateKeeperAccount(
  auth: GateKeeperAuth = useGateKeeperAuth(),
  options: UseGateKeeperResourceOptions = {},
) {
  const identities = ref<GateKeeperLinkedIdentity[]>([])
  const loading = ref(false)
  const saving = ref(false)
  const error = ref<Error | null>(null)

  const activeOrg = computed(() => {
    const currentOrgId = auth.me.value?.org_id
    return auth.orgs.value.find((org) => org.id === currentOrgId) || auth.orgs.value[0] || null
  })

  async function load() {
    loading.value = true
    error.value = null
    try {
      await auth.loadUser()
      identities.value = await auth.linkedIdentities()
      return {
        me: auth.me.value,
        identities: identities.value,
      }
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not load GateKeeper account')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function updateProfile(params: GateKeeperProfileUpdateParams) {
    saving.value = true
    error.value = null
    try {
      return await auth.updateProfile(params)
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not update GateKeeper profile')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  async function changePassword(params: GateKeeperPasswordChangeParams) {
    saving.value = true
    error.value = null
    try {
      return await auth.changePassword(params)
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not change GateKeeper password')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  async function requestEmailChange(params: { newEmail: string; currentPassword?: string | null }) {
    saving.value = true
    error.value = null
    try {
      return await auth.requestEmailChange(params)
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not request GateKeeper email change')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  async function confirmEmailChange(params: { newEmail: string; code: string; revokeOtherSessions?: boolean }) {
    saving.value = true
    error.value = null
    try {
      return await auth.confirmEmailChange(params)
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not confirm GateKeeper email change')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  async function unlinkIdentity(identityId: string) {
    saving.value = true
    error.value = null
    try {
      const result = await auth.unlinkIdentity(identityId)
      identities.value = identities.value.filter((identity) => identity.id !== identityId)
      return result
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not unlink GateKeeper identity')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  async function exportAccount() {
    saving.value = true
    error.value = null
    try {
      return await auth.exportAccount()
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not export GateKeeper account')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  async function deactivateAccount(params: {
    currentPassword?: string | null
    totpCode?: string | null
    recoveryCode?: string | null
  } = {}) {
    saving.value = true
    error.value = null
    try {
      return await auth.deactivateAccount(params)
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not deactivate GateKeeper account')
      throw error.value
    } finally {
      saving.value = false
    }
  }

  if (options.immediate) {
    onMounted(() => {
      void load()
    })
  }

  return {
    auth,
    me: auth.me,
    user: auth.user,
    orgs: auth.orgs,
    activeOrg,
    identities,
    loading,
    saving,
    error,
    load,
    updateProfile,
    changePassword,
    requestEmailChange,
    confirmEmailChange,
    unlinkIdentity,
    exportAccount,
    deactivateAccount,
  }
}

export function useGateKeeperSessions(
  auth: GateKeeperAuth = useGateKeeperAuth(),
  options: UseGateKeeperResourceOptions = {},
) {
  const items = ref<GateKeeperSession[]>([])
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const activeSessions = computed(() => items.value.filter((session) => !session.revoked_at))
  const currentSession = computed(() => items.value.find((session) => session.current) || null)

  function replaceSession(updated: GateKeeperSession) {
    const index = items.value.findIndex((session) => session.id === updated.id)
    if (index >= 0) {
      items.value.splice(index, 1, updated)
    } else {
      items.value.unshift(updated)
    }
  }

  async function load() {
    loading.value = true
    error.value = null
    try {
      items.value = await auth.sessions()
      return items.value
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not load GateKeeper sessions')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function updateDevice(
    sessionId: string,
    params: { deviceLabel?: string | null; trusted?: boolean; trustedUntil?: string | null },
  ) {
    loading.value = true
    error.value = null
    try {
      const updated = await auth.updateSessionDevice(sessionId, params)
      replaceSession(updated)
      return updated
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not update GateKeeper session device')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function revoke(sessionId: string) {
    loading.value = true
    error.value = null
    try {
      const result = await auth.revokeSession(sessionId)
      items.value = items.value.filter((session) => session.id !== sessionId)
      return result
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not revoke GateKeeper session')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function revokeAll(includeCurrent = true) {
    loading.value = true
    error.value = null
    try {
      const result = await auth.revokeAllSessions(includeCurrent)
      if (includeCurrent) {
        items.value = []
      } else {
        await load()
      }
      return result
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not revoke GateKeeper sessions')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  if (options.immediate) {
    onMounted(() => {
      void load()
    })
  }

  return {
    auth,
    sessions: items,
    activeSessions,
    currentSession,
    loading,
    error,
    load,
    updateDevice,
    revoke,
    revokeAll,
  }
}

export function useGateKeeperApiTokens(
  auth: GateKeeperAuth = useGateKeeperAuth(),
  options: UseGateKeeperResourceOptions = {},
) {
  const items = ref<GateKeeperApiToken[]>([])
  const copyOnceToken = ref<GateKeeperApiToken | null>(null)
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const activeTokens = computed(() => items.value.filter((token) => !token.revoked_at))

  function replaceToken(updated: GateKeeperApiToken) {
    const index = items.value.findIndex((token) => token.id === updated.id)
    if (index >= 0) {
      items.value.splice(index, 1, updated)
    } else {
      items.value.unshift(updated)
    }
  }

  async function load() {
    loading.value = true
    error.value = null
    try {
      items.value = await auth.apiTokens()
      return items.value
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not load GateKeeper API tokens')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function create(params: GateKeeperApiTokenCreate) {
    loading.value = true
    error.value = null
    try {
      const created = await auth.createApiToken(params)
      copyOnceToken.value = created.token ? created : null
      replaceToken(created)
      return created
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not create GateKeeper API token')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function rotate(tokenId: string) {
    loading.value = true
    error.value = null
    try {
      const rotated = await auth.rotateApiToken(tokenId)
      copyOnceToken.value = rotated.token ? rotated : null
      replaceToken(rotated)
      return rotated
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not rotate GateKeeper API token')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function revoke(tokenId: string) {
    loading.value = true
    error.value = null
    try {
      const result = await auth.revokeApiToken(tokenId)
      items.value = items.value.filter((token) => token.id !== tokenId)
      if (copyOnceToken.value?.id === tokenId) {
        copyOnceToken.value = null
      }
      return result
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not revoke GateKeeper API token')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  function clearCopyOnceToken() {
    copyOnceToken.value = null
  }

  if (options.immediate) {
    onMounted(() => {
      void load()
    })
  }

  return {
    auth,
    tokens: items,
    activeTokens,
    copyOnceToken,
    loading,
    error,
    load,
    create,
    rotate,
    revoke,
    clearCopyOnceToken,
  }
}

export interface UseGateKeeperConnectedAppsOptions extends UseGateKeeperResourceOptions {
  includeRevoked?: boolean
}

export function useGateKeeperConnectedApps(
  auth: GateKeeperAuth = useGateKeeperAuth(),
  options: UseGateKeeperConnectedAppsOptions = {},
) {
  const items = ref<GateKeeperOAuthGrant[]>([])
  const includeRevoked = ref(Boolean(options.includeRevoked))
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const activeGrants = computed(() => items.value.filter((grant) => !grant.revoked_at))
  const revokedGrants = computed(() => items.value.filter((grant) => grant.revoked_at))

  async function load() {
    loading.value = true
    error.value = null
    try {
      const grants = await auth.grants()
      items.value = includeRevoked.value ? grants : grants.filter((grant) => !grant.revoked_at)
      return items.value
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not load GateKeeper connected apps')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function revoke(grantId: string) {
    loading.value = true
    error.value = null
    try {
      const result = await auth.revokeGrant(grantId)
      items.value = items.value.filter((grant) => grant.id !== grantId)
      return result
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not revoke GateKeeper connected app')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  function setIncludeRevoked(value: boolean) {
    includeRevoked.value = value
  }

  if (options.immediate) {
    onMounted(() => {
      void load()
    })
  }

  return {
    auth,
    grants: items,
    activeGrants,
    revokedGrants,
    includeRevoked,
    loading,
    error,
    load,
    revoke,
    setIncludeRevoked,
  }
}

export interface UseGateKeeperConnectedAppsAdminOptions
  extends UseGateKeeperResourceOptions,
    GateKeeperOAuthGrantAdminListOptions {}

export function useGateKeeperConnectedAppsAdmin(
  auth: GateKeeperAuth = useGateKeeperAuth(),
  options: UseGateKeeperConnectedAppsAdminOptions = {},
) {
  const items = ref<GateKeeperOAuthGrant[]>([])
  const filters = ref<GateKeeperOAuthGrantAdminListOptions>({
    orgId: options.orgId,
    clientId: options.clientId,
    userId: options.userId,
    includeRevoked: options.includeRevoked,
  })
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const activeGrants = computed(() => items.value.filter((grant) => !grant.revoked_at))
  const revokedGrants = computed(() => items.value.filter((grant) => grant.revoked_at))

  async function load(nextFilters: GateKeeperOAuthGrantAdminListOptions = {}) {
    loading.value = true
    error.value = null
    filters.value = {
      ...filters.value,
      ...nextFilters,
    }
    try {
      items.value = await auth.grantsAdmin(filters.value)
      return items.value
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not load GateKeeper connected-app grants')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  async function revoke(grantId: string) {
    loading.value = true
    error.value = null
    try {
      const result = await auth.revokeGrantAdmin(grantId)
      items.value = items.value.filter((grant) => grant.id !== grantId)
      return result
    } catch (err) {
      error.value = gateKeeperError(err, 'Could not revoke GateKeeper connected-app grant')
      throw error.value
    } finally {
      loading.value = false
    }
  }

  function setFilters(nextFilters: GateKeeperOAuthGrantAdminListOptions) {
    filters.value = {
      ...filters.value,
      ...nextFilters,
    }
  }

  if (options.immediate) {
    onMounted(() => {
      void load()
    })
  }

  return {
    auth,
    grants: items,
    activeGrants,
    revokedGrants,
    filters,
    loading,
    error,
    load,
    revoke,
    setFilters,
  }
}

const gateKeeperComponentProps = {
  auth: Object as PropType<GateKeeperAuth>,
  classPrefix: { type: String, default: 'gk' },
}

function gkClass(prefix: string, name: string) {
  return `${prefix}-${name}`
}

function formatGateKeeperDate(value?: string | null) {
  return value ? new Date(value).toLocaleString() : 'never'
}

function gateKeeperErrorText(error: Error | null) {
  return error?.message || ''
}

function gateKeeperButton(label: string, onClick: () => unknown | Promise<unknown>, disabled = false) {
  return h(
    'button',
    {
      type: 'button',
      disabled,
      onClick: () => {
        void onClick()
      },
    },
    label,
  )
}

function gateKeeperCopyButton(label: string, value?: string | null) {
  return gateKeeperButton(label, async () => {
    if (value && typeof navigator !== 'undefined' && navigator.clipboard) {
      await navigator.clipboard.writeText(value)
    }
  }, !value)
}

export const GateKeeperAccountCard = defineComponent({
  name: 'GateKeeperAccountCard',
  props: gateKeeperComponentProps,
  setup(props, { slots }) {
    const account = useGateKeeperAccount(props.auth || useGateKeeperAuth(), { immediate: true })

    return () => {
      const prefix = props.classPrefix
      if (slots.default) {
        return h('section', { class: gkClass(prefix, 'account-card') }, slots.default({ account }))
      }
      return h('section', { class: gkClass(prefix, 'account-card') }, [
        h('div', { class: gkClass(prefix, 'account-header') }, [
          h('div', [
            h('p', { class: gkClass(prefix, 'eyebrow') }, 'GateKeeper account'),
            h('h2', account.user.value?.display_name || account.user.value?.email || 'Signed-in user'),
            h('p', account.user.value?.email || account.me.value?.subject || 'No account loaded'),
          ]),
          gateKeeperButton('Refresh', account.load, account.loading.value),
        ]),
        account.error.value
          ? h('p', { class: gkClass(prefix, 'error') }, gateKeeperErrorText(account.error.value))
          : null,
        h('dl', { class: gkClass(prefix, 'facts') }, [
          h('div', [h('dt', 'Organization'), h('dd', account.activeOrg.value?.name || 'Personal account')]),
          h('div', [h('dt', 'Role'), h('dd', account.activeOrg.value?.role || 'none')]),
          h('div', [h('dt', 'Permissions'), h('dd', account.activeOrg.value?.permissions.join(', ') || 'none')]),
          h('div', [h('dt', 'Linked identities'), h('dd', String(account.identities.value.length))]),
        ]),
        h('div', { class: gkClass(prefix, 'actions') }, [
          gateKeeperButton('Export account', account.exportAccount, account.saving.value),
        ]),
      ])
    }
  },
})

export const GateKeeperSessionList = defineComponent({
  name: 'GateKeeperSessionList',
  props: gateKeeperComponentProps,
  setup(props, { slots }) {
    const sessionState = useGateKeeperSessions(props.auth || useGateKeeperAuth(), { immediate: true })

    return () => {
      const prefix = props.classPrefix
      if (slots.default) {
        return h('section', { class: gkClass(prefix, 'sessions') }, slots.default({ sessions: sessionState }))
      }
      const rows = sessionState.sessions.value
      return h('section', { class: gkClass(prefix, 'sessions') }, [
        h('div', { class: gkClass(prefix, 'section-header') }, [
          h('h2', 'Sessions and devices'),
          gateKeeperButton('Refresh', sessionState.load, sessionState.loading.value),
        ]),
        sessionState.error.value
          ? h('p', { class: gkClass(prefix, 'error') }, gateKeeperErrorText(sessionState.error.value))
          : null,
        sessionState.loading.value && !rows.length ? h('p', 'Loading sessions...') : null,
        !sessionState.loading.value && !rows.length ? h('p', 'No sessions found.') : null,
        h(
          'ul',
          { class: gkClass(prefix, 'list') },
          rows.map((session) =>
            h('li', { key: session.id, class: gkClass(prefix, 'list-item') }, [
              h('div', [
                h('strong', session.device_label || session.client_name || 'GateKeeper session'),
                h(
                  'p',
                  [
                    session.current ? 'Current session' : 'Session',
                    session.trusted ? ' / trusted device' : '',
                    session.client_id ? ` / ${session.client_id}` : '',
                  ].join(''),
                ),
                h('p', `Last seen ${formatGateKeeperDate(session.last_seen_at)} / expires ${formatGateKeeperDate(session.expires_at)}`),
                session.amr.length ? h('p', `Assurance: ${session.amr.join(', ')}`) : null,
              ]),
              h('div', { class: gkClass(prefix, 'actions') }, [
                gateKeeperButton(
                  session.trusted ? 'Untrust' : 'Trust',
                  () => sessionState.updateDevice(session.id, { trusted: !session.trusted }),
                  sessionState.loading.value || Boolean(session.revoked_at),
                ),
                gateKeeperButton(
                  session.revoked_at ? 'Revoked' : 'Revoke',
                  () => sessionState.revoke(session.id),
                  sessionState.loading.value || Boolean(session.revoked_at),
                ),
              ]),
            ]),
          ),
        ),
        h('div', { class: gkClass(prefix, 'actions') }, [
          gateKeeperButton('Revoke other sessions', () => sessionState.revokeAll(false), sessionState.loading.value),
          gateKeeperButton('Sign out everywhere', () => sessionState.revokeAll(true), sessionState.loading.value),
        ]),
      ])
    }
  },
})

export const GateKeeperApiTokenList = defineComponent({
  name: 'GateKeeperApiTokenList',
  props: {
    ...gateKeeperComponentProps,
    defaultName: { type: String, default: 'GateKeeper API key' },
    tokenType: { type: String, default: 'personal' },
    scopes: { type: Array as PropType<string[]>, default: () => ['api:read'] },
    audiences: { type: Array as PropType<string[]>, default: () => [] },
  },
  setup(props, { slots }) {
    const tokenState = useGateKeeperApiTokens(props.auth || useGateKeeperAuth(), { immediate: true })

    async function createDefaultToken() {
      return tokenState.create({
        name: props.defaultName,
        tokenType: props.tokenType,
        scopes: props.scopes,
        audiences: props.audiences,
      })
    }

    return () => {
      const prefix = props.classPrefix
      if (slots.default) {
        return h('section', { class: gkClass(prefix, 'api-tokens') }, slots.default({ apiTokens: tokenState }))
      }
      const rows = tokenState.tokens.value
      return h('section', { class: gkClass(prefix, 'api-tokens') }, [
        h('div', { class: gkClass(prefix, 'section-header') }, [
          h('h2', 'API keys'),
          h('div', { class: gkClass(prefix, 'actions') }, [
            gateKeeperButton('Refresh', tokenState.load, tokenState.loading.value),
            gateKeeperButton('Create key', createDefaultToken, tokenState.loading.value),
          ]),
        ]),
        tokenState.error.value ? h('p', { class: gkClass(prefix, 'error') }, gateKeeperErrorText(tokenState.error.value)) : null,
        tokenState.copyOnceToken.value?.token
          ? h('div', { class: gkClass(prefix, 'copy-once') }, [
              h('strong', 'Copy this key now'),
              h('code', tokenState.copyOnceToken.value.token),
              gateKeeperCopyButton('Copy key', tokenState.copyOnceToken.value.token),
              gateKeeperButton('Dismiss', tokenState.clearCopyOnceToken),
            ])
          : null,
        tokenState.loading.value && !rows.length ? h('p', 'Loading API keys...') : null,
        !tokenState.loading.value && !rows.length ? h('p', 'No API keys found.') : null,
        h(
          'ul',
          { class: gkClass(prefix, 'list') },
          rows.map((token) =>
            h('li', { key: token.id, class: gkClass(prefix, 'list-item') }, [
              h('div', [
                h('strong', token.name),
                h('p', `${token.token_type} / ${token.token_hint}`),
                h('p', `Scopes: ${token.scopes.join(', ') || 'none'}`),
                h('p', `Audiences: ${token.audiences.join(', ') || 'none'}`),
                h('p', `Last used ${formatGateKeeperDate(token.last_used_at)}`),
              ]),
              h('div', { class: gkClass(prefix, 'actions') }, [
                gateKeeperButton('Rotate', () => tokenState.rotate(token.id), tokenState.loading.value || Boolean(token.revoked_at)),
                gateKeeperButton('Revoke', () => tokenState.revoke(token.id), tokenState.loading.value || Boolean(token.revoked_at)),
              ]),
            ]),
          ),
        ),
      ])
    }
  },
})

export const GateKeeperConnectedAppsList = defineComponent({
  name: 'GateKeeperConnectedAppsList',
  props: {
    ...gateKeeperComponentProps,
    includeRevoked: { type: Boolean, default: false },
  },
  setup(props, { slots }) {
    const grantState = useGateKeeperConnectedApps(props.auth || useGateKeeperAuth(), {
      immediate: true,
      includeRevoked: props.includeRevoked,
    })

    return () => {
      const prefix = props.classPrefix
      if (slots.default) {
        return h('section', { class: gkClass(prefix, 'connected-apps') }, slots.default({ connectedApps: grantState }))
      }
      const rows = grantState.grants.value
      return h('section', { class: gkClass(prefix, 'connected-apps') }, [
        h('div', { class: gkClass(prefix, 'section-header') }, [
          h('h2', 'Connected apps'),
          gateKeeperButton('Refresh', grantState.load, grantState.loading.value),
        ]),
        grantState.error.value ? h('p', { class: gkClass(prefix, 'error') }, gateKeeperErrorText(grantState.error.value)) : null,
        grantState.loading.value && !rows.length ? h('p', 'Loading connected apps...') : null,
        !grantState.loading.value && !rows.length ? h('p', 'No connected apps found.') : null,
        h(
          'ul',
          { class: gkClass(prefix, 'list') },
          rows.map((grant) =>
            h('li', { key: grant.id, class: gkClass(prefix, 'list-item') }, [
              h('div', [
                h('strong', grant.client_name),
                h('p', grant.client_id),
                h('p', `Audience: ${grant.audience || 'default'}`),
                h('p', `Scopes: ${grant.scopes.join(', ') || 'none'}`),
                h('p', `Last authorized ${formatGateKeeperDate(grant.last_authorized_at)}`),
              ]),
              h('div', { class: gkClass(prefix, 'actions') }, [
                gateKeeperButton('Revoke', () => grantState.revoke(grant.id), grantState.loading.value || Boolean(grant.revoked_at)),
              ]),
            ]),
          ),
        ),
      ])
    }
  },
})

export { BrowserTokenStore, GateKeeperClient }
export type {
  AuthorizationStartParams,
  GateKeeperAccountDeactivateResponse,
  GateKeeperAccountExport,
  GateKeeperApiToken,
  GateKeeperApiTokenCreate,
  GateKeeperConfig,
  GateKeeperEmailChangeResponse,
  GateKeeperEmailCodeRequestParams,
  GateKeeperEmailCodeVerifyParams,
  GateKeeperInvitationAcceptParams,
  GateKeeperLinkedIdentity,
  GateKeeperLoginParams,
  GateKeeperMe,
  GateKeeperOAuthGrant,
  GateKeeperOAuthGrantAdminListOptions,
  GateKeeperOAuthProvider,
  GateKeeperOAuthProviderAdmin,
  GateKeeperOAuthProviderCreate,
  GateKeeperOAuthProviderUpdate,
  GateKeeperOrg,
  GateKeeperPasswordChangeParams,
  GateKeeperPasswordChangeResponse,
  GateKeeperPasswordResetConfirmParams,
  GateKeeperProfileUpdateParams,
  GateKeeperSession,
  GateKeeperSignupParams,
  GateKeeperTokenResponse,
  GateKeeperTokens,
  GateKeeperUser,
  SwitchOrgParams,
  TokenStore,
}
