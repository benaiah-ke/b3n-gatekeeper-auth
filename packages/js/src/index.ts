export interface GateKeeperConfig {
  issuer: string
  clientId?: string
  redirectUri?: string
}

export interface ProtectedResourceMetadata {
  resource: string
  authorization_servers: string[]
  scopes_supported: string[]
}

export class GateKeeperClient {
  private issuer: string
  private clientId?: string
  private redirectUri?: string

  constructor(config: GateKeeperConfig) {
    this.issuer = config.issuer.replace(/\/$/, '')
    this.clientId = config.clientId
    this.redirectUri = config.redirectUri
  }

  authorizationUrl(params: {
    codeChallenge: string
    scope?: string
    state?: string
    audience?: string
  }) {
    if (!this.clientId || !this.redirectUri) {
      throw new Error('clientId and redirectUri are required')
    }
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      code_challenge: params.codeChallenge,
      code_challenge_method: 'S256',
      scope: params.scope || 'openid profile email',
    })
    if (params.state) query.set('state', params.state)
    if (params.audience) query.set('audience', params.audience)
    return `${this.issuer}/oauth/authorize?${query.toString()}`
  }

  async protectedResource(path = ''): Promise<ProtectedResourceMetadata> {
    const suffix = path ? `/${path.replace(/^\//, '')}` : ''
    const response = await fetch(`${this.issuer}/.well-known/oauth-protected-resource${suffix}`)
    if (!response.ok) throw new Error('Could not load protected-resource metadata')
    return response.json()
  }

  async me(accessToken: string) {
    const response = await fetch(`${this.issuer}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (!response.ok) throw new Error('GateKeeper session is invalid')
    return response.json()
  }
}

