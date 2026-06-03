import { inject, provide, type App, type InjectionKey } from 'vue'

import { GateKeeperClient, type GateKeeperConfig } from '@b3n/gatekeeper-js'

const gateKeeperKey: InjectionKey<GateKeeperClient> = Symbol('GateKeeper')

export function createGateKeeper(config: GateKeeperConfig) {
  const client = new GateKeeperClient(config)
  return {
    install(app: App) {
      app.provide(gateKeeperKey, client)
    },
    client,
  }
}

export function provideGateKeeper(config: GateKeeperConfig) {
  const client = new GateKeeperClient(config)
  provide(gateKeeperKey, client)
  return client
}

export function useGateKeeper() {
  const client = inject(gateKeeperKey)
  if (!client) {
    throw new Error('GateKeeper provider is missing')
  }
  return client
}

export { GateKeeperClient }
export type { GateKeeperConfig }

