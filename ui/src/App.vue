<script setup lang="ts">
import { computed } from 'vue'
import type { Component } from 'vue'
import {
  BadgeCheck,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  PlugZap,
  MonitorCog,
  MonitorSmartphone,
  ScrollText,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  UserPlus,
} from 'lucide-vue-next'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { api } from '@/services/api'

const route = useRoute()
const router = useRouter()
const authRoutes = ['/login', '/signup', '/verify', '/reset-password', '/device', '/accept-invite', '/authorize']
const isAuthRoute = computed(() => authRoutes.includes(route.path))

const nav: Array<{ path: string; label: string; icon: Component }> = [
  { path: '/account', label: 'Account', icon: LayoutDashboard },
  { path: '/users', label: 'Users', icon: Users },
  { path: '/invitations', label: 'Invites', icon: UserPlus },
  { path: '/grants', label: 'Apps', icon: BadgeCheck },
  { path: '/sessions', label: 'Sessions', icon: MonitorSmartphone },
  { path: '/tokens', label: 'Tokens', icon: KeyRound },
  { path: '/clients', label: 'Clients', icon: MonitorCog },
  { path: '/providers', label: 'Providers', icon: PlugZap },
  { path: '/policy', label: 'Policy', icon: SlidersHorizontal },
  { path: '/projects', label: 'Projects', icon: ListChecks },
  { path: '/roles', label: 'Roles', icon: ShieldCheck },
  { path: '/audit', label: 'Audit', icon: ScrollText },
]

async function signOut() {
  try {
    await api.logout()
  } finally {
    router.push('/login')
  }
}
</script>

<template>
  <main v-if="isAuthRoute" class="min-h-svh bg-bg text-fg">
    <RouterView />
  </main>

  <main v-else class="min-h-svh bg-bg text-fg">
    <aside
      class="fixed inset-y-0 left-0 hidden w-64 border-r border-border bg-[#0B0C0E] px-5 py-6 lg:block"
    >
      <RouterLink to="/account" class="flex items-center gap-3">
        <span class="grid h-9 w-9 place-items-center rounded-md border border-border bg-surface font-mono text-xs text-accent">
          GK
        </span>
        <div>
          <p class="font-serif text-2xl leading-none">GateKeeper</p>
          <p class="mono-label mt-1">AUTH / 01</p>
        </div>
      </RouterLink>
      <nav class="mt-10 grid gap-1">
        <RouterLink
          v-for="item in nav"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted transition hover:bg-surface hover:text-fg"
          active-class="bg-surface text-fg"
        >
          <component :is="item.icon" class="h-4 w-4" aria-hidden="true" />
          {{ item.label }}
        </RouterLink>
      </nav>
    </aside>

    <section class="lg:pl-64">
      <header
        class="sticky top-0 z-10 border-b border-border bg-bg/90 px-4 backdrop-blur md:px-8"
      >
        <div class="flex min-h-16 items-center justify-between gap-4">
          <RouterLink to="/account" class="flex items-center gap-3 lg:hidden">
            <span class="grid h-8 w-8 place-items-center rounded-md border border-border bg-surface font-mono text-xs text-accent">
              GK
            </span>
            <span class="font-serif text-xl">GateKeeper</span>
          </RouterLink>
          <div class="hidden lg:block">
            <p class="mono-label">AUTH CONTROL</p>
          </div>
          <button type="button" class="btn-secondary gap-2 text-sm" @click="signOut">
            <LogOut class="h-4 w-4" aria-hidden="true" />
            Sign out
          </button>
        </div>
        <nav class="flex gap-2 overflow-x-auto pb-3 lg:hidden">
          <RouterLink
            v-for="item in nav"
            :key="item.path"
            :to="item.path"
            class="inline-flex min-h-10 shrink-0 items-center gap-2 rounded-md border border-border px-3 text-sm text-muted"
            active-class="bg-surface text-fg"
          >
            <component :is="item.icon" class="h-4 w-4" aria-hidden="true" />
            {{ item.label }}
          </RouterLink>
        </nav>
      </header>
      <RouterView />
    </section>
  </main>
</template>
