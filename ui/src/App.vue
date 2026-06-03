<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

const route = useRoute()
const authRoutes = ['/login', '/signup', '/verify', '/reset-password', '/device']
const isAuthRoute = computed(() => authRoutes.includes(route.path))

const nav: Array<[string, string]> = [
  ['/account', 'Account'],
  ['/tokens', 'Tokens'],
  ['/clients', 'Clients'],
  ['/projects', 'Projects'],
  ['/roles', 'Roles'],
  ['/audit', 'Audit'],
]
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
        <img src="/brand/b3n-mark-no-bg.png" class="h-9 w-9" alt="B3n" />
        <div>
          <p class="font-serif text-2xl leading-none">GateKeeper</p>
          <p class="mono-label mt-1">AUTH / 01</p>
        </div>
      </RouterLink>
      <nav class="mt-10 grid gap-1">
        <RouterLink
          v-for="[path, label] in nav"
          :key="path"
          :to="path"
          class="rounded-md px-3 py-2 text-sm text-muted transition hover:bg-surface hover:text-fg"
          active-class="bg-surface text-fg"
        >
          {{ label }}
        </RouterLink>
      </nav>
    </aside>

    <section class="lg:pl-64">
      <header
        class="sticky top-0 z-10 flex min-h-16 items-center justify-between border-b border-border bg-bg/90 px-4 backdrop-blur md:px-8"
      >
        <RouterLink to="/account" class="flex items-center gap-3 lg:hidden">
          <img src="/brand/b3n-mark-no-bg.png" class="h-8 w-8" alt="B3n" />
          <span class="font-serif text-xl">GateKeeper</span>
        </RouterLink>
        <div class="hidden lg:block">
          <p class="mono-label">B3N AUTH CONTROL</p>
        </div>
        <RouterLink to="/login" class="btn-secondary text-sm">Sign out</RouterLink>
      </header>
      <RouterView />
    </section>
  </main>
</template>
