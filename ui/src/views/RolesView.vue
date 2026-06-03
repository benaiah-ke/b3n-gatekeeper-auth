<template>
  <section class="mx-auto max-w-6xl px-4 py-10 md:px-8">
    <p class="mono-label">RBAC</p>
    <h1 class="mt-3 font-serif text-5xl">Roles</h1>
    <div class="mt-8 grid gap-3">
      <article v-for="role in ['owner', 'admin', 'operator', 'viewer']" :key="role" class="panel p-4">
        <h2 class="capitalize">{{ role }}</h2>
      </article>
    </div>
  </section>
</template>

