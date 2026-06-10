<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '@/services/api'
import type { Org } from '@/types'

const router = useRouter()
const orgs = ref<Org[]>([])
const activeOrgId = ref('')
const loading = ref(true)
const error = ref('')
const switchingOrgId = ref('')

onMounted(async () => {
  try {
    const [orgRows, status] = await Promise.all([api.orgs(), api.setupStatus()])
    orgs.value = orgRows
    activeOrgId.value = status.org?.id || ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load organizations'
  } finally {
    loading.value = false
  }
})

async function switchOrg(org: Org) {
  error.value = ''
  switchingOrgId.value = org.id
  try {
    const response = await api.switchOrg({ org_id: org.id })
    activeOrgId.value = org.id
    orgs.value = response.orgs || orgs.value
    await router.push('/account')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not switch organization'
  } finally {
    switchingOrgId.value = ''
  }
}
</script>

<template>
  <section class="mx-auto max-w-4xl px-4 py-10 md:px-8">
    <p class="mono-label">Organizations</p>
    <h1 class="mt-3 text-2xl font-semibold leading-tight">Select org</h1>
    <div class="mt-8 grid gap-3">
      <article v-if="loading" class="panel p-4 text-sm text-muted">Loading organizations...</article>
      <article v-else-if="error" class="rounded-md border border-red/40 bg-red/10 p-4 text-sm text-red">
        {{ error }}
      </article>
      <article v-else-if="!orgs.length" class="panel p-4 text-sm text-muted">No organizations available.</article>
      <template v-else>
        <button
          v-for="org in orgs"
          :key="org.id"
          type="button"
          class="panel flex min-h-20 items-center justify-between gap-4 p-4 text-left transition hover:border-border-active"
          :disabled="switchingOrgId === org.id"
          @click="switchOrg(org)"
        >
          <span class="min-w-0">
            <span class="block truncate font-medium">{{ org.name }}</span>
            <span class="mt-1 block font-mono text-xs text-muted">{{ org.slug }}</span>
          </span>
          <span class="flex shrink-0 items-center gap-3">
            <span v-if="activeOrgId === org.id" class="rounded border border-green/30 bg-green/10 px-2 py-1 text-xs text-green">
              Active
            </span>
            <span class="font-mono text-xs text-muted">{{ switchingOrgId === org.id ? 'switching' : org.role || 'member' }}</span>
          </span>
        </button>
      </template>
    </div>
  </section>
</template>
