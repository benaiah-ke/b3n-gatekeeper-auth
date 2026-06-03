<script setup lang="ts">
import { FolderPlus, ListChecks } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api } from '@/services/api'
import type { AuthClient, Project, SetupStatus, Workspace } from '@/types'

const setup = ref<SetupStatus | null>(null)
const workspaces = ref<Workspace[]>([])
const projects = ref<Project[]>([])
const clients = ref<AuthClient[]>([])
const workspaceName = ref('Default workspace')
const workspaceSlug = ref('default')
const projectName = ref('Sentinel')
const projectSlug = ref('sentinel')
const projectAudience = ref('sentinel-api')
const selectedWorkspace = ref('')
const loading = ref(true)
const savingWorkspace = ref(false)
const savingProject = ref(false)
const error = ref('')

const activeOrgId = computed(() => setup.value?.org?.id || setup.value?.orgs[0]?.id || '')
const canManage = computed(() => Boolean(setup.value?.can_manage_projects))
const audienceSummaries = computed(() => {
  const summaries = new Map<string, { audience: string; clients: string[]; project?: string }>()
  for (const project of projects.value) {
    summaries.set(project.audience, { audience: project.audience, clients: [], project: project.name })
  }
  for (const client of clients.value) {
    for (const audience of client.audiences || []) {
      const existing = summaries.get(audience) || { audience, clients: [] }
      existing.clients.push(client.name)
      summaries.set(audience, existing)
    }
  }
  return Array.from(summaries.values()).sort((a, b) => a.audience.localeCompare(b.audience))
})

function slugify(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const setupStatus = await api.setupStatus()
    setup.value = setupStatus
    const orgId = setupStatus.org?.id
    const [workspaceRows, projectRows, clientRows] = await Promise.all([
      api.workspaces(orgId),
      api.projects(orgId),
      api.clients(),
    ])
    workspaces.value = workspaceRows
    projects.value = projectRows
    clients.value = clientRows
    selectedWorkspace.value = workspaceRows[0]?.id || ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not load projects'
  } finally {
    loading.value = false
  }
}

async function createWorkspace() {
  savingWorkspace.value = true
  error.value = ''
  try {
    await api.createWorkspace({
      org_id: activeOrgId.value,
      name: workspaceName.value,
      slug: workspaceSlug.value || slugify(workspaceName.value),
    })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create workspace'
  } finally {
    savingWorkspace.value = false
  }
}

async function createProject() {
  savingProject.value = true
  error.value = ''
  try {
    await api.createProject({
      org_id: activeOrgId.value,
      workspace_id: selectedWorkspace.value || null,
      name: projectName.value,
      slug: projectSlug.value || slugify(projectName.value),
      audience: projectAudience.value,
    })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Could not create project'
  } finally {
    savingProject.value = false
  }
}

onMounted(load)
</script>

<template>
  <section class="mx-auto max-w-6xl px-4 py-8 md:px-8">
    <p class="mono-label">Workspaces</p>
    <h1 class="mt-3 font-serif text-4xl leading-tight md:text-5xl">Projects and audiences</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-muted">
      Bind audiences to workspaces and projects before issuing project or machine credentials.
    </p>

    <article v-if="loading" class="panel mt-8 p-5 text-sm text-muted">Loading projects...</article>
    <article v-else-if="error" class="mt-6 rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
      {{ error }}
    </article>

    <div v-if="!loading" class="mt-8 grid gap-6">
      <article
        v-if="!canManage"
        class="rounded-md border border-orange/45 bg-orange/10 p-4 text-sm leading-6 text-orange"
      >
        This account can inspect workspaces and audiences but cannot create project records.
      </article>

      <div class="grid gap-4 md:grid-cols-3">
        <article class="panel p-5">
          <p class="text-sm text-muted">Workspaces</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ workspaces.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Projects</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ projects.length }}</h2>
        </article>
        <article class="panel p-5">
          <p class="text-sm text-muted">Audiences</p>
          <h2 class="mt-2 text-3xl font-semibold">{{ audienceSummaries.length }}</h2>
        </article>
      </div>

      <div class="grid gap-4 lg:grid-cols-2">
        <form class="panel grid gap-4 p-5" :class="{ 'opacity-60': !canManage }" @submit.prevent="createWorkspace">
          <div class="flex items-center gap-2">
            <FolderPlus class="h-4 w-4 text-accent" aria-hidden="true" />
            <h2 class="font-semibold">Create workspace</h2>
          </div>
          <input v-model="workspaceName" class="input" :disabled="!canManage" placeholder="Workspace name" required />
          <input v-model="workspaceSlug" class="input font-mono" :disabled="!canManage" placeholder="workspace-slug" required />
          <button class="btn-primary justify-self-start" :disabled="savingWorkspace || !canManage">
            {{ savingWorkspace ? 'Creating' : 'Create workspace' }}
          </button>
        </form>

        <form class="panel grid gap-4 p-5" :class="{ 'opacity-60': !canManage }" @submit.prevent="createProject">
          <div class="flex items-center gap-2">
            <ListChecks class="h-4 w-4 text-accent" aria-hidden="true" />
            <h2 class="font-semibold">Create project</h2>
          </div>
          <input v-model="projectName" class="input" :disabled="!canManage" placeholder="Project name" required />
          <input v-model="projectSlug" class="input font-mono" :disabled="!canManage" placeholder="project-slug" required />
          <input v-model="projectAudience" class="input font-mono" :disabled="!canManage" placeholder="project-api" required />
          <select v-model="selectedWorkspace" class="input" :disabled="!canManage">
            <option value="">No workspace</option>
            <option v-for="workspace in workspaces" :key="workspace.id" :value="workspace.id">{{ workspace.name }}</option>
          </select>
          <button class="btn-primary justify-self-start" :disabled="savingProject || !canManage">
            {{ savingProject ? 'Creating' : 'Create project' }}
          </button>
        </form>
      </div>

      <div class="grid gap-3">
        <p class="mono-label">Audience map</p>
        <article v-if="!audienceSummaries.length" class="panel p-4 text-sm text-muted">No audiences registered yet.</article>
        <article v-for="summary in audienceSummaries" v-else :key="summary.audience" class="panel p-4">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 class="break-all font-mono text-lg font-semibold">{{ summary.audience }}</h2>
              <p class="mt-2 text-sm text-muted">{{ summary.project || 'No project record' }}</p>
            </div>
            <span class="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted">
              {{ summary.clients.length }} clients
            </span>
          </div>
          <p class="mt-3 break-all font-mono text-xs text-muted">{{ summary.clients.join(', ') || 'No clients bound yet' }}</p>
        </article>
      </div>
    </div>
  </section>
</template>
