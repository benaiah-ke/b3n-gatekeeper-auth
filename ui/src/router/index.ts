import { createRouter, createWebHistory } from 'vue-router'

import AccountView from '@/views/AccountView.vue'
import AuditView from '@/views/AuditView.vue'
import ClientsView from '@/views/ClientsView.vue'
import DeviceLoginView from '@/views/DeviceLoginView.vue'
import LoginView from '@/views/LoginView.vue'
import OrgSelectView from '@/views/OrgSelectView.vue'
import ProjectsView from '@/views/ProjectsView.vue'
import ResetPasswordView from '@/views/ResetPasswordView.vue'
import RolesView from '@/views/RolesView.vue'
import SessionsView from '@/views/SessionsView.vue'
import SignupView from '@/views/SignupView.vue'
import TokensView from '@/views/TokensView.vue'
import VerifyView from '@/views/VerifyView.vue'
import { getAccessToken, getRefreshToken, hasAuthenticatedSession } from '@/services/api'

const publicRoutes = new Set(['/login', '/signup', '/verify', '/reset-password', '/device'])

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/account' },
    { path: '/login', component: LoginView },
    { path: '/signup', component: SignupView },
    { path: '/verify', component: VerifyView },
    { path: '/reset-password', component: ResetPasswordView },
    { path: '/device', component: DeviceLoginView },
    { path: '/select-org', component: OrgSelectView },
    { path: '/account', component: AccountView },
    { path: '/sessions', component: SessionsView },
    { path: '/tokens', component: TokensView },
    { path: '/clients', component: ClientsView },
    { path: '/projects', component: ProjectsView },
    { path: '/roles', component: RolesView },
    { path: '/audit', component: AuditView },
  ],
})

router.beforeEach(async (to) => {
  const hasLocalSession = Boolean(getAccessToken() || getRefreshToken())
  const isPublic = publicRoutes.has(to.path)

  if (!isPublic && !hasLocalSession && !(await hasAuthenticatedSession())) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }

  if (to.path === '/login' && hasLocalSession) {
    return { path: '/account' }
  }

  return true
})

export default router
