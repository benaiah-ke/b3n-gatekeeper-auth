import { createRouter, createWebHistory } from 'vue-router'

import AccountView from '@/views/AccountView.vue'
import AcceptInviteView from '@/views/AcceptInviteView.vue'
import AuthorizeView from '@/views/AuthorizeView.vue'
import AuditView from '@/views/AuditView.vue'
import ClientsView from '@/views/ClientsView.vue'
import DeviceLoginView from '@/views/DeviceLoginView.vue'
import GrantsView from '@/views/GrantsView.vue'
import InvitationsView from '@/views/InvitationsView.vue'
import LoginView from '@/views/LoginView.vue'
import OrgSelectView from '@/views/OrgSelectView.vue'
import PolicyView from '@/views/PolicyView.vue'
import ProjectsView from '@/views/ProjectsView.vue'
import ProvidersView from '@/views/ProvidersView.vue'
import ResetPasswordView from '@/views/ResetPasswordView.vue'
import RolesView from '@/views/RolesView.vue'
import SessionsView from '@/views/SessionsView.vue'
import SignupView from '@/views/SignupView.vue'
import TokensView from '@/views/TokensView.vue'
import UsersView from '@/views/UsersView.vue'
import VerifyView from '@/views/VerifyView.vue'
import { gatekeeperApiUrl, hasAuthenticatedSession } from '@/services/api'
import { safeInternalRedirect } from '@/services/redirects'

const publicRoutes = new Set(['/login', '/signup', '/verify', '/reset-password', '/device', '/accept-invite'])

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/account' },
    { path: '/login', component: LoginView },
    { path: '/signup', component: SignupView },
    { path: '/accept-invite', component: AcceptInviteView },
    { path: '/verify', component: VerifyView },
    { path: '/reset-password', component: ResetPasswordView },
    { path: '/device', component: DeviceLoginView },
    { path: '/authorize', component: AuthorizeView },
    { path: '/select-org', component: OrgSelectView },
    { path: '/account', component: AccountView },
    { path: '/users', component: UsersView },
    { path: '/invitations', component: InvitationsView },
    { path: '/sessions', component: SessionsView },
    { path: '/grants', component: GrantsView },
    { path: '/tokens', component: TokensView },
    { path: '/clients', component: ClientsView },
    { path: '/providers', component: ProvidersView },
    { path: '/policy', component: PolicyView },
    { path: '/projects', component: ProjectsView },
    { path: '/roles', component: RolesView },
    { path: '/audit', component: AuditView },
  ],
})

router.beforeEach(async (to) => {
  const isPublic = publicRoutes.has(to.path)
  const isAuthenticated = await hasAuthenticatedSession()

  if (!isPublic && !isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }

  if ((to.path === '/login' || to.path === '/signup') && isAuthenticated && to.query.step_up !== 'mfa') {
    const redirect = safeInternalRedirect(to.query.redirect)
    if (redirect.startsWith('/oauth/')) {
      window.location.assign(gatekeeperApiUrl(redirect))
      return false
    }
    return redirect || { path: '/account' }
  }

  return true
})

export default router
