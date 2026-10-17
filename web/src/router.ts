import { createRouter, createWebHistory } from 'vue-router'
import Welcome from './pages/Welcome.vue'
import { ApiError } from './api'
import { pageProblem } from './problem'
import { loadSession, session } from './session'

declare module 'vue-router' {
  interface RouteMeta {
    /** Whether unauthenticated users can access the route. */
    public?: boolean
    /** Whether the route is restricted to administrators. */
    admin?: boolean
  }
}

/** Default route for signed-in users. */
const home = '/devices'
/** `sessionStorage` key preserving the pre-login target route across the OIDC redirect to `/`. */
const returnKey = 'ito-return'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: Welcome, meta: { public: true } },
    { path: '/devices', component: () => import('./pages/Devices.vue') },
    { path: '/networks', component: () => import('./pages/Networks.vue') },
    { path: '/accounts', component: () => import('./pages/Accounts.vue'), meta: { admin: true } },
    { path: '/account', component: () => import('./pages/Account.vue') },
    { path: '/connect', component: () => import('./pages/Connect.vue') },
    { path: '/:rest(.*)', redirect: '/' },
  ],
})

router.beforeEach(async (to) => {
  // Abort navigation if a full-page problem is already displayed.
  if (pageProblem.value) return false
  if (session.value === undefined) {
    try {
      await loadSession()
    } catch (e) {
      pageProblem.value = e instanceof ApiError ? e.problem : { title: 'Ito does not answer.', detail: String(e) }
      return false
    }
  }
  if (to.meta.public) {
    if (!session.value) return true
    const back = sessionStorage.getItem(returnKey)
    sessionStorage.removeItem(returnKey)
    return back ?? home
  }
  if (!session.value) {
    sessionStorage.setItem(returnKey, to.fullPath)
    return '/'
  }
  return !to.meta.admin || session.value.admin || home
})
