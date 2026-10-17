import { ref } from 'vue'
import { ApiError, callApi, setCsrfToken, type Session } from './api'

/** The browser session: `undefined` until loaded, `null` when signed out. */
export const session = ref<Session | null>()

export async function loadSession() {
  try {
    session.value = await callApi<Session>('GET', '/session')
    setCsrfToken(session.value.csrf_token)
  } catch (e) {
    if (!(e instanceof ApiError && e.problem.status === 401)) throw e
    session.value = null
  }
}

/** Ends the local session, then visits provider logout confirmation when available. */
export async function signOut() {
  let redirect = '/'
  try {
    const result = await callApi<{ redirect_url: string }>('POST', '/auth/logout')
    redirect = result.redirect_url
  } finally {
    location.assign(redirect)
  }
}
