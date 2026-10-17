import { afterEach, describe, expect, test, vi } from 'vitest'
import { callApi, setCsrfToken } from './api'
import { loadSession, session, signOut } from './session'

afterEach(() => {
  vi.unstubAllGlobals()
  session.value = undefined
  setCsrfToken('')
})

describe('browser sessions', () => {
  test('a loaded session supplies the CSRF token for later writes', async () => {
    const signedIn = { account_id: 'a', admin: false, csrf_token: 'token' }
    vi.stubGlobal('fetch', async () => Response.json(signedIn))
    await loadSession()
    expect(session.value).toEqual(signedIn)
    const fetch = vi.fn(async (_url: string, _init: RequestInit) => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetch)
    await callApi('POST', '/auth/logout')
    expect(fetch.mock.calls[0]![1].headers).toEqual({ 'X-CSRF-Token': 'token' })
  })

  test('an expired session becomes signed out', async () => {
    vi.stubGlobal('fetch', async () => Response.json({ status: 401, title: 'Expired' }, { status: 401 }))
    await loadSession()
    expect(session.value).toBeNull()
  })

  test('a failing session load rethrows and leaves the session unknown', async () => {
    vi.stubGlobal('fetch', async () => Response.json({ status: 503, title: 'Unavailable' }, { status: 503 }))
    await expect(loadSession()).rejects.toMatchObject({ problem: { status: 503 } })
    expect(session.value).toBeUndefined()
  })

  test.each(['/', 'https://idp.test/logout?client_id=ito'])('signing out navigates to %s', async (redirect) => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign })
    vi.stubGlobal('fetch', async () => Response.json({ redirect_url: redirect }))
    await signOut()
    expect(assign).toHaveBeenCalledExactlyOnceWith(redirect)
  })

  test.each([
    ['an expired session', 401],
    ['an unavailable server', 503],
  ])('a logout refused by %s still navigates home and rethrows', async (_case, status) => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign })
    vi.stubGlobal('fetch', async () => new Response(null, { status }))
    await expect(signOut()).rejects.toMatchObject({ problem: { status } })
    expect(assign).toHaveBeenCalledExactlyOnceWith('/')
  })
})
