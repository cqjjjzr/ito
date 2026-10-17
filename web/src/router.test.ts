import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import type { Session } from './api'

// The router keeps its place in memory instead of the browser address bar.
vi.mock('vue-router', async (importOriginal) => {
  const router = await importOriginal<typeof import('vue-router')>()
  return { ...router, createWebHistory: router.createMemoryHistory }
})

const member = { account_id: 'a', admin: false, csrf_token: 't' } as Session
const admin = { ...member, admin: true }

/** Imports a fresh router with its session and page problem, so no test sees another's place. */
async function importRouter() {
  vi.resetModules()
  const [{ router }, { session }, { pageProblem }] = await Promise.all([import('./router'), import('./session'), import('./problem')])
  const visit = async (path: string) => {
    await router.push(path)
    return router.currentRoute.value.fullPath
  }
  return { visit, session, pageProblem }
}

beforeEach(() => {
  const storage = new Map<string, string>()
  vi.stubGlobal('sessionStorage', {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
  })
})
afterEach(() => vi.unstubAllGlobals())

describe('router', () => {
  test('signed-out visitors land on the welcome page', async () => {
    const { visit, session } = await importRouter()
    session.value = null
    expect(await visit('/networks')).toBe('/')
  })

  test('signing in returns to the page first asked for', async () => {
    const signedOut = await importRouter()
    signedOut.session.value = null
    await signedOut.visit('/networks')
    // The identity provider sends the browser back to the welcome page, which loads anew.
    const signedIn = await importRouter()
    signedIn.session.value = member
    expect(await signedIn.visit('/')).toBe('/networks')
  })

  test('signed-in visitors skip the welcome page', async () => {
    const { visit, session } = await importRouter()
    session.value = member
    expect(await visit('/')).toBe('/devices')
  })

  test.each([
    ['members are sent to their devices', member, '/devices'],
    ['administrators are let in', admin, '/accounts'],
  ])('on admin routes, %s', async (_case, user, landing) => {
    const { visit, session } = await importRouter()
    session.value = user
    expect(await visit('/accounts')).toBe(landing)
  })

  test.each([
    [
      'a problem answer shows that problem',
      async () => Response.json({ title: 'Unavailable', status: 503 }, { status: 503 }),
      { title: 'Unavailable', status: 503 },
    ],
    [
      'an unreachable server shows that Ito does not answer',
      async () => Promise.reject(new TypeError('Failed to fetch')),
      { title: 'Ito does not answer.', detail: 'TypeError: Failed to fetch' },
    ],
  ])('a failing session load stops navigation: %s', async (_case, fetch, problem) => {
    vi.stubGlobal('fetch', fetch)
    const { visit, pageProblem } = await importRouter()
    expect(await visit('/devices')).toBe('/')
    expect(pageProblem.value).toEqual(problem)
  })

  test('a shown problem page blocks navigation', async () => {
    const { visit, session, pageProblem } = await importRouter()
    session.value = member
    pageProblem.value = { title: 'The sign-in did not complete.' }
    expect(await visit('/devices')).toBe('/')
  })
})
