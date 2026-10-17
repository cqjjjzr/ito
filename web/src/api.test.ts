import { afterEach, describe, expect, test, vi } from 'vitest'
import { ApiError, callApi, setCsrfToken } from './api'

/** Answers every request with `response` and returns the fetch spy. */
function stubFetch(response: () => Response) {
  const fetch = vi.fn(async (_url: string, _init: RequestInit) => response())
  vi.stubGlobal('fetch', fetch)
  return fetch
}

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrfToken('')
})

describe('API client', () => {
  test('writes send the CSRF token, JSON body and revision', async () => {
    const fetch = stubFetch(() => new Response(null, { status: 204 }))
    setCsrfToken('token')
    await callApi('PATCH', '/devices/d', { body: { note: '' }, revision: 4 })
    expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/v1/devices/d', {
      method: 'PATCH',
      headers: { 'X-CSRF-Token': 'token', 'Content-Type': 'application/json', 'If-Match': '"4"' },
      body: '{"note":""}',
    })
  })

  test('reads send no CSRF token', async () => {
    const fetch = stubFetch(() => Response.json([]))
    setCsrfToken('token')
    await callApi('GET', '/devices')
    expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/v1/devices', { method: 'GET', headers: {}, body: undefined })
  })

  test('JSON responses resolve to their body', async () => {
    stubFetch(() => Response.json({ id: 'a' }))
    expect(await callApi('GET', '/session')).toEqual({ id: 'a' })
  })

  test('empty responses resolve to undefined', async () => {
    stubFetch(() => new Response(null, { status: 204 }))
    expect(await callApi('POST', '/auth/logout')).toBeUndefined()
  })

  test('problem responses reject with the problem', async () => {
    const problem = { title: 'Stale', status: 412, code: 'revision_conflict' }
    stubFetch(() => Response.json(problem, { status: 412 }))
    const call = callApi('GET', '/devices')
    await expect(call).rejects.toBeInstanceOf(ApiError)
    await expect(call).rejects.toMatchObject({ problem })
  })

  test.each([
    ['its reason phrase', 'Bad Gateway', 'Bad Gateway'],
    ['its status without a reason phrase', '', 'HTTP 502'],
  ])('a non-JSON error page is named by %s', async (_case, statusText, title) => {
    stubFetch(() => new Response('<html></html>', { status: 502, statusText }))
    await expect(callApi('GET', '/devices')).rejects.toMatchObject({ problem: { title, status: 502 } })
  })
})
