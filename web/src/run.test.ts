import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { ApiError } from './api'
import { useRun } from './run'

const toast = vi.hoisted(() => ({ add: vi.fn() }))
vi.mock('@nuxt/ui/composables', () => ({ useToast: () => toast }))

const assign = vi.fn()
beforeEach(() => vi.stubGlobal('location', { assign }))
afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('actions run from pages', () => {
  test('an unauthorized action sends the browser home without a toast', async () => {
    const run = useRun()
    const expired = new ApiError({ type: 'about:blank', title: 'Expired', status: 401, code: 'invalid_credentials' })
    expect(await run(() => Promise.reject(expired))).toBeUndefined()
    expect(assign).toHaveBeenCalledExactlyOnceWith('/')
    expect(toast.add).not.toHaveBeenCalled()
  })

  test.each([
    [
      'an API problem shows its title, detail and request',
      new ApiError({ type: 'about:blank', title: 'Stale', status: 412, code: 'revision_conflict', detail: 'Reload first.', instance: 'urn:uuid:1' }),
      { title: 'Stale', description: 'Reload first.\nurn:uuid:1', color: 'error' },
    ],
    ['another error shows its message', new Error('No network'), { title: 'No network', description: '', color: 'error' }],
  ])('%s as an error toast', async (_case, error, shown) => {
    const run = useRun()
    expect(await run(() => Promise.reject(error), 'Saved')).toBeUndefined()
    expect(toast.add).toHaveBeenCalledExactlyOnceWith(shown)
    expect(assign).not.toHaveBeenCalled()
  })

  test.each([
    ['its success message is toasted', 'Saved', [[{ title: 'Saved', color: 'success' }]]],
    ['nothing is toasted without a success message', undefined, []],
  ])('a successful action returns its result: %s', async (_case, success, toasts) => {
    const run = useRun()
    expect(await run(async () => 7, success)).toBe(7)
    expect(toast.add.mock.calls).toEqual(toasts)
  })
})
