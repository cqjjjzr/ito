import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { effectScope } from 'vue'
import { isDeviceChanging, usePolling } from './polling'

const applying = { revision: 2, applied_revision: 1, deleting: false }
const deleting = { revision: 2, applied_revision: 2, deleting: true }
const settled = { revision: 2, applied_revision: 2, deleting: false }

/** Starts polling in a scope standing in for the page; `load` returns each list in turn, then the last. */
function startPolling(...lists: (typeof settled)[][]) {
  let devices: (typeof settled)[] = []
  const load = vi.fn(async () => {
    devices = lists.length > 1 ? lists.shift()! : lists[0]!
  })
  const scope = effectScope()
  const reload = scope.run(() => usePolling(load, () => devices.some(isDeviceChanging)))!
  return { load, reload, scope }
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('device polling', () => {
  test.each([
    ['an applying device', applying],
    ['a deleting device', deleting],
  ])('%s is loaded again two seconds later', async (_case, device) => {
    const { load, reload } = startPolling([device])
    await reload()
    await vi.advanceTimersByTimeAsync(1999)
    expect(load).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(load).toHaveBeenCalledTimes(2)
  })

  test('polling stops once every device is settled', async () => {
    const { load, reload } = startPolling([applying], [deleting, settled], [settled])
    await reload()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(load).toHaveBeenCalledTimes(3)
  })

  test('a reload replaces the pending repeat', async () => {
    const { load, reload } = startPolling([applying])
    await reload()
    await vi.advanceTimersByTimeAsync(1000)
    await reload()
    await vi.advanceTimersByTimeAsync(1999)
    expect(load).toHaveBeenCalledTimes(2)
  })

  test('closing the page cancels the pending repeat', async () => {
    const { load, reload, scope } = startPolling([applying])
    await reload()
    scope.stop()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(load).toHaveBeenCalledTimes(1)
  })

  test('a load that finishes after the page closed does not repeat', async () => {
    let finishLoad!: () => void
    const load = vi.fn(() => new Promise<void>((resolve) => (finishLoad = resolve)))
    const scope = effectScope()
    const reload = scope.run(() => usePolling(load, () => true))!
    const loading = reload()
    scope.stop()
    finishLoad()
    await loading
    await vi.advanceTimersByTimeAsync(60_000)
    expect(load).toHaveBeenCalledTimes(1)
  })
})
