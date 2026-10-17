import { onScopeDispose } from 'vue'
import type { Device } from './api'

/** Returns true while the server is still applying a change to `d` or deleting it. */
export function isDeviceChanging(d: Pick<Device, 'revision' | 'applied_revision' | 'deleting'>): boolean {
  return d.applied_revision !== d.revision || d.deleting
}

/**
 * Returns `reload`, which runs `load` and runs it again every two seconds while `shouldRepeat()`
 * holds. Calling `reload` again replaces the pending repeat; closing the page stops it.
 */
export function usePolling(load: () => Promise<unknown>, shouldRepeat: () => boolean) {
  let timer: ReturnType<typeof setTimeout> | undefined
  // A load still running when the page closes must not start the timer again.
  let closed = false
  async function reload() {
    clearTimeout(timer)
    await load()
    if (!closed && shouldRepeat()) timer = setTimeout(reload, 2000)
  }
  onScopeDispose(() => {
    closed = true
    clearTimeout(timer)
  })
  return reload
}
