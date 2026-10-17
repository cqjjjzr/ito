import { useToast } from '@nuxt/ui/composables'
import { ApiError, type Problem } from './api'

/**
 * Returns an async wrapper that executes `action`, displays a toast on error (or on success if
 * `success` is provided), and redirects to `/` on `401 Unauthorized`.
 */
export function useRun() {
  const toast = useToast()
  return async function run<T>(action: () => Promise<T>, success?: string): Promise<T | undefined> {
    try {
      const result = await action()
      if (success) toast.add({ title: success, color: 'success' })
      return result
    } catch (e) {
      const problem: Partial<Problem> = e instanceof ApiError ? e.problem : { title: e instanceof Error ? e.message : String(e) }
      if (problem.status === 401) return void location.assign('/')
      const { title, detail, instance } = problem
      toast.add({ title, description: [detail, instance].filter(Boolean).join('\n'), color: 'error' })
    }
  }
}
