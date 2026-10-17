import { ref } from 'vue'
import type { Problem } from './api'

/** Full-page RFC 9457 Problem Details displayed in place of router views (for example, on OIDC callback failure). */
export const pageProblem = ref<Partial<Problem>>()

/**
 * Reads the RFC 9457 Problem Details embedded in `<meta name="ito-problem">` on error pages.
 * Returns `undefined` on normal pages, or a fallback problem if the tag content is not valid JSON.
 */
export function readEmbeddedProblem(): Partial<Problem> | undefined {
  const content = document.querySelector<HTMLMetaElement>('meta[name="ito-problem"]')?.content
  if (content === undefined) return undefined
  try {
    return JSON.parse(content) as Partial<Problem>
  } catch {
    return { title: 'Ito is down.', detail: 'The server could not describe the error. Try again later.' }
  }
}
