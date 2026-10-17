import { afterEach, describe, expect, test, vi } from 'vitest'
import { readEmbeddedProblem } from './problem'

const fallback = { title: 'Ito is down.', detail: 'The server could not describe the error. Try again later.' }

afterEach(() => vi.unstubAllGlobals())

describe('embedded problem pages', () => {
  test.each([
    ['a normal page has none', undefined, undefined],
    ['a problem page has its problem', '{"title":"Unavailable","status":503}', { title: 'Unavailable', status: 503 }],
    ['an empty tag falls back to a generic problem', '', fallback],
    ['a tag without JSON falls back to a generic problem', '<html>', fallback],
  ])('%s', (_case, content, problem) => {
    vi.stubGlobal('document', { querySelector: () => (content === undefined ? null : { content }) })
    expect(readEmbeddedProblem()).toEqual(problem)
  })
})
