import type { components } from './schema'

type Schemas = components['schemas']
export type AccountView = Schemas['AccountView']
export type Device = Schemas['Device']
export type DeviceConfig = Schemas['DeviceConfig']
export type DeviceStatus = Schemas['DeviceStatus']
export type Interface = Schemas['Interface']
export type Problem = Schemas['Problem']
export type Session = Schemas['SessionView']

/** Error thrown when an API request returns a non-2xx HTTP status. */
export class ApiError extends Error {
  constructor(readonly problem: Problem) {
    super(problem.title)
  }
}

let csrfToken = ''

/** Sets the session CSRF token sent in `X-CSRF-Token` on all non-GET requests. */
export function setCsrfToken(token: string) {
  csrfToken = token
}

/**
 * Sends a request to `/api/v1{path}` with optional JSON `body` and `If-Match` `revision`, throwing
 * [`ApiError`] on non-2xx responses.
 */
export async function callApi<T = void>(
  method: string,
  path: string,
  { body, revision }: { body?: unknown; revision?: number } = {},
): Promise<T> {
  const headers: Record<string, string> = {}
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (revision !== undefined) headers['If-Match'] = `"${revision}"`
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    // Fall back to HTTP status text if a reverse proxy returned a non-JSON error body.
    const problem = await response
      .json()
      .catch(() => ({ title: response.statusText || `HTTP ${response.status}`, status: response.status }))
    throw new ApiError(problem)
  }
  return response.headers.get('content-type')?.includes('json') ? response.json() : (undefined as T)
}
