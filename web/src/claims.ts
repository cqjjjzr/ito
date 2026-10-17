/**
 * Formats the first eight hex digits of a 64-character request ID as an uppercase verification
 * code (`XXXX-XXXX`).
 */
export function formatCheckCode(requestId: string): string {
  const head = requestId.slice(0, 8).toUpperCase()
  return `${head.slice(0, 4)}-${head.slice(4)}`
}

/** Returns true if `requestId` is a 64-digit lowercase hex SHA-256 digest and timestamp `requestedAt` is within 15 minutes of `now`. */
export function isApprovable(requestId: string, requestedAt: number, now = Date.now() / 1000): boolean {
  const age = now - requestedAt
  return /^[0-9a-f]{64}$/.test(requestId) && age < 15 * 60 && age > -60
}
