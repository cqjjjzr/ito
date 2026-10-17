import { describe, expect, test } from 'vitest'
import { formatCheckCode, isApprovable } from './claims'

const requestId = '3f9a1c2e' + '0'.repeat(56)

describe('agent approval requests', () => {
  test('the verification code shows the leading digest bytes', () => {
    expect(formatCheckCode(requestId)).toBe('3F9A-1C2E')
  })

  test.each([
    ['a fresh request is approvable', 0, true],
    ['a request within its lifetime is approvable', 899, true],
    ['a request at expiry is refused', 900, false],
    ['an expired request is refused', 901, false],
    ['a request within the clock skew is approvable', -59, true],
    ['a request at the clock-skew limit is refused', -60, false],
    ['a request with an invalid time is refused', NaN, false],
  ])('%s', (_case, age, approvable) => {
    expect(isApprovable(requestId, 1000, 1000 + age)).toBe(approvable)
  })

  test.each([
    ['empty', ''],
    ['not hex', 'not hex'],
    ['too short', requestId.slice(1)],
    ['too long', requestId + '0'],
    ['uppercase', requestId.toUpperCase()],
  ])('a malformed request ID is refused: %s', (_case, id) => expect(isApprovable(id, 1000, 1000)).toBe(false))
})
