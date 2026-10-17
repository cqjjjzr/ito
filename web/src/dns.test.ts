import { describe, expect, test } from 'vitest'
import { buildDnsLabel } from './dns'

describe('device DNS labels', () => {
  test.each([
    ['punctuation becomes dashes', "Alice's MacBook Pro", 'alice-s-macbook-pro'],
    ['accents and edge dashes are dropped', ' -Café_Zürich- ', 'cafe-zurich'],
    ['names without ASCII give no label', '日本', ''],
    ['empty names give no label', '', ''],
    ['labels are cut to 63 characters without a trailing dash', 'a'.repeat(62) + ' b', 'a'.repeat(62)],
  ])('%s', (_case, name, label) => expect(buildDnsLabel(name)).toBe(label))
})
