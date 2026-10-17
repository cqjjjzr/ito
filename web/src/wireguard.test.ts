import { afterEach, describe, expect, test, vi } from 'vitest'
import type { DeviceConfig } from './api'
import { buildConfigFileName, buildWgConfig, countAddressBits, generateKey, importKeyPair, isValidKey, listAdditionalGrants } from './wireguard'

const config = {
  addresses: ['10.0.0.2', 'fd00::2'],
  dns: ['10.0.0.1'],
  dns_search: ['vpn.test'],
  mtu: 0,
  keepalive: 25,
  server_public_key: 'SERVER=',
  preshared_key: '',
  endpoint: 'vpn.test:51820',
  route_profiles: [
    { id: 'all', name: 'All', allowed_ips: ['0.0.0.0/0', '::/0'] },
    { id: 'vpn', name: 'VPN', allowed_ips: ['10.0.0.0/24'] },
  ],
  default_profile_id: 'vpn',
} as unknown as DeviceConfig

afterEach(() => vi.unstubAllGlobals())

describe('WireGuard keys and configuration', () => {
  test('generated secrets are distinct, valid 32-byte base64 values', () => {
    const a = generateKey(), b = generateKey()
    expect(atob(a)).toHaveLength(32)
    expect(isValidKey(a)).toBe(true)
    expect(isValidKey(b)).toBe(true)
    expect(a).not.toBe(b)
  })

  test.each(['', ' ', 'not a key', btoa('short'), btoa('x'.repeat(33)), btoa('\0'.repeat(32)), `${btoa('x'.repeat(32)).slice(0, -2)}B=`])(
    'invalid or noncanonical keys are refused: %j', async (key) => {
      expect(isValidKey(key)).toBe(false)
      await expect(importKeyPair(key)).rejects.toThrow('valid WireGuard private key')
    },
  )

  test('an imported private key yields its public key', async () => {
    // The key pair of Alice in RFC 7748, section 6.1.
    const privateKey = 'dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo='
    expect(await importKeyPair(` ${privateKey}\n`)).toEqual({ privateKey, publicKey: 'hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=' })
  })

  test('a generated secret can be imported as a private key', async () => {
    const privateKey = generateKey()
    const pair = await importKeyPair(privateKey)
    expect(pair.privateKey).toBe(privateKey)
    expect(isValidKey(pair.publicKey)).toBe(true)
    expect(await importKeyPair(` ${privateKey}\n`)).toEqual(pair)
  })

  test('a page without Web Crypto explains why it cannot import private keys', async () => {
    const key = generateKey()
    vi.stubGlobal('crypto', {})
    await expect(importKeyPair(key)).rejects.toThrow('only for portals served over HTTPS')
  })

  test('the configuration uses the chosen profile and leaves out unset hints', () => {
    expect(buildWgConfig(config, 'PRIVATE=', 'all')).toBe(`[Interface]
PrivateKey = PRIVATE=
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.0.0.1, vpn.test

[Peer]
PublicKey = SERVER=
Endpoint = vpn.test:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`)
  })

  test('the configuration carries a set MTU and preshared key', () => {
    const text = buildWgConfig({ ...config, mtu: 1380, preshared_key: 'PSK=' }, 'PRIVATE=', 'vpn')
    expect(text).toContain('DNS = 10.0.0.1, vpn.test\nMTU = 1380\n\n[Peer]\n')
    expect(text).toContain('PublicKey = SERVER=\nPresharedKey = PSK=\nEndpoint')
  })

  test('an unknown profile routes nothing', () => {
    expect(buildWgConfig(config, 'PRIVATE=', 'gone')).toContain('\nAllowedIPs = \n')
  })

  test.each([
    ['punctuation becomes dashes', "Alice's  Phone", 'Alice-s-Phone.conf'],
    ['accents are dropped', ' -Café Zürich- ', 'Cafe-Zurich.conf'],
    ['long names are cut to 15 characters', 'a very long device name', 'a-very-long-dev.conf'],
    ['names without ASCII fall back to ito', '日本', 'ito.conf'],
  ])('configuration file names suit wg-quick: %s', (_case, name, fileName) => {
    expect(buildConfigFileName(name)).toBe(fileName)
  })

  test.each([['10.0.0.2', 32], ['10.0.0.0/24', 32], ['fd00::2', 128], ['fd00::/64', 128]])(
    'the address width of %s is %i bits', (address, bits) => expect(countAddressBits(address)).toBe(bits),
  )

  test('additional grants leave out only the device host prefixes', () => {
    expect(listAdditionalGrants({
      client_addresses: ['10.0.0.2', 'fd00::2'],
      grants: ['10.0.0.2/32', 'fd00::2/128', '10.0.1.0/24', 'fd00:1::/64'],
    })).toEqual(['10.0.1.0/24', 'fd00:1::/64'])
  })
})
