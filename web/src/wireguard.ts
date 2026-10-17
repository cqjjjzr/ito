import type { Device, DeviceConfig } from './api'

/** Converts an unpadded base64url string (from JWK) into standard padded base64 for WireGuard. */
function convertBase64Url(text: string): string {
  const base64 = text.replaceAll('-', '+').replaceAll('_', '/')
  return base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
}

/** Returns the address width in bits (32 for IPv4, 128 for IPv6). */
export function countAddressBits(address: string): number {
  return address.includes(':') ? 128 : 32
}

/** Formats an IPv4 or IPv6 host address as a `/32` or `/128` CIDR prefix. */
export function buildHostPrefix(address: string): string {
  return `${address}/${countAddressBits(address)}`
}

/** Returns `device.grants` excluding the `/32` and `/128` host prefixes of `device.client_addresses`. */
export function listAdditionalGrants(device: Pick<Device, 'grants' | 'client_addresses'>): string[] {
  const own = device.client_addresses.map(buildHostPrefix)
  return device.grants.filter((g) => !own.includes(g))
}

/**
 * Derives a `wg-quick`-compatible `.conf` filename (at most 15 ASCII characters before `.conf`)
 * from a device display name.
 */
export function buildConfigFileName(name: string): string {
  const base = name
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .replace(/[^\w=+.-]+/g, '-')
    .replace(/^-+/, '')
    .slice(0, 15)
    .replace(/-+$/, '')
  return `${base || 'ito'}.conf`
}

/** Base64-encoded WireGuard X25519 key pair. */
export interface KeyPair {
  privateKey: string
  publicKey: string
}

/** Returns `crypto.subtle`, which browsers expose only in secure contexts (HTTPS or `localhost`). */
function requireSubtle(): SubtleCrypto {
  if (!crypto.subtle) throw new Error('This browser makes keys only for portals served over HTTPS.')
  return crypto.subtle
}

function rejectNoX25519(): never {
  throw new Error('This browser cannot make WireGuard keys; use a current one.')
}

/** Accepts nonzero 32-byte keys in canonical standard base64, matching the server. */
export function isValidKey(value: string): boolean {
  const text = value.trim()
  if (!/^[A-Za-z0-9+/]{43}=$/.test(text)) return false
  const bytes = atob(text)
  return btoa(bytes) === text && [...bytes].some((c) => c.charCodeAt(0) !== 0)
}

/** Generates a private key or PSK using the browser's cryptographic random source. */
export function generateKey(): string {
  const bytes = new Uint8Array(32)
  do { crypto.getRandomValues(bytes) } while (bytes.every((b) => b === 0))
  return btoa(String.fromCharCode(...bytes))
}

/** ASN.1 DER prefix for a 32-byte X25519 private key in PKCS #8 format. */
const X25519_PKCS8_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]

/** Validates a base64 WireGuard private key and derives its corresponding public key via Web Crypto. */
export async function importKeyPair(privateKey: string): Promise<KeyPair> {
  const subtle = requireSubtle()
  const text = privateKey.trim()
  if (!isValidKey(text)) throw new Error('Enter or generate a valid WireGuard private key (32 bytes, not all zero in canonical base64).')
  const pkcs8 = new Uint8Array([...X25519_PKCS8_PREFIX, ...Array.from(atob(text), (c) => c.charCodeAt(0))])
  const key = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']).catch(rejectNoX25519)
  const jwk = await subtle.exportKey('jwk', key)
  return { privateKey: text, publicKey: convertBase64Url(jwk.x!) }
}

/** Renders a `wg-quick` configuration file for `c` using `privateKey` and route profile `profileId`. */
export function buildWgConfig(c: DeviceConfig, privateKey: string, profileId: string): string {
  const allowedIps = c.route_profiles.find((p) => p.id === profileId)?.allowed_ips ?? []
  const dns = [...c.dns, ...c.dns_search]
  return [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${c.addresses.map(buildHostPrefix).join(', ')}`,
    dns.length ? `DNS = ${dns.join(', ')}` : null,
    c.mtu ? `MTU = ${c.mtu}` : null,
    '',
    '[Peer]',
    `PublicKey = ${c.server_public_key}`,
    c.preshared_key ? `PresharedKey = ${c.preshared_key}` : null,
    `Endpoint = ${c.endpoint}`,
    `AllowedIPs = ${allowedIps.join(', ')}`,
    c.keepalive ? `PersistentKeepalive = ${c.keepalive}` : null,
    '',
  ]
    .filter((line) => line !== null)
    .join('\n')
}
