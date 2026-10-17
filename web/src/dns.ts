/**
 * Normalizes a device display name into a valid DNS label (up to 63 lowercase ASCII letters,
 * digits, and interior hyphens).
 */
export function buildDnsLabel(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+/, '')
    .slice(0, 63)
    .replace(/-+$/, '')
}
