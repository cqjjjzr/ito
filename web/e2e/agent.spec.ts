import { expect } from '@playwright/test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { agentBinary as binary, signIn, test, startAgent, startClient } from './helpers'

test('a script logs the Linux agent in, which connects, rotates and logs out', async ({ page }) => {
  await signIn(page, 'alice')
  await page.getByRole('button', { name: 'New device' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Agent Box')
  await page.getByRole('button', { name: 'Generate private key', exact: true }).click()
  await page.getByRole('button', { name: 'Generate preshared key', exact: true }).click()
  await page.getByRole('button', { name: 'Create' }).click()
  await page.getByRole('button', { name: 'Done' }).click()
  const devices: { id: string; name: string }[] = await (await page.request.get('/api/v1/devices')).json()
  const device = devices.find((d) => d.name === 'Agent Box')!.id

  const client = await startClient()
  try {
    // Reach the portal over the E2E virtual network.
    const state = mkdtempSync(join(tmpdir(), 'ito-agent-'))
    const login = ['--state-dir', state, 'login', '--no-dns', 'http://10.99.0.1:8000', '--device', device, '--connect', '--json']
    const started = startAgent(client.pid, login)
    // Approve the login request through the HTTP API using the browser session.
    const { request, requested_at } = await started.readRequest()
    const { csrf_token } = await (await page.request.get('/api/v1/session')).json()
    const headers = { 'x-csrf-token': csrf_token, origin: new URL(page.url()).origin }
    const approved = await page.request.post(`/api/v1/devices/${device}/claims`, { headers, data: { id: request, t: requested_at } })
    expect(approved.status()).toBe(204)
    const outcome = JSON.parse((await started.waitForExit()).trim().split('\n').at(-1)!)
    const name: string = outcome.summary.name
    expect(name).toMatch(/^ito-[0-9a-f]{8}$/)
    expect(outcome.summary.state).toBe('connected')
    expect(outcome.summary.no_dns).toBe(true)
    const runAgent = (...args: string[]) => client.run(binary, '--state-dir', state, ...args)
    const pingServers = () => ['10.77.0.1', 'fd77::1'].forEach(client.ping)
    pingServers()
    const status = JSON.parse(runAgent('status', name, '--json'))
    expect(status.local.peers[0].handshake).not.toBeNull()
    expect(status.summary.device.name).toBe('Agent Box')

    runAgent('rotate-key', name)
    pingServers()
    runAgent('rotate-psk', name)
    pingServers()
    runAgent('profile', name, 'all')
    expect(client.run('ip', 'rule')).toContain('lookup 51820')
    pingServers()

    expect(runAgent('logout', name)).toContain('revoked')
    expect(client.run('ip', 'link')).not.toContain(name)
    expect(client.run('ip', 'rule')).not.toContain('lookup 51820')
  } finally {
    client.stop()
  }
  await page.reload()
  await expect(page.getByText('No key', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Delete' }).click()
  await page.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('No devices yet.')).toBeVisible()
})

test('the Linux agent logs in through the portal', async ({ page }) => {
  await signIn(page, 'alice')
  await page.getByRole('button', { name: 'New device' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Login Box')
  await page.getByRole('button', { name: 'Generate private key', exact: true }).click()
  await page.getByRole('button', { name: 'Generate preshared key', exact: true }).click()
  await page.getByRole('button', { name: 'Create' }).click()
  await page.getByRole('button', { name: 'Done' }).click()
  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Connect a computer' }).click()
  const dialog = page.getByRole('dialog')
  const link = dialog.getByRole('link', { name: 'Open in the Ito tray' })
  await expect(link).toHaveAttribute('href', /^ito-wg:\/\/connect\?portal=http%3A%2F%2Flocalhost%3A8000&device=\S+$/)
  const command = await dialog.getByLabel('Linux or Windows command').inputValue()
  expect(command).toMatch(/^ito-agent login http:\/\/localhost:8000 --device \S+$/)
  const device = command.split(' ').at(-1)!
  await page.keyboard.press('Escape')

  const client = await startClient()
  const state = mkdtempSync(join(tmpdir(), 'ito-agent-'))
  // The client connects to 10.99.0.1:8000 while the browser uses localhost:8000.
  const portal = 'http://10.99.0.1:8000'
  const approveTicket = async (ticket: { code: string; url: string }) => {
    await page.goto(ticket.url.replace(portal, ''))
    await expect(page.getByText(ticket.code)).toBeVisible()
  }
  try {
    // Bound to the device chosen in the portal.
    const bound = startAgent(client.pid, ['--state-dir', state, 'login', '--no-dns', portal, '--device', device, '--connect'])
    await approveTicket(await bound.readTicket())
    await expect(page.getByText('It connects as Login Box')).toBeVisible()
    await page.getByRole('button', { name: 'Approve' }).click()
    await expect(page.getByText('Approved')).toBeVisible()
    expect(await bound.waitForExit()).toMatch(/: added, as Login Box/)
    client.ping('10.77.0.1')

    // From the computer: a new device, while the first connection stays.
    const open = startAgent(client.pid, ['--state-dir', state, 'login', '--no-dns', portal, '--keep-others'])
    await approveTicket(await open.readTicket())
    await page.getByText('Create a new device').click()
    await page.getByLabel('Name', { exact: true }).fill('Second Box')
    await page.getByRole('button', { name: 'Approve' }).click()
    await expect(page.getByText('Approved')).toBeVisible()
    const output = await open.waitForExit()
    expect(output).toMatch(/: added, as Second Box/)
    expect(output).toMatch(/other connections to http:\/\/10\.99\.0\.1:8000:\s+Login Box/)
    expect(output).toContain('Kept them.')
    const names = client.run(binary, '--state-dir', state, 'list').trim().split('\n').map((l) => l.split('\t')[0]!)
    expect(names).toHaveLength(2)
    for (const name of names) client.run(binary, '--state-dir', state, 'logout', name)
  } finally {
    client.stop()
  }
  await page.goto('/devices')
  for (let left = 2; left > 0; left--) {
    await page.getByRole('button', { name: 'More actions' }).first().click()
    await page.getByRole('menuitem', { name: 'Delete' }).click()
    await page.getByRole('button', { name: 'Delete' }).click()
    await expect(page.getByRole('button', { name: 'More actions' })).toHaveCount(left - 1)
  }
})
