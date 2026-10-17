import { expect } from '@playwright/test'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { run, signIn, test, startClient } from './helpers'

/** Brings up `config`, a wg-quick file, in a client namespace and pings the server through it. */
async function connect(config: string) {
  const readValues = (key: string) => config.match(new RegExp(`^${key} = (.+)$`, 'm'))![1]!.split(', ')
  const client = await startClient()
  try {
    // Create the WireGuard interface before moving it to the client namespace so its outer UDP
    // socket remains in the server namespace.
    run('ip', 'link', 'add', 'wgc', 'type', 'wireguard')
    const [peer, endpoint, allowed] = [readValues('PublicKey')[0]!, readValues('Endpoint')[0]!, readValues('AllowedIPs')]
    const dir = mkdtempSync(join(tmpdir(), 'ito-'))
    writeFileSync(join(dir, 'key'), readValues('PrivateKey')[0]!)
    writeFileSync(join(dir, 'psk'), readValues('PresharedKey')[0]!)
    run('wg', 'set', 'wgc', 'private-key', join(dir, 'key'), 'peer', peer, 'preshared-key', join(dir, 'psk'), 'endpoint', endpoint, 'allowed-ips', allowed.join(','))
    run('ip', 'link', 'set', 'wgc', 'netns', client.pid)
    for (const address of readValues('Address')) client.run('ip', 'address', 'add', address, 'dev', 'wgc', ...(address.includes(':') ? ['nodad'] : []))
    client.run('ip', 'link', 'set', 'wgc', 'up')
    for (const route of allowed) client.run('ip', 'route', 'add', route, 'dev', 'wgc')
    for (const server of ['10.77.0.1', 'fd77::1']) client.ping(server)
  } finally {
    client.stop()
  }
}

test('a device made in the browser connects over WireGuard', async ({ page }) => {
  await signIn(page, 'alice')
  await page.getByRole('button', { name: 'New device' }).click()
  await page.getByLabel('Name', { exact: true }).fill('My Laptop')
  await expect(page.getByLabel('DNS label')).toHaveValue('my-laptop')
  await page.getByRole('button', { name: 'Generate private key', exact: true }).click()
  await page.getByRole('button', { name: 'Generate preshared key', exact: true }).click()
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByText('This is shown only once')).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Download My-Laptop.conf' }).click()
  const config = readFileSync((await (await download).path())!, 'utf8')
  expect(config).toContain('DNS = 10.77.0.1, fd77::1, ito.test\n')
  expect(config).toMatch(/^PresharedKey = \S{44}$/m)
  await page.getByRole('button', { name: 'Show QR code' }).click()
  await expect(page.locator('svg[viewBox]').last()).toBeVisible()
  await page.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByText('Ready')).toBeVisible()

  await connect(config)
  await page.reload()
  await page.getByRole('button', { name: 'Show details' }).click()
  await expect(page.getByText('Last handshake').locator('+ dd')).not.toHaveText('Never')

  await page.getByRole('button', { name: 'Addresses' }).click()
  await page.getByRole('button', { name: 'Add block' }).click()
  await page.getByLabel('Size').fill('29')
  await page.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Additional grants').locator('+ dd')).toHaveText('10.77.0.8/29')

  await page.getByRole('button', { name: 'Edit' }).click()
  await page.getByLabel('Name', { exact: true }).fill('work laptop')
  await page.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByRole('cell', { name: 'work laptop' })).toBeVisible()

  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Delete' }).click()
  await page.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('No devices yet.')).toBeVisible()
})

test('the networks page shows the search domains of an interface', async ({ page }) => {
  await signIn(page, 'alice')
  await page.getByRole('link', { name: 'Networks' }).click()
  await expect(page.getByText('Search domains').locator('+ dd')).toHaveText('ito.test')
})

test('an administrator changes the limits of an account', async ({ page, browser }) => {
  const aliceSession = await browser.newPage()
  await signIn(aliceSession, 'alice')
  await aliceSession.close()
  await signIn(page, 'admin')
  await page.getByRole('link', { name: 'Accounts' }).click()
  const alice = page.getByRole('row', { name: /Alice/ })
  await alice.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Edit' }).click()
  await page.getByLabel('IPv4 limit').fill('4')
  await page.getByRole('button', { name: 'Save' }).click()
  await expect(alice).toContainText('of 4')
})

test('a problem met while navigating shows as a page, and stays JSON for scripts', async ({ page }) => {
  const response = await page.goto('/api/v1/auth/callback?error=access_denied&state=x')
  expect(response!.status()).toBe(401)
  await expect(page.getByRole('heading', { name: 'The sign-in did not complete.' })).toBeVisible()
  await expect(page.getByText('the sign-in was cancelled or refused; start it again')).toBeVisible()
  await expect(page.getByText('Request ID')).toBeVisible()
  const api = await page.request.get('/api/v1/session')
  expect(api.headers()['content-type']).toBe('application/problem+json')
  await page.getByRole('link', { name: 'Back to Ito' }).click()
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible()
})

test('key inputs require explicit values, save supplied PSKs and confirm clearing', async ({ page }) => {
  await signIn(page, 'alice')
  await page.getByRole('button', { name: 'New device' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Supplied keys')
  const create = page.getByRole('button', { name: 'Create', exact: true })
  await expect(create).toBeDisabled()
  const privateKey = 'dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo='
  const psk = btoa('a'.repeat(32))
  await page.getByLabel('Private key', { exact: true }).fill(privateKey)
  await page.getByLabel('Preshared key', { exact: true }).fill('invalid')
  await expect(create).toBeDisabled()
  await page.getByLabel('Preshared key', { exact: true }).fill(psk)

  // A failed PSK write must not silently finish without it or create another device on retry.
  let writes = 0
  await page.route('**/api/v1/devices/*/psk', async (route) => {
    if (++writes === 1) await route.fulfill({ status: 503, contentType: 'application/problem+json', body: JSON.stringify({ title: 'Temporary PSK failure', status: 503 }) })
    else await route.continue()
  })
  await create.click()
  await expect(page.getByRole('button', { name: 'Finish setup' })).toBeEnabled()
  await expect(page.getByLabel('Name', { exact: true })).toBeDisabled()
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await page.getByRole('button', { name: 'Show configuration' }).click()
  await expect(page.locator('pre')).toContainText(`PrivateKey = ${privateKey}`)
  await expect(page.locator('pre')).toContainText(`PresharedKey = ${psk}`)
  await page.getByRole('button', { name: 'Done', exact: true }).click()
  const devices = await (await page.request.get('/api/v1/devices')).json()
  expect(devices).toHaveLength(1)
  const id = devices[0].id
  const savedPsk = async () => (await (await page.request.get(`/api/v1/devices/${id}/config`)).json()).preshared_key
  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Preshared key', exact: true }).click()
  const field = page.getByLabel('Preshared key', { exact: true })
  const save = page.getByRole('button', { name: 'Save', exact: true })
  const generate = page.getByRole('button', { name: 'Generate preshared key', exact: true })
  await expect(field).toHaveValue(psk)
  // A successful write must unlock the dialog without relying on another config fetch.
  const configPath = `**/api/v1/devices/${id}/config`
  let refreshes = 0
  await page.route(configPath, async (route) => {
    refreshes++
    await route.abort()
  })
  await field.fill('invalid')
  await expect(save).toBeDisabled()
  const supplied = btoa('b'.repeat(32))
  await field.fill(supplied)
  await save.click()
  await expect.poll(savedPsk).toBe(supplied)
  await expect(save).toBeDisabled()
  await expect(generate).toBeEnabled()
  await generate.click()
  const generated = await field.inputValue()
  expect(generated).not.toBe(supplied)
  expect(await savedPsk()).toBe(supplied)
  await save.click()
  await expect.poll(savedPsk).toBe(generated)
  await expect(save).toBeDisabled()
  await expect(generate).toBeEnabled()
  await field.fill('')
  const pskDialogId = await page.getByRole('dialog').getAttribute('id')
  await save.click()
  const confirmation = page.getByRole('dialog', { name: 'Remove the preshared key of Supplied keys?' })
  await expect(page.getByRole('dialog')).toHaveCount(1)
  await expect(confirmation).toHaveAttribute('id', pskDialogId!)
  await confirmation.getByRole('button', { name: 'Cancel' }).click()
  expect(await savedPsk()).toBe(generated)
  await expect(generate).toBeEnabled()
  await expect(field).toHaveValue('')
  await save.click()
  await expect(page.getByRole('dialog')).toHaveCount(1)
  await expect(confirmation).toHaveAttribute('id', pskDialogId!)
  await confirmation.getByRole('button', { name: 'Remove', exact: true }).click()
  await expect.poll(savedPsk).toBe('')
  await expect(page.getByText('This device has no preshared key.')).toBeVisible()
  await expect(generate).toBeEnabled()
  await expect(page.getByRole('dialog')).toHaveAttribute('id', pskDialogId!)
  await generate.click()
  await expect(field).not.toHaveValue('')
  expect(await savedPsk()).toBe('')
  expect(refreshes).toBe(0)
  await page.unroute(configPath)
  await page.getByRole('dialog', { name: 'Preshared key of Supplied keys', exact: true }).getByRole('button', { name: 'Close', exact: true }).click()

  await page.getByRole('button', { name: 'New key', exact: true }).click()
  const replace = page.getByRole('button', { name: 'Replace', exact: true })
  await expect(replace).toBeDisabled()
  await page.getByLabel('Private key', { exact: true }).fill(btoa('\0'.repeat(32)))
  await expect(replace).toBeDisabled()
  await page.getByRole('button', { name: 'Generate private key', exact: true }).click()
  const replacement = await page.getByLabel('Private key', { exact: true }).inputValue()
  await replace.click()
  await page.getByRole('button', { name: 'Show configuration' }).click()
  await expect(page.locator('pre')).toContainText(`PrivateKey = ${replacement}`)
  await expect(page.locator('pre')).not.toContainText('PresharedKey =')
  await page.getByRole('button', { name: 'Done', exact: true }).click()
})


test('sign-out ends Ito first and leaves SSO logout to Keycloak confirmation', async ({ page }) => {
  await signIn(page, 'alice')
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(page.locator('#kc-logout')).toBeVisible()
  const logout = new URL(page.url())
  expect(logout.pathname).toBe('/realms/ito/protocol/openid-connect/logout')
  expect(logout.searchParams.get('client_id')).toBe('ito')
  expect(logout.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:8000/')
  expect(logout.searchParams.has('id_token_hint')).toBe(false)
  expect((await page.request.get('http://localhost:8000/api/v1/session')).status()).toBe(401)

  // Leaving the confirmation page keeps SSO, but the Ito session is already gone.
  await page.goto('/')
  await page.getByRole('link', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/devices$/)
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await page.locator('#kc-logout').click()
  await expect(page).toHaveURL('http://localhost:8000/')
  await page.getByRole('link', { name: 'Sign in' }).click()
  await expect(page.locator('#username')).toBeVisible()
})
