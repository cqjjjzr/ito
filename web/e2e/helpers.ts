import { expect, test as base, type Page } from '@playwright/test'
import { execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'

// Each test owns the devices it creates in this isolated controller. Clean up even after an
// assertion fails, so a later browser test does not inherit rows or consume its address quota.
export const test = base.extend({
  page: async ({ page }, use) => {
    await use(page)
    const session = await page.request.get('/api/v1/session')
    if (!session.ok()) return
    const { csrf_token } = await session.json()
    const response = await page.request.get('/api/v1/devices')
    expect(response.ok()).toBe(true)
    for (const { id, deleting } of await response.json()) {
      if (deleting) continue
      const deleted = await page.request.delete(`/api/v1/devices/${id}`, {
        headers: { 'x-csrf-token': csrf_token, origin: new URL(page.url()).origin },
      })
      expect(deleted.ok(), await deleted.text()).toBe(true)
    }
  },
})

export const agentBinary = process.env.ITO_AGENT_BIN ?? new URL('../../target/debug/ito-agent', import.meta.url).pathname

export async function signIn(page: Page, user: string) {
  await page.goto('/')
  await page.getByRole('link', { name: 'Sign in' }).click()
  await page.fill('#username', user)
  await page.fill('#password', user)
  await page.click('#kc-login')
  await expect(page).toHaveURL(/\/devices$/)
}

/** Runs `command` in the controller network namespace and returns its stdout. */
export const run = (...command: string[]) => execFileSync(command[0]!, command.slice(1), { encoding: 'utf8' })

/**
 * Starts a client network namespace connected to the controller namespace by a veth pair so the
 * client can reach the controller at `10.99.0.1`. Stopping the client removes both.
 */
export async function startClient() {
  const holder = spawn('unshare', ['--net', 'sh', '-c', 'echo ready && exec sleep infinity'])
  await once(holder.stdout, 'data')
  const pid = String(holder.pid)
  const runInClient = (...command: string[]) => run('nsenter', `--net=/proc/${pid}/ns/net`, ...command)
  run('ip', 'link', 'add', 'ito-v0', 'type', 'veth', 'peer', 'name', 'ito-v1', 'netns', pid)
  run('ip', 'address', 'add', '10.99.1.1/30', 'dev', 'ito-v0')
  run('ip', 'link', 'set', 'ito-v0', 'up')
  runInClient('ip', 'address', 'add', '10.99.1.2/30', 'dev', 'ito-v1')
  runInClient('ip', 'link', 'set', 'ito-v1', 'up')
  runInClient('ip', 'route', 'add', '10.99.0.1/32', 'via', '10.99.1.1')
  return {
    pid,
    run: runInClient,
    /** Pings `server` from the client, waiting up to ten seconds while a tunnel settles. */
    ping: (server: string) => runInClient('ping', '-c', '1', '-w', '10', server),
    stop: () => holder.kill(),
  }
}

/**
 * Spawns `ito-agent ARGS` inside the client namespace `pid`. Provides helpers to await the printed
 * login ticket (`readTicket`), the `--json` request line (`readRequest`), and a successful exit
 * (`waitForExit`).
 */
export function startAgent(pid: string, args: string[]) {
  const child = spawn('nsenter', [`--net=/proc/${pid}/ns/net`, agentBinary, ...args])
  const exited = once(child, 'exit')
  let output = ''
  child.stdout.on('data', (d) => (output += d))
  child.stderr.on('data', (d) => (output += d))
  const matchTicket = () => /showing (\S+):\s+(\S+)/.exec(output)
  const matchJsonLine = () => /^\{.*\}$/m.exec(output)
  return {
    async readRequest(): Promise<{ request: string; requested_at: number; code: string }> {
      await expect.poll(matchJsonLine, { timeout: 10_000 }).toBeTruthy()
      return JSON.parse(matchJsonLine()![0])
    },
    async readTicket() {
      await expect.poll(matchTicket, { timeout: 10_000 }).toBeTruthy()
      const [, code, url] = matchTicket()!
      return { code: code!, url: url! }
    },
    async waitForExit() {
      const [status] = await exited
      expect(status, output).toBe(0)
      return output
    },
  }
}
