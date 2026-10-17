import { defineConfig } from '@playwright/test'

// `just test-e2e` runs this inside a user and network namespace, where the controller may create
// WireGuard links and the tests may add a client namespace.
export default defineConfig({
  testDir: 'e2e',
  use: { baseURL: 'http://localhost:8000' },
  // The tests share one controller and one set of accounts.
  workers: 1,
  webServer: {
    // Clients in other namespaces reach the controller at 10.99.0.1, its WireGuard endpoint too.
    command: 'ip address add 10.99.0.1/32 dev lo && rm -rf build/e2e && web/e2e/serve.sh build/e2e',
    env: { ITO_ENDPOINT: '10.99.0.1:51820' },
    cwd: '..',
    url: 'http://localhost:8000/health/ready',
  },
})
