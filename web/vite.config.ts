import ui from '@nuxt/ui/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [
    vue(),
    ui({
      ui: {
        colors: { primary: 'ito', neutral: 'zinc' },
        // Solid primary buttons get dark text: white on the light primary is hard to read.
        button: {
          compoundVariants: [{ color: 'primary', variant: 'solid', class: 'text-ito-950' }],
        },
      },
      // Bundle the icons the app uses, so pages fetch nothing from the Iconify API.
      icon: { clientBundle: { scan: true } },
    }),
  ],
  // `pnpm dev` sends API calls to a controller on port 8000, such as `just demo-up`, under the
  // controller's own origin. Sign in on port 8000 first: cookies count for every port of a host.
  server: {
    proxy: { '/api': { target: 'http://localhost:8000', headers: { origin: 'http://localhost:8000' } } },
  },
  test: { include: ['src/**/*.test.ts'] },
})
