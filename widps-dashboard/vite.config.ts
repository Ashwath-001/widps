import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Settings come from .env (see .env.example); loadEnv with prefix '' keeps them out of the client bundle.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.WIDPS_API_TARGET || 'http://127.0.0.1:8787'
  const host = env.WIDPS_DEV_HOST || '127.0.0.1'
  const port = Number(env.WIDPS_DEV_PORT || 5173)
  const proxy = {
    '/api': {
      target: apiTarget,
      changeOrigin: false, // keep Host = dev server so the backend's Origin check matches
    },
  }
  return {
    plugins: [react()],
    server: { host, port, proxy },
    preview: { host, port, proxy },
    // SPA fallback: serve index.html for all routes (no 404 on /honeypot)
    appType: 'spa',
  }
})
