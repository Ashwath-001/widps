import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8787',
        changeOrigin: false, // keep Host = dev server so the backend's Origin check matches
      },
    },
  },
  // SPA fallback: serve index.html for all routes (no 404 on /honeypot)
  appType: 'spa',
})
