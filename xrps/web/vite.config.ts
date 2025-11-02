import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  // Ensure production assets are referenced under /ui/ when served by Go
  base: '/ui/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
      '/logs': 'http://localhost:8080',
      '/status': 'http://localhost:8080',
      '/healthz': 'http://localhost:8080',
      '/ws': {
        target: 'http://localhost:8080',
        ws: true,
        changeOrigin: true,
      }
    }
  }
})
