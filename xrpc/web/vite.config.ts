import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    }
  },
  server: {
    port: 5174,
    proxy: {
      '/api': 'http://localhost:8081',
      '/logs': 'http://localhost:8081',
      '/status': 'http://localhost:8081',
      '/healthz': 'http://localhost:8081',
      '/ws': {
        target: 'http://localhost:8081',
        ws: true,
        changeOrigin: true,
      },
    }
  }
})
