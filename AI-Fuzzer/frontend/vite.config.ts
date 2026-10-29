import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'

function readOnlyBackendProxy(): Plugin {
  return {
    name: 'read-only-backend-proxy',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const requestPath = new URL(request.url ?? '/', 'http://localhost').pathname
        const pathname = requestPath.startsWith('/api/') ? requestPath.slice(4) : requestPath
        const isBackendRoute =
          requestPath.startsWith('/api/') && (
            pathname === '/health' ||
          pathname === '/targets' ||
          pathname.startsWith('/targets/') ||
          pathname === '/scans' ||
          pathname.startsWith('/scans/')
          )

        if (isBackendRoute && request.method !== 'GET') {
          response.statusCode = 405
          response.setHeader('Allow', 'GET')
          response.end('This frontend proxy only permits read-only API requests.')
          return
        }

        next()
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [readOnlyBackendProxy(), react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
