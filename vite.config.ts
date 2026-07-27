import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// Update this to match your GitHub repository name so production assets
// resolve correctly on GitHub Pages, e.g. for
// github.com/ironbranded/microsoft-cloud-attack-matrix this stays as-is;
// if you deploy under a different repo name, change it to match.
const GH_PAGES_BASE = '/microsoft-cloud-attack-matrix/'

export default defineConfig(({ command }) => ({
  plugins: [react()],
  base: command === 'build' ? GH_PAGES_BASE : '/',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
}))
