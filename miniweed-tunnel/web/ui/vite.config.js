import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { resolve } from 'path';

export default defineConfig({
  plugins: [preact()],
  base: '/app/',
  build: {
    outDir: resolve(__dirname, '../public/app'),
    emptyOutDir: true
  },
  // Solo en `npm run dev`: redirige las llamadas /api al backend local (server.js).
  server: {
    proxy: {
      '/api': 'http://localhost:3016'
    }
  }
});
