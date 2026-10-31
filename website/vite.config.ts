import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  server: {
    port: 5188,
    host: true
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    assetsInlineLimit: 4096,
    cssMinify: true
  }
});
