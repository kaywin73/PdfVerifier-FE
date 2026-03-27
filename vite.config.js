import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';
import pkg from './package.json' with { type: 'json' };

const { version } = pkg;

const buildEnv = process.env.BUILD_ENV ? `.${process.env.BUILD_ENV.trim()}` : '';

export default defineConfig({
  plugins: [
    wasm(),
    topLevelAwait()
  ],
  define: {
    '__BUILD_ENV__': JSON.stringify(process.env.BUILD_ENV || 'prod')
  },
  build: {
    lib: {
      entry: 'src/lib/index.js',
      name: 'PdfVerifier',
      fileName: (format) => `pdf-verifier-sdk.${version}${buildEnv}.${format}.js`
    },
    rollupOptions: {
      output: {
        exports: 'named'
      }
    }
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
});
