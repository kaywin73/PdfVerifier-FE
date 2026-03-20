import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';
import pkg from './package.json' assert { type: 'json' };

const { version } = pkg;

export default defineConfig({
  plugins: [
    wasm(),
    topLevelAwait()
  ],
  build: {
    lib: {
      entry: 'src/lib/index.js',
      name: 'PdfVerifier',
      fileName: (format) => `pdf-verifier-sdk.${version}.${format}.js`
    },
    rollupOptions: {
      output: {
        exports: 'named'
      }
    }
  }
});
