import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue()],
  build: {
    lib: {
      entry: 'src/index.ts',
      name: 'GateKeeperVue',
      fileName: 'index',
    },
    rollupOptions: {
      external: ['vue', '@b3n/gatekeeper-js'],
    },
  },
})

