import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'net/index': 'src/net/index.ts',
    'bus/index': 'src/bus/index.ts',
    'usermsg/index': 'src/usermsg/index.ts',
    'stores/index': 'src/stores/index.ts',
    'archive/index': 'src/archive/index.ts',
    'chat/index': 'src/chat/index.ts',
    'devices/index': 'src/devices/index.ts',
    'bus/pow-worker': 'src/bus/pow-worker.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  target: 'es2022',
  external: ['ws', 'node:net', 'node:dns', 'node:fs', 'node:worker_threads', 'node:path'],
});
