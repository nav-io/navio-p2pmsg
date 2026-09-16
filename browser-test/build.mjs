import { build } from 'esbuild';
const common = { bundle: true, format: 'esm', platform: 'browser', target: 'es2022', sourcemap: true, external: ['node:*', 'ws'], logLevel: 'info' };
await build({ ...common, entryPoints: ['browser-test/app.ts'], outfile: 'browser-test/out/app.js' });
await build({ ...common, entryPoints: ['src/bus/pow-worker.ts'], outfile: 'browser-test/out/pow-worker.js' });
