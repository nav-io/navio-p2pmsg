import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from '../common/bytes.js';
import { GrindAbortedError, PowGrinder } from './pow-grinder.js';
import { checkPoW, type PoWHeader } from './pow.js';

function randomHeader(): PoWHeader {
  return {
    version: 1,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    kind: 0,
    sessionEph: randomBytes(48),
    payloadHash: randomBytes(32),
    nonce: 0n,
  };
}

// The worker entry imports './pow.js', which only exists once built. Build the
// real tsup entry into a temp dir so the test exercises the shipped artefact.
let outDir: string;
let workerUrl: URL;

beforeAll(async () => {
  outDir = mkdtempSync(join(tmpdir(), 'p2pmsg-worker-'));
  const { build } = await import('tsup');
  await build({
    entry: { 'pow-worker': 'src/bus/pow-worker.ts' },
    format: ['esm'],
    outDir,
    silent: true,
    dts: false,
    sourcemap: false,
    splitting: false,
    clean: false,
    target: 'es2022',
    external: ['node:worker_threads'],
    // The real dist keeps @noble/* external (resolvable from inside the package);
    // a temp dir cannot resolve them, so inline everything here.
    noExternal: [/.*/],
  });
  workerUrl = pathToFileURL(join(outDir, 'pow-worker.js'));
});

afterAll(() => {
  rmSync(outDir, { recursive: true, force: true });
});

describe('PowGrinder (worker_threads)', () => {
  it('finds a nonce for bits=12 with 2 workers and reports progress', async () => {
    const g = new PowGrinder({ workers: 2, workerUrl, sliceIters: 5_000 });
    try {
      const h = randomHeader();
      let progress = 0;
      const stamped = await g.grind(h, 12, { onProgress: (a) => (progress = a) });
      expect(g.liveWorkers).toBe(2);
      expect(checkPoW(stamped, 12)).toBe(true);
      expect(stamped.sessionEph).toEqual(h.sessionEph);
      expect(h.nonce).toBe(0n); // input not mutated
      expect(progress).toBeGreaterThanOrEqual(0);
      // a second grind reuses the pool
      const again = await g.grind(randomHeader(), 10);
      expect(checkPoW(again, 10)).toBe(true);
    } finally {
      g.close();
    }
  });

  it('honours cancellation via AbortSignal', async () => {
    const g = new PowGrinder({ workers: 2, workerUrl, sliceIters: 5_000 });
    try {
      const ac = new AbortController();
      const p = g.grind(randomHeader(), 60, { signal: ac.signal }); // effectively unattainable
      await new Promise((r) => setTimeout(r, 50));
      ac.abort();
      await expect(p).rejects.toBeInstanceOf(GrindAbortedError);
      // grinder still usable afterwards
      const ok = await g.grind(randomHeader(), 8);
      expect(checkPoW(ok, 8)).toBe(true);
    } finally {
      g.close();
    }
  });

  it('close() rejects in-flight grinds', async () => {
    const g = new PowGrinder({ workers: 1, workerUrl });
    const p = g.grind(randomHeader(), 60);
    await new Promise((r) => setTimeout(r, 20));
    g.close();
    await expect(p).rejects.toThrow(/closed/);
  });
});

describe('PowGrinder fallbacks', () => {
  it('workers: 0 grinds on the main thread', async () => {
    const g = new PowGrinder({ workers: 0 });
    const stamped = await g.grind(randomHeader(), 10);
    expect(checkPoW(stamped, 10)).toBe(true);
    expect(g.liveWorkers).toBe(0);
    g.close();
  });

  it('unresolvable worker script falls back to the main thread', async () => {
    const g = new PowGrinder({ workers: 2, workerUrl: pathToFileURL(join(outDir, 'does-not-exist.js')) });
    const stamped = await g.grind(randomHeader(), 10);
    expect(checkPoW(stamped, 10)).toBe(true);
    expect(g.liveWorkers).toBe(0);
    g.close();
  });

  it('main-thread abort', async () => {
    const g = new PowGrinder({ workers: 0, sliceIters: 1000 });
    const ac = new AbortController();
    const p = g.grind(randomHeader(), 60, { signal: ac.signal });
    setTimeout(() => ac.abort(), 20);
    await expect(p).rejects.toBeInstanceOf(GrindAbortedError);
    g.close();
  });
});
