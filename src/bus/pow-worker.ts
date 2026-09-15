/**
 * PoW grinding worker. Works both as a Node `worker_threads` Worker and as a
 * browser (module) `Worker`:
 *
 *   Node:    new Worker(new URL('./pow-worker.js', import.meta.url))
 *   Browser: new Worker(new URL('./pow-worker.js', import.meta.url), { type: 'module' })
 *
 * Protocol: see `pow-protocol.ts`. Grinding runs in slices (default 200k
 * attempts) and yields to the event loop between slices so `cancel` messages
 * are honoured promptly and `progress` is reported per slice.
 */
import { PowMidstate } from './pow.js';
import {
  DEFAULT_SLICE_ITERS,
  type GrindRequest,
  type WorkerRequest,
  type WorkerResponse,
} from './pow-protocol.js';

type Post = (msg: WorkerResponse) => void;

const active = new Map<number, { cancelled: boolean }>();

function yieldToLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function runGrind(req: GrindRequest, post: Post): Promise<void> {
  const ctl = { cancelled: false };
  active.set(req.id, ctl);
  try {
    const mid = new PowMidstate(req.header);
    const slice = req.sliceIters && req.sliceIters > 0 ? req.sliceIters : DEFAULT_SLICE_ITERS;
    const stride = Math.max(1, req.stride | 0);
    let nonce = BigInt.asUintN(64, req.startNonce);
    let attempts = 0;
    for (;;) {
      const found = mid.search(nonce, stride, req.bits, slice);
      if (found !== null) {
        // attempts up to and including the hit
        attempts += Number((found - nonce) / BigInt(stride)) + 1;
        post({ type: 'found', id: req.id, nonce: found, attempts });
        return;
      }
      attempts += slice;
      post({ type: 'progress', id: req.id, attempts: slice });
      nonce = BigInt.asUintN(64, nonce + BigInt(slice) * BigInt(stride));
      await yieldToLoop();
      if (ctl.cancelled) {
        post({ type: 'cancelled', id: req.id });
        return;
      }
    }
  } catch (e) {
    post({ type: 'error', id: req.id, message: e instanceof Error ? e.message : String(e) });
  } finally {
    active.delete(req.id);
  }
}

function handle(msg: WorkerRequest, post: Post): void {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'grind') {
    void runGrind(msg, post);
  } else if (msg.type === 'cancel') {
    const ctl = active.get(msg.id);
    if (ctl) ctl.cancelled = true;
  }
}

async function main(): Promise<void> {
  const g = globalThis as unknown as {
    self?: unknown;
    importScripts?: unknown;
    WorkerGlobalScope?: unknown;
    postMessage?: (m: unknown) => void;
    addEventListener?: (t: string, cb: (ev: { data: unknown }) => void) => void;
  };
  const isBrowserWorker =
    typeof g.WorkerGlobalScope !== 'undefined' ||
    (typeof g.self !== 'undefined' && typeof g.importScripts === 'function');
  if (isBrowserWorker && typeof g.postMessage === 'function' && typeof g.addEventListener === 'function') {
    const post: Post = (m) => g.postMessage!(m);
    g.addEventListener('message', (ev) => handle(ev.data as WorkerRequest, post));
    return;
  }
  // Node worker_threads. The specifier is kept out of static analysis so browser
  // bundlers do not try to resolve it.
  const modName = 'node:worker_threads';
  const wt = (await import(/* @vite-ignore */ /* webpackIgnore: true */ modName)) as typeof import('node:worker_threads');
  const port = wt.parentPort;
  if (!port) return; // loaded as a plain module, not as a worker: nothing to do
  const post: Post = (m) => port.postMessage(m);
  port.on('message', (m: WorkerRequest) => handle(m, post));
}

void main();
