/**
 * Multi-worker PoW grinder.
 *
 * Spawns N workers running `pow-worker` (Node `worker_threads` or browser
 * `Worker`); worker i searches nonces `start + i, start + i + N, ...` so the
 * workers partition the nonce space. The first hit wins and the others are
 * cancelled. If workers cannot be created (no worker URL resolvable, e.g. a
 * bundler that did not emit the worker, or `workers: 0`) the grind runs on the
 * main thread in async slices so the event loop is not starved.
 *
 * Resolving the worker script:
 *  - Node ESM (`dist/bus/index.js`): `new URL('./pow-worker.js', import.meta.url)`
 *    -> `dist/bus/pow-worker.js` (a separate tsup entry, self-contained).
 *  - Node CJS (`dist/bus/index.cjs`): esbuild leaves `import.meta.url` empty, so
 *    we fall back to `__filename` -> `dist/bus/pow-worker.cjs`.
 *  - Browser: bundlers (Vite, webpack 5, Rollup, Parcel) statically recognise
 *    `new Worker(new URL('./pow-worker.js', import.meta.url), { type: 'module' })`
 *    and emit the worker as a chunk. If yours does not, build
 *    `navio-p2pmsg/dist/bus/pow-worker.js` yourself (or copy it to a static path)
 *    and pass `workerUrl` explicitly.
 */
import { checkPoW, type PoWHeader, grindSync, serializePoWHeader, withNonce } from './pow.js';
import { DEFAULT_SLICE_ITERS, type WorkerRequest, type WorkerResponse } from './pow-protocol.js';

export interface PowGrinderOptions {
  /** Worker count. Default: hardware threads - 1, clamped to [1, 8]. `0` = main thread only. */
  workers?: number;
  /** Explicit worker script location (see module docs). */
  workerUrl?: string | URL;
  /** Attempts per slice in workers / on the main thread before yielding. */
  sliceIters?: number;
}

export interface GrindCallOptions {
  signal?: AbortSignal;
  /** Called with the cumulative attempt count as slices complete. */
  onProgress?: (attempts: number) => void;
}

export class GrindAbortedError extends Error {
  override readonly name = 'GrindAbortedError';
  constructor(message = 'PoW grind aborted') {
    super(message);
  }
}

interface WorkerHandle {
  post(msg: WorkerRequest): void;
  terminate(): void;
  ref(): void;
  unref(): void;
}

interface Pending {
  id: number;
  header: PoWHeader;
  bits: number;
  workers: Set<WorkerHandle>;
  attempts: number;
  done: boolean;
  onProgress?: (attempts: number) => void;
  signal?: AbortSignal;
  resolve: (h: PoWHeader) => void;
  reject: (e: Error) => void;
  onAbort?: () => void;
}

function defaultWorkerCount(): number {
  let hw = 0;
  const nav = (globalThis as { navigator?: { hardwareConcurrency?: number } }).navigator;
  if (nav && typeof nav.hardwareConcurrency === 'number') hw = nav.hardwareConcurrency;
  if (!hw && typeof process !== 'undefined') {
    // Node >= 18 exposes availableParallelism on os; avoid a static import for browser bundles.
    try {
      const os = (process as unknown as { getBuiltinModule?: (n: string) => { availableParallelism?: () => number; cpus?: () => unknown[] } }).getBuiltinModule?.('node:os');
      if (os) hw = os.availableParallelism ? os.availableParallelism() : (os.cpus?.().length ?? 0);
    } catch {
      /* ignore */
    }
  }
  return Math.max(1, Math.min(8, (hw || 2) - 1));
}

function isNode(): boolean {
  return typeof process !== 'undefined' && !!(process as { versions?: { node?: string } }).versions?.node;
}

function defaultWorkerUrl(): URL | string | undefined {
  let base: string | undefined;
  try {
    base = import.meta.url;
  } catch {
    /* CJS */
  }
  if (base) return new URL('./pow-worker.js', base);
  try {
    // CJS build: tsup emits dist/bus/pow-worker.cjs next to dist/bus/index.cjs.
    if (typeof __filename === 'string') return __filename.replace(/[^/\\]*$/, 'pow-worker.cjs');
  } catch {
    /* ESM */
  }
  return undefined;
}

export class PowGrinder {
  private readonly workerCount: number;
  private readonly workerUrl: URL | string | undefined;
  private readonly sliceIters: number;
  private pool: Promise<WorkerHandle[]> | null = null;
  private live: WorkerHandle[] = [];
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private closed = false;

  constructor(opts: PowGrinderOptions = {}) {
    this.workerCount = opts.workers === undefined ? defaultWorkerCount() : Math.max(0, Math.min(64, opts.workers | 0));
    this.workerUrl = opts.workerUrl;
    this.sliceIters = opts.sliceIters && opts.sliceIters > 0 ? opts.sliceIters : DEFAULT_SLICE_ITERS;
  }

  /** Number of currently live workers (0 before first grind or when falling back). */
  get liveWorkers(): number {
    return this.live.length;
  }

  /** Grind `header` (starting at `header.nonce`) until it meets `bits`. Returns a copy with the nonce set. */
  async grind(header: PoWHeader, bits: number, opts: GrindCallOptions = {}): Promise<PoWHeader> {
    if (this.closed) throw new Error('PowGrinder is closed');
    if (opts.signal?.aborted) throw new GrindAbortedError();
    if (checkPoW(header, bits)) return withNonce(header, header.nonce);
    const workers = this.workerCount > 0 ? await this.ensurePool() : [];
    if (opts.signal?.aborted) throw new GrindAbortedError();
    if (workers.length === 0) return this.grindMainThread(header, bits, opts);

    return new Promise<PoWHeader>((resolve, reject) => {
      const id = this.nextId++;
      const req: Pending = {
        id,
        header,
        bits,
        workers: new Set(workers),
        attempts: 0,
        done: false,
        resolve,
        reject,
      };
      if (opts.onProgress) req.onProgress = opts.onProgress;
      if (opts.signal) req.signal = opts.signal;
      this.pending.set(id, req);
      if (this.pending.size === 1) for (const w of this.live) w.ref();
      const bytes = serializePoWHeader(header);
      const n = workers.length;
      workers.forEach((w, i) => {
        w.post({
          type: 'grind',
          id,
          header: bytes,
          bits,
          startNonce: BigInt.asUintN(64, header.nonce + BigInt(i)),
          stride: n,
          sliceIters: this.sliceIters,
        });
      });
      if (opts.signal) {
        req.onAbort = () => this.finish(req, undefined, new GrindAbortedError());
        opts.signal.addEventListener('abort', req.onAbort, { once: true });
      }
    });
  }

  /** Terminate workers and reject in-flight grinds. */
  close(): void {
    this.closed = true;
    for (const req of [...this.pending.values()]) this.finish(req, undefined, new Error('PowGrinder closed'));
    for (const w of this.live) w.terminate();
    this.live = [];
    this.pool = null;
  }

  private finish(req: Pending, result?: PoWHeader, err?: Error): void {
    if (req.done) return;
    req.done = true;
    this.pending.delete(req.id);
    if (req.onAbort && req.signal) req.signal.removeEventListener('abort', req.onAbort);
    for (const w of req.workers) w.post({ type: 'cancel', id: req.id });
    if (this.pending.size === 0) for (const w of this.live) w.unref();
    if (result) req.resolve(result);
    else req.reject(err ?? new Error('grind failed'));
  }

  private onMessage(handle: WorkerHandle, msg: WorkerResponse): void {
    const req = this.pending.get(msg.id);
    if (!req || req.done) return;
    switch (msg.type) {
      case 'found': {
        const h = withNonce(req.header, msg.nonce);
        if (checkPoW(h, req.bits)) {
          req.attempts += msg.attempts;
          this.finish(req, h);
        } else {
          // Should never happen; treat like a worker fault.
          this.dropWorkerFromRequest(req, handle);
        }
        break;
      }
      case 'progress':
        req.attempts += msg.attempts;
        req.onProgress?.(req.attempts);
        break;
      case 'error':
        this.dropWorkerFromRequest(req, handle);
        break;
      case 'cancelled':
        break;
    }
  }

  private onWorkerError(handle: WorkerHandle): void {
    this.live = this.live.filter((w) => w !== handle);
    try {
      handle.terminate();
    } catch {
      /* ignore */
    }
    if (this.live.length === 0) this.pool = null;
    for (const req of [...this.pending.values()]) this.dropWorkerFromRequest(req, handle);
  }

  private dropWorkerFromRequest(req: Pending, handle: WorkerHandle): void {
    req.workers.delete(handle);
    if (req.workers.size === 0 && !req.done) {
      // Every worker for this request is gone: continue on the main thread.
      const opts: GrindCallOptions = {};
      if (req.signal) opts.signal = req.signal;
      if (req.onProgress) {
        const base = req.attempts;
        const cb = req.onProgress;
        opts.onProgress = (a) => cb(base + a);
      }
      this.grindMainThread(req.header, req.bits, opts).then(
        (h) => this.finish(req, h),
        (e: unknown) => this.finish(req, undefined, e instanceof Error ? e : new Error(String(e))),
      );
    }
  }

  /** Main-thread grind in async slices (`sliceIters` attempts, then yield). */
  async grindMainThread(header: PoWHeader, bits: number, opts: GrindCallOptions = {}): Promise<PoWHeader> {
    let nonce = header.nonce;
    let attempts = 0;
    const slice = Math.min(this.sliceIters, 100_000);
    for (;;) {
      if (opts.signal?.aborted) throw new GrindAbortedError();
      const found = grindSync(header, bits, { startNonce: nonce, stride: 1, maxIters: slice });
      if (found !== null) return withNonce(header, found);
      attempts += slice;
      opts.onProgress?.(attempts);
      nonce = BigInt.asUintN(64, nonce + BigInt(slice));
      await new Promise<void>((r) => setTimeout(r, 0));
    }
  }

  private ensurePool(): Promise<WorkerHandle[]> {
    if (!this.pool) {
      this.pool = this.spawnAll().catch(() => [] as WorkerHandle[]);
    }
    return this.pool;
  }

  private async spawnAll(): Promise<WorkerHandle[]> {
    const url = this.workerUrl ?? defaultWorkerUrl();
    if (!url) return [];
    const handles: WorkerHandle[] = [];
    for (let i = 0; i < this.workerCount; i++) {
      let h: WorkerHandle;
      try {
        h = isNode() ? await this.spawnNode(url) : this.spawnBrowser(url);
      } catch {
        break;
      }
      handles.push(h);
    }
    this.live = handles;
    for (const h of handles) h.unref();
    return handles;
  }

  private async spawnNode(url: URL | string): Promise<WorkerHandle> {
    const modName = 'node:worker_threads';
    const wt = (await import(/* @vite-ignore */ /* webpackIgnore: true */ modName)) as typeof import('node:worker_threads');
    const w = new wt.Worker(url);
    const handle: WorkerHandle = {
      post: (m) => w.postMessage(m),
      terminate: () => void w.terminate(),
      ref: () => w.ref(),
      unref: () => w.unref(),
    };
    w.on('message', (m: WorkerResponse) => this.onMessage(handle, m));
    w.on('error', () => this.onWorkerError(handle));
    w.on('exit', () => {
      if (this.live.includes(handle)) this.onWorkerError(handle);
    });
    return handle;
  }

  private spawnBrowser(url: URL | string): WorkerHandle {
    const W = (globalThis as { Worker?: new (u: URL | string, o?: { type: 'module' }) => Worker }).Worker;
    if (!W) throw new Error('no Worker constructor');
    const w = new W(url, { type: 'module' });
    const handle: WorkerHandle = {
      post: (m) => w.postMessage(m),
      terminate: () => w.terminate(),
      ref: () => {},
      unref: () => {},
    };
    w.onmessage = (ev: MessageEvent<WorkerResponse>) => this.onMessage(handle, ev.data);
    w.onerror = () => this.onWorkerError(handle);
    return handle;
  }
}
