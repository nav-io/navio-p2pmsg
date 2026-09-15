/**
 * WebSocket transport. Uses the global `WebSocket` when present (browsers,
 * Node >= 22), otherwise lazily imports the optional `ws` package (Node).
 *
 * Byte-stream semantics: every inbound binary frame is appended to the stream
 * and every `send()` becomes one binary frame. Frame boundaries carry no
 * meaning; the Bitcoin message codec above re-frames.
 */
import type { Transport } from './transport.js';

export interface WsTransportOptions {
  /** Abort `connect()` if the WebSocket does not open within this time. Default 10 s. */
  connectTimeoutMs?: number;
}

/** The subset of the WebSocket API shared by browsers and `ws`. */
interface WsLike {
  binaryType: string;
  readyState: number;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onclose: ((ev: { code?: number; reason?: string; wasClean?: boolean }) => void) | null;
}
type WsCtor = new (url: string) => WsLike;

const WS_OPEN = 1;

async function loadWebSocket(): Promise<WsCtor> {
  const g = globalThis as { WebSocket?: unknown };
  if (typeof g.WebSocket === 'function') return g.WebSocket as WsCtor;
  let mod: { default?: unknown; WebSocket?: unknown };
  try {
    mod = (await import('ws')) as { default?: unknown; WebSocket?: unknown };
  } catch (e) {
    throw new Error(
      `WsTransport: no global WebSocket and optional dependency 'ws' is not installed (${(e as Error).message})`,
    );
  }
  const ctor = mod.default ?? mod.WebSocket;
  if (typeof ctor !== 'function') throw new Error("WsTransport: could not load 'ws'");
  return ctor as WsCtor;
}

export class WsTransport implements Transport {
  readonly remote: string;
  private ws: WsLike | null = null;
  private dataCb: ((bytes: Uint8Array) => void) | null = null;
  private closeCb: ((err?: Error) => void) | null = null;
  private closed = false;
  private lastError: Error | undefined;
  private readonly connectTimeoutMs: number;

  constructor(
    readonly url: string,
    opts: WsTransportOptions = {},
  ) {
    this.remote = url;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
  }

  async connect(): Promise<void> {
    if (this.ws) throw new Error('WsTransport: already connected');
    if (this.closed) throw new Error('WsTransport: closed');
    const Ctor = await loadWebSocket();
    await new Promise<void>((resolve, reject) => {
      let ws: WsLike;
      try {
        ws = new Ctor(this.url);
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
        return;
      }
      this.ws = ws;
      ws.binaryType = 'arraybuffer';
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        const err = new Error(`WsTransport: connect timeout to ${this.remote}`);
        this.lastError = err;
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        reject(err);
      }, this.connectTimeoutMs);

      ws.onopen = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      };
      ws.onerror = (ev) => {
        const err = toError(ev, `WsTransport: socket error (${this.remote})`);
        this.lastError = err;
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      };
      ws.onmessage = (ev) => {
        const d = ev.data;
        if (d instanceof ArrayBuffer) {
          this.dataCb?.(new Uint8Array(d));
        } else if (ArrayBuffer.isView(d)) {
          this.dataCb?.(new Uint8Array(d.buffer, d.byteOffset, d.byteLength));
        } else if (Array.isArray(d)) {
          // `ws` may deliver fragmented frames as Buffer[] under some settings.
          for (const part of d as ArrayBufferView[]) {
            this.dataCb?.(new Uint8Array(part.buffer, part.byteOffset, part.byteLength));
          }
        } else if (typeof d === 'object' && d !== null && typeof (d as Blob).arrayBuffer === 'function') {
          // Defensive: some runtimes ignore binaryType and hand us a Blob.
          void (d as Blob).arrayBuffer().then((ab) => this.dataCb?.(new Uint8Array(ab)));
        }
        // Text frames are not part of the protocol; ignore.
      };
      ws.onclose = (ev) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          const err =
            this.lastError ?? new Error(`WsTransport: closed before open (code ${ev.code ?? '?'})`);
          this.finish(err);
          reject(err);
          return;
        }
        let err = this.lastError;
        if (!err && ev.wasClean === false && ev.code !== undefined && ev.code !== 1000 && ev.code !== 1005) {
          err = new Error(`WsTransport: closed with code ${ev.code}${ev.reason ? `: ${ev.reason}` : ''}`);
        }
        this.finish(err);
      };
    });
  }

  close(): void {
    if (this.closed) return;
    const ws = this.ws;
    if (ws) {
      try {
        ws.close(1000);
      } catch {
        /* ignore */
      }
      // onclose fires asynchronously; `finish` is idempotent.
    } else {
      this.finish();
    }
  }

  send(bytes: Uint8Array): void {
    const ws = this.ws;
    if (!ws || this.closed || ws.readyState !== WS_OPEN) throw new Error('WsTransport: not connected');
    ws.send(bytes);
  }

  onData(cb: (bytes: Uint8Array) => void): void {
    this.dataCb = cb;
  }

  onClose(cb: (err?: Error) => void): void {
    this.closeCb = cb;
  }

  private finish(err?: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.closeCb?.(err);
  }
}

function toError(ev: unknown, fallback: string): Error {
  if (ev instanceof Error) return ev;
  const e = ev as { error?: unknown; message?: unknown };
  if (e && e.error instanceof Error) return e.error;
  if (e && typeof e.message === 'string' && e.message) return new Error(e.message);
  return new Error(fallback);
}
