/**
 * Node-only TCP transport over `node:net`. The module is imported lazily inside
 * `connect()` so this file can be bundled for browsers as long as it is never
 * invoked there. This is the ONLY file in the library allowed to touch `Buffer`.
 */
import type { Socket } from 'node:net';
import { formatHostPort, type Transport } from './transport.js';

export interface TcpTransportOptions {
  /** Abort `connect()` if the TCP handshake takes longer than this. Default 10 s. */
  connectTimeoutMs?: number;
  /** Disable Nagle. Default true (P2P messages are small and latency-sensitive). */
  noDelay?: boolean;
}

export class TcpTransport implements Transport {
  readonly remote: string;
  private socket: Socket | null = null;
  private dataCb: ((bytes: Uint8Array) => void) | null = null;
  private closeCb: ((err?: Error) => void) | null = null;
  private closed = false;
  private lastError: Error | undefined;
  private readonly connectTimeoutMs: number;
  private readonly noDelay: boolean;

  constructor(
    readonly host: string,
    readonly port: number,
    opts: TcpTransportOptions = {},
  ) {
    this.remote = formatHostPort(host, port);
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
    this.noDelay = opts.noDelay ?? true;
  }

  async connect(): Promise<void> {
    if (this.socket) throw new Error('TcpTransport: already connected');
    if (this.closed) throw new Error('TcpTransport: closed');
    const net = await import('node:net');
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port });
      this.socket = socket;
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        const err = new Error(`TcpTransport: connect timeout to ${this.remote}`);
        this.lastError = err;
        socket.destroy(err);
        reject(err);
      }, this.connectTimeoutMs);

      socket.once('connect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.setNoDelay(this.noDelay);
        resolve();
      });
      socket.on('error', (err: Error) => {
        this.lastError = err;
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      });
      socket.on('data', (chunk: Buffer) => {
        // View, not copy: the parser copies what it needs to keep.
        this.dataCb?.(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
      });
      socket.on('close', () => {
        this.finish(this.lastError);
      });
    });
  }

  close(): void {
    if (this.closed) return;
    const s = this.socket;
    if (s) {
      s.destroy();
    } else {
      this.finish();
    }
  }

  send(bytes: Uint8Array): void {
    const s = this.socket;
    if (!s || this.closed || s.destroyed) throw new Error('TcpTransport: not connected');
    s.write(bytes);
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
