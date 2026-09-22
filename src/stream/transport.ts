/**
 * The direct client-to-client channel.
 *
 * The bus caps a frame at 3584 bytes and charges a proof of work per envelope,
 * so images, files, new-device history backfill and calls are all impossible
 * on it — four product holes with one cause. A direct channel closes all four.
 *
 * Signalling rides the bus, which is already authenticated, encrypted and
 * reachable; the payload does not.
 *
 * Everything here is transport-agnostic on purpose. WebRTC is the backend that
 * works in both runtimes (a browser cannot accept inbound sockets or speak raw
 * UDP, so any browser-to-Node pair forces it), but the layers above only see
 * this interface, so a raw-UDP or QUIC backend can replace it later.
 */

export type StreamChannelId = 'control' | 'file' | 'media';

export interface StreamChannel {
  readonly id: StreamChannelId;
  send(data: Uint8Array): void;
  onMessage(cb: (data: Uint8Array) => void): () => void;
  close(): void;
}

export interface StreamSession {
  readonly remote: string;
  channel(id: StreamChannelId): StreamChannel;
  onClose(cb: (err?: Error) => void): () => void;
  close(): void;
  readonly closed: boolean;
}

/** Signalling messages the two ends exchange over the bus to meet. */
export interface SignalChannel {
  send(signal: Uint8Array): Promise<void>;
  onSignal(cb: (signal: Uint8Array) => void): () => void;
}

export interface StreamTransport {
  /** Dial the peer. Resolves once a channel is usable. */
  connect(remote: string, signal: SignalChannel): Promise<StreamSession>;
  /** Answer a dial. */
  accept(remote: string, signal: SignalChannel): Promise<StreamSession>;
  /** Whether this backend can run here at all (e.g. the native module loaded). */
  available(): boolean;
}

// ---------------------------------------------------------------------------
// Loopback, for tests and for wiring two sessions in one process.

class LoopbackChannel implements StreamChannel {
  private handlers = new Set<(d: Uint8Array) => void>();
  peer: LoopbackChannel | undefined;
  constructor(readonly id: StreamChannelId) {}

  send(data: Uint8Array): void {
    const copy = data.slice();
    // Asynchronous, like any real transport: code that assumes synchronous
    // delivery would work here and fail over a socket.
    queueMicrotask(() => {
      for (const h of [...(this.peer?.handlers ?? [])]) h(copy);
    });
  }

  onMessage(cb: (data: Uint8Array) => void): () => void {
    this.handlers.add(cb);
    return () => this.handlers.delete(cb);
  }

  close(): void {
    this.handlers.clear();
  }
}

export class LoopbackSession implements StreamSession {
  private readonly channels = new Map<StreamChannelId, LoopbackChannel>();
  private readonly closeHandlers = new Set<(e?: Error) => void>();
  private _closed = false;
  peer: LoopbackSession | undefined;

  constructor(readonly remote: string) {}

  get closed(): boolean {
    return this._closed;
  }

  channel(id: StreamChannelId): StreamChannel {
    let c = this.channels.get(id);
    if (!c) {
      c = new LoopbackChannel(id);
      this.channels.set(id, c);
      const other = this.peer?.channel(id) as LoopbackChannel | undefined;
      if (other) {
        c.peer = other;
        other.peer = c;
      }
    }
    return c;
  }

  onClose(cb: (err?: Error) => void): () => void {
    this.closeHandlers.add(cb);
    return () => this.closeHandlers.delete(cb);
  }

  close(): void {
    if (this._closed) return;
    this._closed = true;
    for (const c of this.channels.values()) c.close();
    for (const h of [...this.closeHandlers]) h();
    this.peer?.close();
  }
}

/** A connected pair of sessions in one process. */
export function loopbackPair(a = 'a', b = 'b'): [LoopbackSession, LoopbackSession] {
  const left = new LoopbackSession(b);
  const right = new LoopbackSession(a);
  left.peer = right;
  right.peer = left;
  return [left, right];
}
