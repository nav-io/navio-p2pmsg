/**
 * In-memory transports for tests (exported so other layers can simulate a node
 * without sockets). `MockTransport.pair()` returns two ends of a duplex pipe;
 * `MockNode` drives one end like a minimal naviod.
 */
import { MessageParser, encodeMessage, type ParsedMessage } from './codec.js';
import { Emitter } from './emitter.js';
import {
  MessageType,
  NetworkMagic,
  PROTOCOL_VERSION,
  ServiceFlags,
  decodePing,
  decodeVersion,
  encodeAddrV2,
  encodePong,
  encodeVersion,
  type NetAddress,
  type NetworkName,
  type VersionMessage,
} from './messages.js';
import type { Transport } from './transport.js';

export interface MockTransportOptions {
  /** Reject `connect()` with this error. */
  failConnect?: Error;
  /** Delay `connect()` resolution (ms). */
  connectDelayMs?: number;
  /** Never resolve `connect()` (simulates a black hole). */
  hangConnect?: boolean;
}

export class MockTransport implements Transport {
  peer: MockTransport | null = null;
  /** Every chunk passed to `send()`, in order. */
  readonly sent: Uint8Array[] = [];
  private dataCb: ((bytes: Uint8Array) => void) | null = null;
  private closeCb: ((err?: Error) => void) | null = null;
  private _connected = false;
  private _closed = false;
  private pending: Uint8Array[] = [];

  constructor(
    readonly remote: string,
    private readonly opts: MockTransportOptions = {},
  ) {}

  /** Two connected ends. Bytes sent on one arrive (asynchronously) on the other. */
  static pair(remoteA = 'mock-a', remoteB = 'mock-b', opts: MockTransportOptions = {}): [MockTransport, MockTransport] {
    const a = new MockTransport(remoteA, opts);
    const b = new MockTransport(remoteB);
    a.peer = b;
    b.peer = a;
    // The "server" end is considered connected as soon as it exists.
    b._connected = true;
    return [a, b];
  }

  get connected(): boolean {
    return this._connected && !this._closed;
  }
  get closed(): boolean {
    return this._closed;
  }

  async connect(): Promise<void> {
    if (this._closed) throw new Error('MockTransport: closed');
    if (this.opts.hangConnect) return new Promise<void>(() => {});
    if (this.opts.connectDelayMs) await new Promise((r) => setTimeout(r, this.opts.connectDelayMs));
    if (this.opts.failConnect) {
      this._closed = true;
      throw this.opts.failConnect;
    }
    this._connected = true;
    // Flush anything the other end sent before we "connected".
    const q = this.pending;
    this.pending = [];
    for (const b of q) this.deliver(b);
  }

  close(): void {
    this.closeWith(undefined);
  }

  /** Close both ends as if the connection dropped with `err`. */
  closeWith(err: Error | undefined): void {
    if (this._closed) return;
    this._closed = true;
    this._connected = false;
    const p = this.peer;
    queueMicrotask(() => {
      this.closeCb?.(err);
      p?.closeWith(undefined);
    });
  }

  send(bytes: Uint8Array): void {
    if (!this._connected || this._closed) throw new Error('MockTransport: not connected');
    const copy = bytes.slice();
    this.sent.push(copy);
    this.peer?.receive(copy);
  }

  onData(cb: (bytes: Uint8Array) => void): void {
    this.dataCb = cb;
  }
  onClose(cb: (err?: Error) => void): void {
    this.closeCb = cb;
  }

  /** Inject bytes as if they arrived from the network (bypasses the peer end). */
  receive(bytes: Uint8Array): void {
    if (this._closed) return;
    if (!this._connected) {
      this.pending.push(bytes);
      return;
    }
    this.deliver(bytes);
  }

  private deliver(bytes: Uint8Array): void {
    queueMicrotask(() => {
      if (!this._closed) this.dataCb?.(bytes);
    });
  }
}

export interface MockNodeOptions {
  network: NetworkName;
  services?: bigint;
  userAgent?: string;
  startHeight?: number;
  /** Reply to `version` with version + sendaddrv2 + verack. Default true. */
  autoHandshake?: boolean;
  /** Reply to `ping` with `pong`. Default true. */
  respondPing?: boolean;
  /** Addresses to gossip in reply to `getaddr`. */
  addrs?: NetAddress[];
  /** Skew the node's clock by this many seconds in its `version.timestamp`. */
  clockSkewSeconds?: number;
  /** Protocol version to announce. Default PROTOCOL_VERSION. */
  version?: number;
}

export type MockNodeEvents = {
  message: ParsedMessage;
  close: Error | undefined;
};

/** A scripted remote node sitting on the far end of a `MockTransport`. */
export class MockNode extends Emitter<MockNodeEvents> {
  readonly received: ParsedMessage[] = [];
  readonly magic: Uint8Array;
  peerVersion: VersionMessage | null = null;
  verackReceived = false;
  private readonly parser: MessageParser;
  private readonly opts: MockNodeOptions;
  private _closed = false;

  constructor(
    readonly transport: MockTransport,
    opts: MockNodeOptions,
  ) {
    super();
    this.opts = opts;
    this.magic = NetworkMagic[opts.network];
    this.parser = new MessageParser(this.magic);
    transport.onData((b) => {
      for (const m of this.parser.feed(b)) this.handle(m);
    });
    transport.onClose((err) => {
      this._closed = true;
      this.emit('close', err);
    });
  }

  get closed(): boolean {
    return this._closed;
  }
  get handshakeComplete(): boolean {
    return this.peerVersion !== null && this.verackReceived;
  }

  send(command: string, payload: Uint8Array = new Uint8Array(0)): void {
    this.transport.send(encodeMessage(this.magic, command, payload));
  }

  sendP2pMsg(payload: Uint8Array, stem = false): void {
    this.send(stem ? MessageType.DP2PMSG : MessageType.P2PMSG, payload);
  }

  sendAddrV2(addrs: NetAddress[]): void {
    this.send(MessageType.ADDRV2, encodeAddrV2(addrs));
  }

  close(): void {
    this.transport.close();
  }

  /** Wait until a message with `command` has been received (or timeout). */
  waitFor(command: string, timeoutMs = 2000): Promise<ParsedMessage> {
    const hit = this.received.find((m) => m.command === command);
    if (hit) return Promise.resolve(hit);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        off();
        reject(new Error(`MockNode: timeout waiting for '${command}'`));
      }, timeoutMs);
      const off = this.on('message', (m) => {
        if (m.command === command) {
          clearTimeout(timer);
          off();
          resolve(m);
        }
      });
    });
  }

  private handle(m: ParsedMessage): void {
    this.received.push(m);
    switch (m.command) {
      case MessageType.VERSION:
        this.peerVersion = decodeVersion(m.payload);
        if (this.opts.autoHandshake ?? true) {
          this.send(MessageType.VERSION, encodeVersion(this.buildVersion()));
          this.send(MessageType.SENDADDRV2);
          this.send(MessageType.VERACK);
        }
        break;
      case MessageType.VERACK:
        this.verackReceived = true;
        break;
      case MessageType.PING:
        if (this.opts.respondPing ?? true) {
          const nonce = decodePing(m.payload);
          this.send(MessageType.PONG, nonce === null ? new Uint8Array(0) : encodePong(nonce));
        }
        break;
      case MessageType.GETADDR:
        if (this.opts.addrs && this.opts.addrs.length > 0) this.sendAddrV2(this.opts.addrs);
        break;
      default:
        break;
    }
    this.emit('message', m);
  }

  private buildVersion(): VersionMessage {
    return {
      version: this.opts.version ?? PROTOCOL_VERSION,
      services: this.opts.services ?? ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG_V2,
      timestamp: BigInt(Math.floor(Date.now() / 1000) + (this.opts.clockSkewSeconds ?? 0)),
      addrRecv: { services: 0n, host: '127.0.0.1', port: 0 },
      addrFrom: { services: 0n, host: '::', port: 0 },
      nonce: BigInt(Math.floor(Math.random() * 2 ** 52)),
      userAgent: this.opts.userAgent ?? '/MockNode:0.0.1/',
      startHeight: this.opts.startHeight ?? 1234,
      relay: true,
    };
  }
}
