/**
 * One P2P connection: framing, version/verack handshake, ping/pong keepalive,
 * addr gossip parsing, and p2pmsg/dp2pmsg delivery. Everything else is ignored.
 */
import { randomBytes } from '../common/bytes.js';
import { CodecError, MessageParser, ProtocolError, encodeMessage, type ParsedMessage } from './codec.js';
import { Emitter } from './emitter.js';
import {
  MessageType,
  NetworkMagic,
  PROTOCOL_VERSION,
  ServiceFlags,
  decodeAddr,
  decodeAddrV2,
  decodePong,
  decodeVersion,
  encodePing,
  encodePong,
  encodeVersion,
  type NetAddress,
  type NetworkName,
  type VersionMessage,
} from './messages.js';
import type { Transport } from './transport.js';

export const DEFAULT_USER_AGENT = '/navio-p2pmsg:0.1.0/';

export interface PeerOptions {
  network: NetworkName;
  userAgent?: string;
  /** Services we advertise. Default `NODE_P2PMSG_LEAF`. */
  services?: bigint;
  startHeight?: number;
  relay?: boolean;
  /** Give up on the handshake after this long. Default 10 s. */
  handshakeTimeoutMs?: number;
  /** Send `ping` this often (0 disables periodic pings). Default 60 s. */
  pingIntervalMs?: number;
  /** Drop the peer if a `pong` does not arrive within this. Default 2 x pingIntervalMs (20 s when periodic pings are off). */
  pongTimeoutMs?: number;
  /** Clock source (unix ms). Default `Date.now`. Exposed for tests. */
  now?: () => number;
}

export interface PeerVersionInfo {
  version: number;
  services: bigint;
  /** Peer's clock at `version` time, unix seconds. */
  timestamp: bigint;
  userAgent: string;
  startHeight: number;
  relay: boolean;
  nonce: bigint;
}

export interface PeerMessage {
  /** true for `dp2pmsg` (stem), false for `p2pmsg` (fluff). */
  stem: boolean;
  payload: Uint8Array;
}

export type PeerEvents = {
  /** Handshake complete. */
  connected: PeerVersionInfo;
  /** A `p2pmsg` / `dp2pmsg` envelope. */
  message: PeerMessage;
  /** Parsed `addr` / `addrv2` entries (one event per message). */
  addr: NetAddress[];
  /** A `pong` matching an outstanding ping; value is the round-trip time in ms. */
  pong: number;
  /** Non-fatal problem (bad checksum, unparsable addr, ...). */
  error: Error;
  /** Connection ended. `undefined` for a clean local close. Emitted exactly once. */
  close: Error | undefined;
};

export type PeerState = 'idle' | 'connecting' | 'handshaking' | 'connected' | 'closed';

export class Peer extends Emitter<PeerEvents> {
  readonly id: string;
  readonly network: NetworkName;
  readonly magic: Uint8Array;
  /** Peer's `version` fields, once received. */
  peerVersion: PeerVersionInfo | null = null;
  /** `peer.timestamp - our clock` at the moment its `version` arrived, in seconds. */
  clockOffsetSeconds = 0;
  /** Unix ms when the handshake completed. */
  connectedAt = 0;

  private _state: PeerState = 'idle';
  private readonly opts: Required<Omit<PeerOptions, 'now'>> & { now: () => number };
  private readonly parser: MessageParser;
  private readonly localNonce: bigint;
  private verackSent = false;
  private verackReceived = false;
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private pongTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingPing: { nonce: bigint; sentAt: number } | null = null;
  private handshake: { resolve: () => void; reject: (e: Error) => void } | null = null;
  private closeError: Error | undefined;

  constructor(
    readonly transport: Transport,
    opts: PeerOptions,
  ) {
    super();
    this.network = opts.network;
    this.magic = NetworkMagic[opts.network];
    if (!this.magic) throw new Error(`unknown network: ${opts.network}`);
    this.id = transport.remote;
    this.opts = {
      network: opts.network,
      userAgent: opts.userAgent ?? DEFAULT_USER_AGENT,
      services: opts.services ?? ServiceFlags.NODE_P2PMSG_LEAF,
      startHeight: opts.startHeight ?? 0,
      relay: opts.relay ?? false,
      handshakeTimeoutMs: opts.handshakeTimeoutMs ?? 10_000,
      pingIntervalMs: opts.pingIntervalMs ?? 60_000,
      pongTimeoutMs: opts.pongTimeoutMs ?? ((opts.pingIntervalMs ?? 60_000) > 0 ? 2 * (opts.pingIntervalMs ?? 60_000) : 20_000),
      now: opts.now ?? (() => Date.now()),
    };
    this.localNonce = new DataView(randomBytes(8).buffer).getBigUint64(0, true);
    this.parser = new MessageParser(this.magic, {
      onError: (e: CodecError) => this.emit('error', e),
    });
    transport.onData((bytes) => this.onData(bytes));
    transport.onClose((err) => this.finish(err));
  }

  get state(): PeerState {
    return this._state;
  }
  /** True once the handshake completed and until close. */
  get connected(): boolean {
    return this._state === 'connected';
  }
  get closed(): boolean {
    return this._state === 'closed';
  }
  get services(): bigint {
    return this.opts.services;
  }

  /**
   * Open the transport and run the handshake. Resolves once both veracks have
   * been exchanged; rejects on timeout or if the connection drops first.
   */
  async connect(): Promise<void> {
    if (this._state !== 'idle') throw new Error(`Peer.connect: invalid state ${this._state}`);
    this._state = 'connecting';
    try {
      await this.transport.connect();
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      this.finish(err);
      throw err;
    }
    if (this._state !== 'connecting') {
      // Closed while the transport was connecting.
      throw this.closeError ?? new Error('Peer: closed during connect');
    }
    this._state = 'handshaking';
    const done = new Promise<void>((resolve, reject) => {
      this.handshake = { resolve, reject };
    });
    this.handshakeTimer = setTimeout(() => {
      this.close(new Error(`Peer: handshake timeout (${this.opts.handshakeTimeoutMs} ms) with ${this.id}`));
    }, this.opts.handshakeTimeoutMs);
    try {
      this.send(MessageType.VERSION, encodeVersion(this.buildVersion()));
    } catch (e) {
      this.close(e instanceof Error ? e : new Error(String(e)));
    }
    return done;
  }

  /** Send a raw message. Throws if the connection is closed. */
  send(command: string, payload: Uint8Array = new Uint8Array(0)): void {
    if (this._state === 'closed' || this._state === 'idle') {
      throw new Error(`Peer.send: not connected (${this._state})`);
    }
    this.transport.send(encodeMessage(this.magic, command, payload));
  }

  /** Send an envelope as `dp2pmsg` (stem) or `p2pmsg` (fluff). Requires a completed handshake. */
  sendP2pMsg(envelope: Uint8Array, stem: boolean): void {
    if (!this.connected) throw new Error('Peer.sendP2pMsg: handshake not complete');
    this.send(stem ? MessageType.DP2PMSG : MessageType.P2PMSG, envelope);
  }

  /** Send a ping now (in addition to the periodic keepalive). */
  ping(): void {
    if (!this.connected || this.pendingPing) return;
    const nonce = new DataView(randomBytes(8).buffer).getBigUint64(0, true);
    this.pendingPing = { nonce, sentAt: this.opts.now() };
    this.send(MessageType.PING, encodePing(nonce));
    this.pongTimer = setTimeout(() => {
      this.close(new Error(`Peer: ping timeout (no pong within ${this.opts.pongTimeoutMs} ms) from ${this.id}`));
    }, this.opts.pongTimeoutMs);
  }

  /** Close the connection. `err` (optional) is reported on the `close` event. Idempotent. */
  close(err?: Error): void {
    if (this._state === 'closed') return;
    this.closeError = this.closeError ?? err;
    this.transport.close();
    // Transports report close asynchronously in some runtimes; finish now so
    // state is consistent for the caller.
    this.finish(this.closeError);
  }

  // -------------------------------------------------------------------------

  private buildVersion(): VersionMessage {
    return {
      version: PROTOCOL_VERSION,
      services: this.opts.services,
      timestamp: BigInt(Math.floor(this.opts.now() / 1000)),
      addrRecv: { services: 0n, host: '::', port: 0 },
      addrFrom: { services: this.opts.services, host: '::', port: 0 },
      nonce: this.localNonce,
      userAgent: this.opts.userAgent,
      startHeight: this.opts.startHeight,
      relay: this.opts.relay,
    };
  }

  private onData(bytes: Uint8Array): void {
    if (this._state === 'closed') return;
    let msgs: ParsedMessage[];
    try {
      msgs = this.parser.feed(bytes);
    } catch (e) {
      this.close(e instanceof ProtocolError ? e : new Error(`Peer: parse failure: ${(e as Error).message}`));
      return;
    }
    for (const m of msgs) {
      if (this.closed) return;
      try {
        this.dispatch(m);
      } catch (e) {
        this.emit('error', e instanceof Error ? e : new Error(String(e)));
      }
    }
  }

  private dispatch(m: ParsedMessage): void {
    switch (m.command) {
      case MessageType.VERSION:
        this.onVersion(m.payload);
        return;
      case MessageType.VERACK:
        if (!this.verackReceived) {
          this.verackReceived = true;
          this.maybeConnected();
        }
        return;
      case MessageType.PING:
        // Echo the nonce (empty payload for pre-BIP31 peers).
        this.send(MessageType.PONG, m.payload.length >= 8 ? encodePong(decodePong(m.payload)!) : new Uint8Array(0));
        return;
      case MessageType.PONG:
        this.onPong(m.payload);
        return;
      case MessageType.ADDR:
        this.emitAddrs(decodeAddr(m.payload));
        return;
      case MessageType.ADDRV2:
        this.emitAddrs(decodeAddrV2(m.payload));
        return;
      case MessageType.P2PMSG:
      case MessageType.DP2PMSG:
        if (!this.connected) return;
        this.emit('message', { stem: m.command === MessageType.DP2PMSG, payload: m.payload });
        return;
      default:
        // inv, headers, sendcmpct, wtxidrelay, feefilter, ... : not our business.
        return;
    }
  }

  private onVersion(payload: Uint8Array): void {
    if (this.peerVersion) {
      this.emit('error', new Error('Peer: duplicate version message'));
      return;
    }
    const v = decodeVersion(payload);
    if (v.nonce !== 0n && v.nonce === this.localNonce) {
      this.close(new Error('Peer: connected to self (nonce collision)'));
      return;
    }
    this.peerVersion = {
      version: v.version,
      services: v.services,
      timestamp: v.timestamp,
      userAgent: v.userAgent,
      startHeight: v.startHeight,
      relay: v.relay,
      nonce: v.nonce,
    };
    this.clockOffsetSeconds = Number(v.timestamp) - Math.floor(this.opts.now() / 1000);
    // BIP155: sendaddrv2 MUST be sent between version and verack; the node
    // disconnects peers that send it after verack. Only for peers that
    // announce >= 70016 (as a courtesy, like Bitcoin Core).
    if (v.version >= 70016) this.send(MessageType.SENDADDRV2);
    this.send(MessageType.VERACK);
    this.verackSent = true;
    this.maybeConnected();
  }

  private maybeConnected(): void {
    if (this._state !== 'handshaking' || !this.verackSent || !this.verackReceived || !this.peerVersion) return;
    this._state = 'connected';
    this.connectedAt = this.opts.now();
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    this.send(MessageType.GETADDR);
    if (this.opts.pingIntervalMs > 0) {
      this.pingTimer = setInterval(() => this.ping(), this.opts.pingIntervalMs);
    }
    const hs = this.handshake;
    this.handshake = null;
    this.emit('connected', this.peerVersion);
    hs?.resolve();
  }

  private onPong(payload: Uint8Array): void {
    const p = this.pendingPing;
    if (!p) return;
    const nonce = decodePong(payload);
    if (nonce !== null && nonce !== p.nonce) return; // stale pong
    this.pendingPing = null;
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = null;
    }
    this.emit('pong', this.opts.now() - p.sentAt);
  }

  private emitAddrs(addrs: NetAddress[]): void {
    if (addrs.length > 0) this.emit('addr', addrs);
  }

  private finish(err?: Error): void {
    if (this._state === 'closed') return;
    this._state = 'closed';
    this.closeError = this.closeError ?? err;
    if (this.handshakeTimer) clearTimeout(this.handshakeTimer);
    if (this.pingTimer) clearInterval(this.pingTimer);
    if (this.pongTimer) clearTimeout(this.pongTimer);
    this.handshakeTimer = null;
    this.pingTimer = null;
    this.pongTimer = null;
    const hs = this.handshake;
    this.handshake = null;
    hs?.reject(this.closeError ?? new Error(`Peer: connection to ${this.id} closed before handshake`));
    this.emit('close', this.closeError);
  }
}
