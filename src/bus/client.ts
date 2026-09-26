/**
 * BusClient: the leaf's view of the p2pmsg bus. Mirrors navio-core
 * `p2pmsg::Transport` minus relaying (a leaf relays nothing).
 *
 * Inbound (`onWire`): parse -> pow version -> pow.kind == kind ->
 * payload_hash == SHA256(MsgHash || flag) -> PoW -> timestamp -> duplicate
 * check on the ciphertext; then
 * trial-decrypt off the caller's stack and dispatch to the handler registered
 * for the kind.
 *
 * Outbound (`send`): encrypt -> PoW header -> grind -> serialise -> sink.
 */
import { BROADCAST_PUBLIC } from './bls.js';
import { encrypt, packetMsgHash } from './ecies.js';
import {
  type Envelope,
  expectedPayloadHash,
  MAX_ENVELOPE_BYTES,
  MAX_FLAG_BYTES,
  parseEnvelope,
  messageKey,
  serializeEnvelope,
} from './envelope.js';
import { type BusKeys, type RecipientClass } from './keyring.js';
import {
  checkPoW,
  checkTimestamp,
  DEFAULT_POW_BITS,
  payloadHash,
  type PoWHeader,
  POW_TIMESTAMP_TOLERANCE_SECONDS,
  POW_VERSION_CURRENT,
} from './pow.js';
import { PowGrinder } from './pow-grinder.js';
import { DEFAULT_REPLAY_CAPACITY, ReplayCache } from './replay-cache.js';

/** Where outbound envelopes go (the `net` layer's peer pool, structurally typed). */
export interface EnvelopeSink {
  /** `stem` = send as `dp2pmsg` to one peer; otherwise `p2pmsg` to all. */
  broadcast(envelope: Uint8Array, opts: { stem: boolean }): void;
}

export type Network = 'mainnet' | 'testnet' | 'regtest';

/** navio-core `-p2pmsgpowbits` defaults per chain. */
export const NETWORK_POW_BITS: Record<Network, number> = {
  mainnet: DEFAULT_POW_BITS,
  testnet: DEFAULT_POW_BITS,
  regtest: 8,
};

/** Payload kinds handled by navio-core itself (`p2pmsg::PayloadKind`). The wire field is a plain u8. */
export const PayloadKind = {
  PING: 0,
  PONG: 1,
  AGG_ANN: 2,
  CANDIDATE_TX: 3,
  RFQ_REQ: 4,
  RFQ_QUOTE: 5,
  ORDER_ANN: 6,
  USER_DATA: 7,
} as const;

export type WireResult = 'accepted' | 'invalid' | 'badpow' | 'stale' | 'replay';

export interface InboundMessage {
  kind: number;
  peerId: unknown;
  /** Arrived as `dp2pmsg`. */
  stem: boolean;
  /** The envelope's ephemeral pubkey. */
  senderEph: Uint8Array;
  recipient: RecipientClass;
  sessionPub?: Uint8Array;
  body: Uint8Array;
  envelope: Envelope;
}

export type MessageHandler = (msg: InboundMessage) => void;

export interface BusSendOptions {
  /** Default true (Dandelion stem to one peer). */
  stem?: boolean;
  signal?: AbortSignal;
  onProgress?: (attempts: number) => void;
  /**
   * Detection flag built from the RECIPIENT's clue key (see `./fmd.js`), so a
   * recipient who is offline can retrieve this message from an archiving node
   * later. It is bound by the proof of work and carries no recipient
   * identifier. Omit it if offline retrieval does not matter; the flag costs
   * 83 bytes of the envelope budget.
   */
  flag?: Uint8Array;
}

const EMPTY_FLAG = new Uint8Array(0);

export interface BusClientOptions {
  keys: BusKeys;
  sink: EnvelopeSink;
  /** Chain, used only to pick the default `powBits`. Default 'mainnet'. */
  network?: Network;
  /** Overrides the per-network default. */
  powBits?: number;
  grinder?: PowGrinder;
  /** Seconds to add to the local clock (median peer offset). */
  clockOffsetSeconds?: () => number;
  /** Timestamp tolerance for inbound stamps (seconds). Default 120. */
  timestampToleranceSeconds?: number;
  replayCapacity?: number;
  /** Wall clock in unix seconds (tests). */
  now?: () => number;
  /** Receives exceptions thrown by handlers / decrypt failures. Default: swallow. */
  onError?: (err: unknown) => void;
}

export class PayloadTooLarge extends Error {
  override readonly name = 'PayloadTooLarge';
  constructor(public readonly envelopeBytes: number) {
    super(`envelope would be ${envelopeBytes} bytes, limit ${MAX_ENVELOPE_BYTES}`);
  }
}

export class BusClient {
  readonly keys: BusKeys;
  readonly powBits: number;
  private readonly sink: EnvelopeSink;
  /** Messages already dispatched, keyed on the ciphertext. */
  private readonly delivered: ReplayCache;
  private readonly handlers = new Map<number, Set<MessageHandler>>();
  private readonly clockOffset: () => number;
  private readonly tolerance: number;
  private readonly wallClock: () => number;
  private readonly onError: (err: unknown) => void;
  private grinder: PowGrinder | undefined;
  private ownsGrinder = false;
  private decryptQueue: Promise<void> = Promise.resolve();
  private closed = false;

  constructor(opts: BusClientOptions) {
    this.keys = opts.keys;
    this.sink = opts.sink;
    this.powBits = opts.powBits ?? NETWORK_POW_BITS[opts.network ?? 'mainnet'];
    this.delivered = new ReplayCache(opts.replayCapacity ?? DEFAULT_REPLAY_CAPACITY);
    this.clockOffset = opts.clockOffsetSeconds ?? (() => 0);
    this.tolerance = opts.timestampToleranceSeconds ?? POW_TIMESTAMP_TOLERANCE_SECONDS;
    this.wallClock = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.onError = opts.onError ?? (() => {});
    if (opts.grinder) this.grinder = opts.grinder;
  }

  /** Current unix time in seconds as the bus sees it (wall clock + peer offset). */
  now(): number {
    return Math.floor(this.wallClock() + this.clockOffset());
  }

  /** Register a handler for `kind`. Returns an unsubscribe function. */
  on(kind: number, handler: MessageHandler): () => void {
    let set = this.handlers.get(kind);
    if (!set) this.handlers.set(kind, (set = new Set()));
    set.add(handler);
    return () => {
      set!.delete(handler);
    };
  }

  off(kind: number, handler?: MessageHandler): void {
    if (!handler) this.handlers.delete(kind);
    else this.handlers.get(kind)?.delete(handler);
  }

  /**
   * Net-layer entry point for an inbound `p2pmsg` (`stem=false`) or `dp2pmsg`
   * (`stem=true`) payload. Cheap checks run synchronously; decryption and
   * dispatch are deferred to the event loop.
   */
  onWire(peerId: unknown, stem: boolean, bytes: Uint8Array): WireResult {
    return this.ingest(peerId, stem, bytes, /*archived=*/ false);
  }

  /**
   * An envelope retrieved from an archiving node rather than received live.
   *
   * Identical to `onWire` except that the timestamp window is not enforced: an
   * archived envelope is old by definition, which is the whole point of
   * retrieving it. Everything else — PoW, replay, trial decrypt — is unchanged,
   * so nothing above the bus can tell the difference, and a decoy that fails to
   * decrypt is dropped exactly like any undecryptable message.
   */
  onArchived(peerId: unknown, bytes: Uint8Array): WireResult {
    return this.ingest(peerId, /*stem=*/ false, bytes, /*archived=*/ true);
  }

  private ingest(peerId: unknown, stem: boolean, bytes: Uint8Array, archived: boolean): WireResult {
    if (bytes.length > MAX_ENVELOPE_BYTES) return 'invalid';
    let env: Envelope;
    try {
      env = parseEnvelope(bytes);
    } catch {
      return 'invalid';
    }
    // Envelope v2 only, matching navio-core. v1 headers bound the ciphertext
    // alone, so accepting both would let a v1 stamp be replayed as a v2
    // envelope with an attacker's flag attached.
    if (env.pow.version !== POW_VERSION_CURRENT) return 'invalid';
    if (env.pow.kind !== env.kind) return 'badpow';
    if (!bytesEqual(env.pow.payloadHash, expectedPayloadHash(env))) return 'badpow';
    if (!checkPoW(env.pow, this.powBits)) return 'badpow';
    if (!archived && !checkTimestamp(env.pow, this.now(), this.tolerance)) return 'stale';
    // Keyed on the CIPHERTEXT, with the flag left out, exactly as navio-core
    // keys its relay cache. The flag is a retrieval hint and it is not
    // secret: anyone who saw an envelope could otherwise rewrite it over
    // somebody else's ciphertext, pay one proof of work, and have the message
    // flooded and delivered all over again.
    if (!this.delivered.add(messageKey(env))) return 'replay';
    if (this.closed) return 'accepted';
    this.decryptQueue = this.decryptQueue
      .then(() => new Promise<void>((r) => setTimeout(r, 0)))
      .then(() => this.decryptAndDispatch(peerId, stem, env))
      .catch((e: unknown) => this.onError(e));
    return 'accepted';
  }

  private decryptAndDispatch(peerId: unknown, stem: boolean, env: Envelope): void {
    if (this.closed) return;
    const handlers = this.handlers.get(env.kind);
    if (!handlers || handlers.size === 0) return; // nothing to do; skip the heavy trial decrypt
    const res = this.keys.trialDecrypt(env.kind, env.enc);
    if (!res) return;
    const msg: InboundMessage = {
      kind: env.kind,
      peerId,
      stem,
      senderEph: env.enc.eph,
      recipient: res.recipient,
      body: res.body,
      envelope: env,
    };
    if (res.sessionPub) msg.sessionPub = res.sessionPub;
    for (const h of [...handlers]) {
      try {
        h(msg);
      } catch (e) {
        this.onError(e);
      }
    }
  }

  /** Wait until every accepted envelope so far has been decrypted and dispatched. */
  async drain(): Promise<void> {
    await this.decryptQueue;
  }

  /**
   * Encrypt `body` to `recipientPub`, stamp with PoW and hand to the sink.
   * Resolves with the serialised envelope bytes. Throws `PayloadTooLarge`
   * before grinding if the envelope would exceed 4096 bytes.
   */
  async send(kind: number, recipientPub: Uint8Array, body: Uint8Array, opts: BusSendOptions = {}): Promise<Uint8Array> {
    if (this.closed) throw new Error('BusClient is closed');
    if (kind < 0 || kind > 255 || !Number.isInteger(kind)) throw new Error('kind must be a u8');
    const flag = opts.flag ?? EMPTY_FLAG;
    if (flag.length > MAX_FLAG_BYTES) throw new Error('detection flag too large');
    const aad = new Uint8Array([kind]);
    const enc = encrypt(recipientPub, body, aad);
    const header: PoWHeader = {
      version: POW_VERSION_CURRENT,
      timestamp: BigInt(this.now()),
      kind,
      sessionEph: enc.eph,
      // v2 commits to the flag as well, so the work cannot be reused with a
      // different (or stripped) flag.
      payloadHash: payloadHash(POW_VERSION_CURRENT, packetMsgHash(enc), flag),
      nonce: 0n,
    };
    const draft: Envelope = { kind, pow: header, flag, enc };
    const size = serializeEnvelope(draft).length;
    if (size > MAX_ENVELOPE_BYTES) throw new PayloadTooLarge(size);

    const grindOpts: { signal?: AbortSignal; onProgress?: (a: number) => void } = {};
    if (opts.signal) grindOpts.signal = opts.signal;
    if (opts.onProgress) grindOpts.onProgress = opts.onProgress;
    const pow = await this.getGrinder().grind(header, this.powBits, grindOpts);
    const env: Envelope = { kind, pow, flag, enc };
    const bytes = serializeEnvelope(env);
    // Our own message will be fluffed back to us by peers; pre-mark it seen.
    this.delivered.add(messageKey(env));
    this.sink.broadcast(bytes, { stem: opts.stem ?? true });
    return bytes;
  }

  /** `send` to the well-known broadcast key (anyone can decrypt). */
  sendBroadcast(kind: number, body: Uint8Array, opts: BusSendOptions = {}): Promise<Uint8Array> {
    return this.send(kind, BROADCAST_PUBLIC, body, opts);
  }

  /**
   * Largest body (bytes) that fits an envelope for this client.
   * `flagBytes` is the size of the detection flag the send will carry, if any
   * — it comes out of the same 4096-byte budget.
   */
  static maxBodyBytes(flagBytes = 0): number {
    // 1 kind + 98 pow + 1 flen + 48 eph + 3 compactsize + 16 tag = 167 overhead;
    // ct = 4 + len (unpadded above 3580).
    return MAX_ENVELOPE_BYTES - 167 - flagBytes - 4;
  }

  private getGrinder(): PowGrinder {
    if (!this.grinder) {
      this.grinder = new PowGrinder();
      this.ownsGrinder = true;
    }
    return this.grinder;
  }

  close(): void {
    this.closed = true;
    if (this.ownsGrinder) this.grinder?.close();
    this.handlers.clear();
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
