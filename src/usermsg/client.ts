/**
 * MessagingClient — the library's public, application-agnostic surface.
 * Identity + addressing + encryption + reliable 1:1 delivery + pub/sub over
 * the p2pmsg bus. Application payloads are opaque bytes.
 */
import { Emitter } from '../net/emitter.js';
import { PeerPool, type PeerPoolOptions } from '../net/pool.js';
import type { NetworkName } from '../net/messages.js';
import { BusClient, type InboundMessage } from '../bus/client.js';
import { BusKeys } from '../bus/keyring.js';
import { PowGrinder } from '../bus/pow-grinder.js';
import { generateSecret, publicKey } from '../bus/bls.js';
import { concat, equal, randomBytes, toHex } from '../common/bytes.js';
import type { Store } from '../stores/store.js';
import { MemoryStore } from '../stores/memory-store.js';
import { snapshotStore, restoreStore, type StoreSnapshot } from '../stores/store.js';
import { Keyring, verifyBundle, verifyExtendedBundle } from './keyring.js';
import { Contacts } from './contacts.js';
import { Outbox, type OutboxEntry } from './outbox.js';
import { Reassembler, splitChunks } from './chunker.js';
import { signAuthFrame, verifyAuthFrame } from './auth.js';
import {
  type AuthFrame,
  BROADCAST_RECIPIENT,
  MSG_ID_BYTES,
  USER_DATA_KIND,
  parseAuthFrame,
  parseUserMsgFrame,
  serializeAuthFrame,
  serializeUserMsgFrame,
} from './frame.js';
import {
  type Bundle,
  decodeContact,
  encodeBundle,
  encodeIdentity,
  type ExtendedBundle,
  isExtendedBundle,
  parseAnyBundle,
  serializeExtendedBundle,
  BUNDLE_BYTES,
  EXTENDED_BUNDLE_BYTES,
} from './bundle.js';
import { extractDetectionKey, fmdFlag, isValidClueKey, parseClueKey } from '../bus/fmd.js';
import { ArchiveClient, type SyncResult } from '../archive/client.js';
import {
  ACK_WHOLE,
  TOPIC_ACK,
  TOPIC_DEFAULT,
  TOPIC_PREKEY_RESPONSE,
  isReservedTopic,
  parseAcks,
  prekeyRequestTopic,
  serializeAcks,
  type AckEntry,
} from './topics.js';

export type MessageScope = 'inbox' | 'session' | 'broadcast';

export interface IncomingMessage {
  msgId: Uint8Array;
  /** Sender identity (navid1…) when the frame was signed, else undefined. */
  from?: string;
  fromIdentity?: Uint8Array;
  topic: string;
  payload: Uint8Array;
  scope: MessageScope;
  timestamp: number; // unix seconds as claimed by the sender
}

export interface SendOptions {
  topic?: string;
  /** Give up after this long without an ack. Default 24 h. */
  ttlMs?: number;
  /** Sign with our identity (default true). Unsigned 1:1 messages cannot be acked. */
  sign?: boolean;
  /** Dandelion stem (default true) or plain fluff. */
  stem?: boolean;
  /**
   * Attach a detection flag so the recipient can retrieve this message from an
   * archiving node if they were offline. Default true whenever we hold the
   * recipient's verified clue key; set false to save 83 bytes per envelope when
   * offline retrieval does not matter. The flag carries no recipient
   * identifier — see `../bus/fmd.js`.
   */
  archivable?: boolean;
  signal?: AbortSignal;
}

export interface PublishOptions {
  sign?: boolean;
  stem?: boolean;
  signal?: AbortSignal;
}

/** Subset of PeerPool the client depends on; injectable for tests. */
export interface PeerNetwork {
  start(): Promise<void>;
  stop(): void;
  broadcast(envelope: Uint8Array, opts: { stem: boolean }): number;
  medianClockOffset(): number;
  readonly connectedCount: number;
  on(event: 'message', cb: (m: { peerId: string; stem: boolean; payload: Uint8Array }) => void): () => void;
  on(event: 'peer', cb: (p: { id: string; address: string }) => void): () => void;
  on(event: 'peerclose', cb: (p: { id: string; address: string }) => void): () => void;
  on(event: 'error', cb: (e: Error) => void): () => void;
}

export interface MessagingClientOptions {
  network: NetworkName;
  /** Inject a pre-built peer network (tests / custom transports). Overrides peers/targetPeers/dnsSeeds. */
  pool?: PeerNetwork;
  /** 32-byte seed; the app owns backup/recovery (mnemonic etc.). */
  seed: Uint8Array;
  store?: Store;
  /** Peer addresses: `host:port`, `ws://…`, `wss://…`. */
  peers?: string[];
  targetPeers?: number;
  dnsSeeds?: string[];
  transportFactory?: PeerPoolOptions['transportFactory'];
  powWorkers?: number;
  /** Override the network's PoW difficulty (tests). */
  powBits?: number;
  /**
   * Link transport. Default 'v1'.
   *
   * 'v2' opens connections with BIP324, which encrypts and authenticates the
   * whole link; peers that only speak v1 are redialled as v1 automatically.
   * Worth turning on before `syncArchive()`, which hands a node an FMD
   * detection key — on a v1 link anyone on the path collects it and can then
   * test every future message addressed to us.
   */
  transportVersion?: 'v1' | 'v2' | 'v2-only';
  /** Chunks per message before `send` throws. Default 16. */
  maxChunks?: number;
  messageTtlMs?: number;
  /** Coalesce acks for this long. Default 2000 ms. */
  ackDelayMs?: number;
  /** Prekey discovery timeout. Default 30 s. */
  discoveryTimeoutMs?: number;
  /** How often the outbox is checked for retries. Default 5 s. */
  retryTickMs?: number;
  /** Lifetime of reply keys we hand out. Default 7 d. */
  replyKeyTtlMs?: number;
  userAgent?: string;
  /** Service bits to advertise. Default `NODE_P2PMSG_LEAF`. */
  services?: bigint;
  now?: () => number;
}

export type MessagingEvents = {
  message: IncomingMessage;
  /**
   * A USER_DATA frame addressed to us whose body is not a library AuthFrame
   * (e.g. sent by `naviod`'s `sendp2pmsg` RPC or another app). Unauthenticated.
   */
  raw: { topic: string; body: Uint8Array; scope: MessageScope };
  /** All chunks of an outgoing message were acked by the recipient. */
  ack: { msgId: Uint8Array; to: string };
  /** Outgoing message gave up (no ack before TTL). */
  expired: { msgId: Uint8Array; to: string };
  /** An attempt to broadcast a message/chunk went out (`peers` = how many peers it was sent to). */
  sent: { msgId: Uint8Array; chunk: number; attempt: number; peers: number };
  /** A verified prekey bundle was learned for a contact. */
  contact: { identity: string; bundle: string };
  peer: { id: string; address: string };
  peerclose: { id: string; address: string };
  error: Error;
};

interface PendingAck {
  identity: Uint8Array;
  key: Uint8Array; // where to send the ack
  entries: AckEntry[];
  timer: ReturnType<typeof setTimeout>;
}

const SEEN_CAPACITY = 16384;
const REPLY_KEYS_PER_CONTACT = 4;
const NS_SEEN = 'seen';

export class MessagingClient extends Emitter<MessagingEvents> {
  readonly network: NetworkName;
  readonly pool: PeerNetwork;
  readonly bus: BusClient;
  readonly keys: BusKeys;
  /**
   * Session keys that are SHARED with more than one party (today: group keys).
   * Inbound frames encrypted to one of these verify their signature against
   * the shared key rather than our identity, and are never acked.
   */
  private readonly sharedKeys = new Set<string>();
  readonly keyring: Keyring;
  readonly contacts: Contacts;
  readonly outbox: Outbox;
  readonly store: Store;

  private readonly opts: Required<
    Pick<MessagingClientOptions, 'maxChunks' | 'ackDelayMs' | 'discoveryTimeoutMs' | 'retryTickMs' | 'replyKeyTtlMs' | 'messageTtlMs'>
  >;
  private readonly now: () => number;
  private readonly grinder: PowGrinder;
  private readonly reassembler: Reassembler;
  private readonly subscriptions = new Map<string, Set<(m: IncomingMessage) => void>>();
  private readonly pendingAcks = new Map<string, PendingAck>();
  private readonly discoveries = new Map<string, { sessionPub: Uint8Array; resolve: (b: Bundle) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  /** Our live reply keys per contact, newest last. Older ones stay valid until pushed out or expired. */
  private readonly replyKeys = new Map<string, Uint8Array[]>();
  private readonly seen = new Map<string, true>();
  private readonly inflight = new Set<string>();
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retrying = false;
  private closed = false;
  private lastPrekeyReply = new Map<string, number>();

  private constructor(o: MessagingClientOptions, store: Store, keyring: Keyring, contacts: Contacts, outbox: Outbox) {
    super();
    this.network = o.network;
    this.store = store;
    this.keyring = keyring;
    this.contacts = contacts;
    this.outbox = outbox;
    this.now = o.now ?? (() => Date.now());
    this.opts = {
      maxChunks: o.maxChunks ?? 16,
      ackDelayMs: o.ackDelayMs ?? 2000,
      discoveryTimeoutMs: o.discoveryTimeoutMs ?? 30_000,
      retryTickMs: o.retryTickMs ?? 5000,
      replyKeyTtlMs: o.replyKeyTtlMs ?? 7 * 24 * 3600 * 1000,
      messageTtlMs: o.messageTtlMs ?? 24 * 3600 * 1000,
    };
    this.reassembler = new Reassembler({ now: this.now });

    this.keys = new BusKeys();
    this.keys.setInbox(keyring.prekey.sk, keyring.prekey.pub);
    if (keyring.previousPrekey) this.keys.addGraceInbox(keyring.previousPrekey.sk);

    const poolOpts: PeerPoolOptions = { network: o.network };
    if (o.transportVersion !== undefined) poolOpts.transportVersion = o.transportVersion;
    if (o.peers) poolOpts.seeds = o.peers;
    if (o.targetPeers !== undefined) poolOpts.targetPeers = o.targetPeers;
    if (o.dnsSeeds) poolOpts.dnsSeeds = o.dnsSeeds;
    if (o.transportFactory) poolOpts.transportFactory = o.transportFactory;
    if (o.userAgent) poolOpts.userAgent = o.userAgent;
    if (o.services !== undefined) poolOpts.services = o.services;
    this.pool = o.pool ?? new PeerPool(poolOpts);

    this.grinder = new PowGrinder(o.powWorkers !== undefined ? { workers: o.powWorkers } : {});
    const busOpts: ConstructorParameters<typeof BusClient>[0] = {
      keys: this.keys,
      sink: this.pool,
      grinder: this.grinder,
      network: o.network,
      clockOffsetSeconds: () => this.pool.medianClockOffset(),
    };
    if (o.powBits !== undefined) busOpts.powBits = o.powBits;
    this.bus = new BusClient(busOpts);

    this.pool.on('message', (m) => {
      this.bus.onWire(m.peerId, m.stem, m.payload);
    });
    this.pool.on('peer', (p) => this.emit('peer', { id: p.id, address: p.address }));
    this.pool.on('peerclose', (p) => this.emit('peerclose', { id: p.id, address: p.address }));
    this.pool.on('error', (e) => this.emit('error', e));
    this.bus.on(USER_DATA_KIND, (m) => {
      this.onUserData(m).catch((e) => this.emit('error', e as Error));
    });
  }

  static async create(o: MessagingClientOptions): Promise<MessagingClient> {
    const store = o.store ?? new MemoryStore();
    const now = o.now ?? (() => Date.now());
    const keyring = await Keyring.open(o.seed, store, now);
    const contacts = new Contacts(store, now);
    await contacts.load();
    const outbox = new Outbox(store, { now, ttlMs: o.messageTtlMs });
    await outbox.load();
    const client = new MessagingClient(o, store, keyring, contacts, outbox);
    await client.loadSeen();
    return client;
  }

  // ---------------------------------------------------------------- identity

  /** Our stable address, `navid1…`. */
  get identity(): string {
    return encodeIdentity(this.keyring.identity.pub);
  }
  get identityBytes(): Uint8Array {
    return this.keyring.identity.pub;
  }
  /**
   * Register a session key that is shared with several parties, such as a
   * group key. Changes how inbound frames encrypted to it are authenticated —
   * see `sharedKeys`.
   */
  registerSharedKey(sk: Uint8Array, pub: Uint8Array): void {
    this.keys.addSessionKey(sk, pub);
    this.sharedKeys.add(toHex(pub));
  }

  /**
   * Our FMD clue key (1152 bytes): what a sender needs in order to flag a
   * message so we can retrieve it from an archiving node after being offline.
   * Published automatically over prekey discovery; exposed here for apps that
   * distribute contact details out of band. Public, safe to share.
   */
  clueKey(): Uint8Array {
    return this.keyring.fmdClueKey();
  }

  /**
   * Detection key at false-positive rate `2^-precision`, for querying an
   * archiving node.
   *
   * SECRET, and long-lived: whoever holds it can test every future flag at this
   * precision until the prekey rotates. Lower precision means more decoys, more
   * bandwidth and a larger anonymity set; the maximum tells the holder exactly
   * which messages are ours. The choice is deliberately the caller's.
   */
  detectionKey(precision: number): Uint8Array {
    return extractDetectionKey(this.keyring.fmd, precision);
  }

  /**
   * Retrieve messages that arrived while we were offline, from connected peers
   * advertising `NODE_P2PMSG_ARCHIVE`. Resolves to what was fetched; retrieved
   * messages surface through the ordinary `message` event, so an application
   * does not have to treat them specially.
   *
   * Requires a `PeerPool` (the default). Returns zero peers when the network
   * was supplied by the application or no archiving peer is connected.
   *
   * `precision` is the false-positive exponent: lower means more decoys, more
   * bandwidth and a larger anonymity set, and the maximum tells the archiving
   * node almost exactly which messages are ours. Default 8.
   */
  async syncArchive(opts: { precision?: number; limit?: number } = {}): Promise<SyncResult> {
    const pool = this.pool;
    if (!(pool instanceof PeerPool)) {
      return { received: 0, accepted: 0, complete: true, peers: 0 };
    }
    const precision = opts.precision ?? 8;
    const archive = new ArchiveClient({
      pool,
      bus: this.bus,
      store: this.store,
      precision,
      powBits: this.bus.powBits,
      ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
    });
    try {
      return await archive.sync(this.detectionKey(precision));
    } finally {
      archive.close();
    }
  }

  /** Full contact bundle, `navmsg1…` (identity + current prekey + signature). */
  bundle(): string {
    return encodeBundle(this.keyring.bundle());
  }
  bundleBytes(): Bundle {
    return this.keyring.bundle();
  }

  async rotatePrekey(): Promise<void> {
    const fresh = await this.keyring.rotatePrekey();
    this.keys.rotateInbox(fresh.sk, fresh.pub);
  }

  // ---------------------------------------------------------------- lifecycle

  async connect(): Promise<void> {
    if (this.closed) throw new Error('client closed');
    await this.pool.start();
    this.scheduleRetry(0);
  }

  close(): void {
    this.closed = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    for (const p of this.pendingAcks.values()) clearTimeout(p.timer);
    for (const d of this.discoveries.values()) {
      clearTimeout(d.timer);
      d.reject(new Error('client closed'));
    }
    this.discoveries.clear();
    this.pool.stop();
    this.grinder.close();
    void this.store.flush?.();
  }

  /** Snapshot of keys/contacts/outbox for apps that persist state themselves. */
  exportState(): Promise<StoreSnapshot> {
    return snapshotStore(this.store, ['keys', 'contacts', 'outbox', NS_SEEN]);
  }
  static importState(store: Store, snap: StoreSnapshot): Promise<void> {
    return restoreStore(store, snap);
  }

  // ---------------------------------------------------------------- contacts

  /**
   * Learn a contact from a `navmsg1…` bundle string (verifies the prekey
   * signature) or note a bare `navid1…` identity for later discovery.
   */
  async addContact(contact: string): Promise<string> {
    const { identity, bundle } = decodeContact(contact);
    if (bundle) await this.learnBundle(bundle);
    else await this.contacts.touch(identity);
    return encodeIdentity(identity);
  }

  private async learnBundle(bundle: Bundle | ExtendedBundle): Promise<void> {
    if (!verifyBundle(bundle)) throw new Error('bundle signature invalid');
    const existing = this.contacts.get(bundle.identity);
    const changed = !existing?.bundle || !equal(existing.bundle.prekey, bundle.prekey);
    await this.contacts.setBundle(bundle);
    if (isExtendedBundle(bundle)) {
      // Verify the clue key under the same identity before storing it:
      // flagging to a substituted clue key would hand the retrieval side to
      // whoever substituted it. A bad signature costs us only the clue key, so
      // keep the prekey and fall back to unflagged sends.
      if (verifyExtendedBundle(bundle) && isValidClueKey(bundle.fmdClueKey)) {
        await this.contacts.setClueKey(bundle.identity, bundle.fmdClueKey, bundle.fmdEpoch);
      }
    }
    if (changed) this.emit('contact', { identity: encodeIdentity(bundle.identity), bundle: encodeBundle(bundle) });
  }

  /**
   * A fresh detection flag for `identity`, or undefined when we hold no
   * verified clue key for them (in which case the message is delivered
   * normally but cannot be retrieved later).
   */
  private flagFor(identity: Uint8Array): Uint8Array | undefined {
    const clueKey = this.contacts.get(identity)?.clueKey;
    if (!clueKey) return undefined;
    try {
      return fmdFlag(parseClueKey(clueKey));
    } catch {
      return undefined;
    }
  }

  /** Find a contact's current prekey bundle over the bus. */
  async discover(identity: Uint8Array | string, timeoutMs = this.opts.discoveryTimeoutMs): Promise<Bundle> {
    const id = typeof identity === 'string' ? decodeContact(identity).identity : identity;
    const key = toHex(id);
    const existing = this.discoveries.get(key);
    if (existing) {
      return new Promise((resolve, reject) => {
        const prevResolve = existing.resolve;
        const prevReject = existing.reject;
        existing.resolve = (b) => {
          prevResolve(b);
          resolve(b);
        };
        existing.reject = (e) => {
          prevReject(e);
          reject(e);
        };
      });
    }
    const sk = generateSecret();
    const pub = publicKey(sk);
    this.keys.addSessionKey(sk, pub, timeoutMs + 5000);
    const result = new Promise<Bundle>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.discoveries.delete(key);
        this.keys.removeSessionKey(pub);
        reject(new Error(`prekey discovery for ${encodeIdentity(id)} timed out`));
      }, timeoutMs);
      this.discoveries.set(key, { sessionPub: pub, resolve, reject, timer });
    });
    const frame: AuthFrame = { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), replyPub: pub, payload: new Uint8Array(0) };
    const body = serializeUserMsgFrame({ topic: prekeyRequestTopic(id), body: serializeAuthFrame(frame) });
    await this.bus.sendBroadcast(USER_DATA_KIND, body, { stem: true });
    return result;
  }

  // ---------------------------------------------------------------- sending

  /**
   * Send an application payload 1:1. Resolves with the message id once the
   * first transmission is on the wire; delivery is confirmed by the `ack` event.
   */
  async send(to: string, payload: Uint8Array, opts: SendOptions = {}): Promise<Uint8Array> {
    const topic = opts.topic ?? TOPIC_DEFAULT;
    if (isReservedTopic(topic)) throw new Error('topic prefix _p2pmsg/ is reserved');
    const { identity, bundle } = decodeContact(to);
    if (bundle) await this.learnBundle(bundle);
    const chunks = splitChunks(payload, topic, this.opts.maxChunks);
    const entry = await this.outbox.add({
      msgId: randomBytes(MSG_ID_BYTES),
      recipient: identity,
      topic,
      chunks,
      ...(opts.ttlMs !== undefined ? { ttlMs: opts.ttlMs } : {}),
    });
    if (opts.sign === false) {
      // Unsigned: fire and forget — nobody can ack an anonymous sender.
      await this.transmit(entry, {
        sign: false,
        stem: opts.stem ?? true,
        ...(opts.archivable !== undefined ? { archivable: opts.archivable } : {}),
        signal: opts.signal,
      });
      await this.outbox.remove(entry.msgId);
      return entry.msgId;
    }
    await this.transmit(entry, {
      sign: true,
      stem: opts.stem ?? true,
      ...(opts.archivable !== undefined ? { archivable: opts.archivable } : {}),
      signal: opts.signal,
    });
    return entry.msgId;
  }

  /** Publish to a public topic (readable by every bus participant). */
  async publish(topic: string, payload: Uint8Array, opts: PublishOptions = {}): Promise<Uint8Array> {
    if (isReservedTopic(topic)) throw new Error('topic prefix _p2pmsg/ is reserved');
    const chunks = splitChunks(payload, topic, this.opts.maxChunks);
    const msgId = randomBytes(MSG_ID_BYTES);
    for (let i = 0; i < chunks.length; i++) {
      const base: Omit<AuthFrame, 'sender' | 'sig'> = {
        msgId,
        timestamp: this.nowSeconds(),
        payload: chunks[i]!,
        ...(chunks.length > 1 ? { chunk: { idx: i, total: chunks.length } } : {}),
      };
      const inner = opts.sign === false ? serializeAuthFrame(base) : signAuthFrame(base, this.keyring.identity, topic, BROADCAST_RECIPIENT);
      const body = serializeUserMsgFrame({ topic, body: inner });
      await this.bus.sendBroadcast(USER_DATA_KIND, body, { stem: opts.stem ?? true, ...(opts.signal ? { signal: opts.signal } : {}) });
    }
    return msgId;
  }

  subscribe(topic: string, handler: (m: IncomingMessage) => void): () => void {
    let set = this.subscriptions.get(topic);
    if (!set) {
      set = new Set();
      this.subscriptions.set(topic, set);
    }
    set.add(handler);
    return () => this.unsubscribe(topic, handler);
  }

  unsubscribe(topic: string, handler?: (m: IncomingMessage) => void): void {
    if (!handler) this.subscriptions.delete(topic);
    else {
      const set = this.subscriptions.get(topic);
      set?.delete(handler);
      if (set && set.size === 0) this.subscriptions.delete(topic);
    }
  }

  /** Where to encrypt the next message for `identity`: one-shot reply key, else verified prekey (discovering if needed). */
  private async recipientKey(identity: Uint8Array): Promise<Uint8Array> {
    const next = await this.contacts.takeNextKey(identity);
    if (next) return next;
    const c = this.contacts.get(identity);
    if (c?.bundle) return c.bundle.prekey;
    const bundle = await this.discover(identity);
    return bundle.prekey;
  }

  /**
   * Mint a fresh reply key for a contact. The previous few stay registered:
   * a message or ack encrypted to an older key may still be in flight (an ack
   * flush and a transmit to the same contact can interleave), and revoking it
   * immediately would silently drop that traffic and force a retry to the prekey.
   */
  private mintReplyKey(identity: Uint8Array): Uint8Array {
    const key = toHex(identity);
    const sk = generateSecret();
    const pub = publicKey(sk);
    this.keys.addSessionKey(sk, pub, this.opts.replyKeyTtlMs);
    const list = this.replyKeys.get(key) ?? [];
    list.push(pub);
    while (list.length > REPLY_KEYS_PER_CONTACT) this.keys.removeSessionKey(list.shift()!);
    this.replyKeys.set(key, list);
    return pub;
  }

  private async transmit(
    entry: OutboxEntry,
    o: { sign: boolean; stem: boolean; archivable?: boolean; signal?: AbortSignal },
  ): Promise<void> {
    const key = toHex(entry.msgId);
    if (this.inflight.has(key)) return;
    this.inflight.add(key);
    try {
      await this.transmitInner(entry, o);
    } finally {
      this.inflight.delete(key);
    }
  }

  private async transmitInner(
    entry: OutboxEntry,
    o: { sign: boolean; stem: boolean; archivable?: boolean; signal?: AbortSignal },
  ): Promise<void> {
    const recipientKey = await this.recipientKey(entry.recipient);
    const replyPub = o.sign ? this.mintReplyKey(entry.recipient) : undefined;
    const pending = this.outbox.pendingChunks(entry);
    for (const idx of pending) {
      const base: Omit<AuthFrame, 'sender' | 'sig'> = {
        msgId: entry.msgId,
        timestamp: this.nowSeconds(),
        payload: entry.chunks[idx]!,
        ...(replyPub ? { replyPub } : {}),
        ...(entry.chunks.length > 1 ? { chunk: { idx, total: entry.chunks.length } } : {}),
      };
      const inner = o.sign ? signAuthFrame(base, this.keyring.identity, entry.topic, entry.recipient) : serializeAuthFrame(base);
      const body = serializeUserMsgFrame({ topic: entry.topic, body: inner });
      // A fresh flag per envelope: the ephemeral element is regenerated each
      // time, so chunks and retries of the same message are unlinkable to each
      // other on the wire.
      const flag = o.archivable === false ? undefined : this.flagFor(entry.recipient);
      const peers = await this.bus.send(USER_DATA_KIND, recipientKey, body, {
        stem: o.stem,
        ...(flag ? { flag } : {}),
        ...(o.signal ? { signal: o.signal } : {}),
      });
      this.emit('sent', { msgId: entry.msgId, chunk: idx, attempt: entry.attempts + 1, peers: typeof peers === 'number' ? peers : this.pool.connectedCount });
    }
    await this.outbox.markSent(entry.msgId);
  }

  private scheduleRetry(delayMs: number): void {
    if (this.closed) return;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.retryTick().catch((e) => this.emit('error', e as Error)).finally(() => this.scheduleRetry(this.opts.retryTickMs));
    }, delayMs);
  }

  private async retryTick(): Promise<void> {
    if (this.retrying || this.closed) return;
    this.retrying = true;
    try {
      const { due, expired } = await this.outbox.due();
      for (const e of expired) this.emit('expired', { msgId: e.msgId, to: encodeIdentity(e.recipient) });
      if (this.pool.connectedCount === 0) return;
      for (const e of due) {
        if (this.closed) return;
        try {
          await this.transmit(e, { sign: true, stem: true });
        } catch (err) {
          // Discovery timeout etc.: try again next tick.
          await this.outbox.markSent(e.msgId);
          this.emit('error', err as Error);
        }
      }
    } finally {
      this.retrying = false;
    }
  }

  // ---------------------------------------------------------------- receiving

  private async onUserData(m: InboundMessage): Promise<void> {
    let topic: string;
    let frame: AuthFrame;
    let outer;
    try {
      outer = parseUserMsgFrame(m.body);
    } catch {
      return; // not a USER_DATA frame at all
    }
    topic = outer.topic;
    try {
      frame = parseAuthFrame(outer.body);
    } catch {
      // Not a library frame: other senders (naviod RPC, other apps) use kind 7 with their own body framing.
      if (m.recipient !== 'broadcast' || this.subscriptions.has(topic)) this.emit('raw', { topic, body: outer.body, scope: m.recipient });
      return;
    }
    const scope: MessageScope = m.recipient;
    // Signatures bind the recipient, so the binding has to match whatever the
    // sender could actually have known:
    //   broadcast          zeros — the message is for everyone
    //   prekey response    the requester's reply key
    //   shared-key traffic the shared key itself. A sender addressing a GROUP
    //                      cannot bind to any one member's identity; that is
    //                      the whole point of one envelope for the group.
    //   everything else    our identity, which a 1:1 sender does know
    const sharedBound = m.sessionPub !== undefined && this.sharedKeys.has(toHex(m.sessionPub));
    const recipientForSig =
      scope === 'broadcast' ? BROADCAST_RECIPIENT
      : topic === TOPIC_PREKEY_RESPONSE ? (m.sessionPub ?? BROADCAST_RECIPIENT)
      : sharedBound ? m.sessionPub!
      : this.keyring.identity.pub;
    if (!verifyAuthFrame(frame, topic, recipientForSig)) return;
    if (frame.sender && equal(frame.sender, this.keyring.identity.pub) && scope !== 'broadcast') return; // our own echo

    if (topic.startsWith(TOPIC_PREKEY_RESPONSE + '/')) return this.onPrekeyRequest(topic, frame, scope);
    if (topic === TOPIC_PREKEY_RESPONSE) return this.onPrekeyResponse(frame, m);
    if (topic === TOPIC_ACK) return this.onAck(frame, scope);
    if (isReservedTopic(topic)) return;

    if (frame.sender) {
      if (frame.replyPub && scope !== 'broadcast') await this.contacts.setNextKey(frame.sender, frame.replyPub);
      else await this.contacts.touch(frame.sender);
    }

    // Dedup re-sends whose ack we already sent (ack may have been lost): re-ack, don't re-deliver.
    const seenKey = `${toHex(frame.msgId)}:${frame.sender ? toHex(frame.sender) : '-'}:${frame.chunk?.idx ?? -1}`;
    const duplicate = this.seen.has(seenKey);
    this.remember(seenKey);
    // No acks for shared-key traffic: every member would ack every message,
    // turning one envelope into N, each with its own proof of work.
    if (scope !== 'broadcast' && frame.sender && !sharedBound) this.queueAck(frame, scope);
    if (duplicate) return;

    let payload: Uint8Array | undefined = frame.payload;
    if (frame.chunk) {
      try {
        payload = this.reassembler.add(frame.msgId, frame.sender, frame.chunk.idx, frame.chunk.total, frame.payload);
      } catch {
        return;
      }
      if (!payload) return;
    }
    const msg: IncomingMessage = {
      msgId: frame.msgId,
      ...(frame.sender ? { from: encodeIdentity(frame.sender), fromIdentity: frame.sender } : {}),
      topic,
      payload,
      scope,
      timestamp: Number(frame.timestamp),
    };
    if (scope === 'broadcast') {
      const subs = this.subscriptions.get(topic);
      if (!subs || subs.size === 0) return; // not subscribed: ignore public chatter
      for (const h of [...subs]) h(msg);
    }
    this.emit('message', msg);
  }

  /**
   * Remember a delivered (msgId, sender, chunk) so a re-send whose ack was lost
   * is re-acked but not re-delivered. Persisted so a restart does not surface
   * duplicates to the application.
   */
  private remember(key: string): void {
    if (this.seen.has(key)) return;
    this.seen.set(key, true);
    void this.store.put(NS_SEEN, key, new Uint8Array(0)).catch(() => {});
    while (this.seen.size > SEEN_CAPACITY) {
      const first = this.seen.keys().next().value;
      if (first === undefined) break;
      this.seen.delete(first);
      void this.store.delete(NS_SEEN, first).catch(() => {});
    }
  }

  private async loadSeen(): Promise<void> {
    for (const { key } of await this.store.list(NS_SEEN)) this.seen.set(key, true);
  }

  private async onPrekeyRequest(topic: string, frame: AuthFrame, scope: MessageScope): Promise<void> {
    if (scope !== 'broadcast' || !frame.replyPub) return;
    if (topic !== prekeyRequestTopic(this.keyring.identity.pub)) return; // someone else's
    // Rate limit per reply key: one answer per 10 s.
    const k = toHex(frame.replyPub);
    const last = this.lastPrekeyReply.get(k) ?? 0;
    if (this.now() - last < 10_000) return;
    this.lastPrekeyReply.set(k, this.now());
    if (this.lastPrekeyReply.size > 1024) this.lastPrekeyReply.clear();
    // Answer with the EXTENDED bundle: the clue key is what lets the requester
    // flag messages to us, and discovery is the only place it is published.
    const bundleBytes = serializeExtendedBundle(this.keyring.extendedBundle());
    const inner = signAuthFrame(
      { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), payload: bundleBytes },
      this.keyring.identity,
      TOPIC_PREKEY_RESPONSE,
      frame.replyPub, // bind to the requester's reply key so the response cannot be replayed elsewhere
    );
    const body = serializeUserMsgFrame({ topic: TOPIC_PREKEY_RESPONSE, body: inner });
    await this.bus.send(USER_DATA_KIND, frame.replyPub, body, { stem: true });
  }

  private async onPrekeyResponse(frame: AuthFrame, m: InboundMessage): Promise<void> {
    if (m.recipient !== 'session' || !m.sessionPub || !frame.sender) return;
    // Accept either form: a peer on an older build answers with the 192-byte
    // v1 bundle and simply gives us no clue key.
    if (frame.payload.length !== BUNDLE_BYTES && frame.payload.length !== EXTENDED_BUNDLE_BYTES) return;
    let bundle: Bundle | ExtendedBundle;
    try {
      bundle = parseAnyBundle(frame.payload);
    } catch {
      return;
    }
    if (!equal(bundle.identity, frame.sender) || !verifyBundle(bundle)) return;
    const key = toHex(bundle.identity);
    const d = this.discoveries.get(key);
    if (!d || !equal(d.sessionPub, m.sessionPub)) return;
    clearTimeout(d.timer);
    this.discoveries.delete(key);
    this.keys.removeSessionKey(d.sessionPub);
    await this.learnBundle(bundle);
    d.resolve(bundle);
  }

  private async onAck(frame: AuthFrame, scope: MessageScope): Promise<void> {
    if (scope === 'broadcast' || !frame.sender) return;
    let acks: AckEntry[];
    try {
      acks = parseAcks(frame.payload);
    } catch {
      return;
    }
    if (frame.replyPub) await this.contacts.setNextKey(frame.sender, frame.replyPub);
    for (const a of acks) {
      const e = this.outbox.get(a.msgId);
      if (!e || !equal(e.recipient, frame.sender)) continue;
      const done = await this.outbox.ack(a.msgId, a.chunkIdx === ACK_WHOLE ? 'whole' : a.chunkIdx);
      if (done) this.emit('ack', { msgId: done.msgId, to: encodeIdentity(done.recipient) });
    }
  }

  private queueAck(frame: AuthFrame, _scope: MessageScope): void {
    if (!frame.sender) return;
    const key = toHex(frame.sender);
    const entry: AckEntry = { msgId: frame.msgId, chunkIdx: frame.chunk ? frame.chunk.idx : ACK_WHOLE };
    let p = this.pendingAcks.get(key);
    if (p) {
      p.entries.push(entry);
      if (frame.replyPub) p.key = frame.replyPub; // newest reply key wins
      return;
    }
    const contact = this.contacts.get(frame.sender);
    const dest = frame.replyPub ?? contact?.bundle?.prekey;
    if (!dest) return; // no way to reach the sender; it will retry with a reply key
    const timer = setTimeout(() => {
      this.flushAcks(key).catch((e) => this.emit('error', e as Error));
    }, this.opts.ackDelayMs);
    this.pendingAcks.set(key, { identity: frame.sender, key: dest, entries: [entry], timer });
  }

  private async flushAcks(key: string): Promise<void> {
    const p = this.pendingAcks.get(key);
    if (!p) return;
    this.pendingAcks.delete(key);
    // Carry our own reply key so the sender's next message to us rides a fresh session key.
    const replyPub = this.mintReplyKey(p.identity);
    const inner = signAuthFrame(
      { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), replyPub, payload: serializeAcks(p.entries) },
      this.keyring.identity,
      TOPIC_ACK,
      p.identity,
    );
    const body = serializeUserMsgFrame({ topic: TOPIC_ACK, body: inner });
    await this.bus.send(USER_DATA_KIND, p.key, body, { stem: true });
  }

  private nowSeconds(): bigint {
    return BigInt(Math.floor(this.now() / 1000) + Math.round(this.pool.medianClockOffset()));
  }
}

// Keep `concat` referenced for potential future use of multi-frame batching.
void concat;
