/**
 * MessagingClient — the library's public, application-agnostic surface.
 * Identity + addressing + encryption + reliable 1:1 delivery + pub/sub over
 * the p2pmsg bus. Application payloads are opaque bytes.
 */
import { Emitter } from '../net/emitter.js';
import { PeerPool, type PeerPoolOptions } from '../net/pool.js';
import { type NetworkName, ServiceFlags } from '../net/messages.js';
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
import { signAuthFrame, signAuthFrameWithDevice, verifyAuthFrame } from './auth.js';
import { MirrorBatcher, type MirrorEntry, parseMirror, serializeMirror } from './mirror.js';

/** One envelope's worth of mirror copies, leaving room for framing. */
const MAX_MIRROR_BYTES = 3000;
/** Discovery requests sent before giving up, spread over the timeout. */
const DISCOVERY_ATTEMPTS = 3;
/** Answers to one reply key inside the rate-limit window; matches the retries. */
const PREKEY_REPLIES_PER_KEY = 3;
/** Minimum gap between re-discoveries prompted by an unknown device key. */
const DEVICE_REFRESH_COOLDOWN_MS = 60_000;
/** How long a burst of sends accumulates before one mirror goes out. */
const MIRROR_FLUSH_MS = 30_000;

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}
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
  parseExtendedBundle,
  BUNDLE_BYTES,
} from './bundle.js';
import { extractDetectionKey, fmdFlag, isValidClueKey, parseClueKey } from '../bus/fmd.js';
import {
  DEVICE_LIST_VERSION,
  type DeviceEntry,
  isListedDevice,
  parseDeviceList,
  serializeDeviceList,
  signDeviceList,
  verifyDeviceList,
} from '../devices/list.js';
import {
  DeviceCaps,
  type DeviceIdentity,
  deviceId,
  generateDevice,
  signDeviceCert,
  verifyDeviceCert,
} from '../devices/hierarchy.js';
import {
  decodePairingOffer,
  encodePairingOffer,
  PAIRING_TTL_MS,
  PAIRING_VERSION,
  type PairingOffer,
  pairingTopic,
  parseAnnounce,
  parseGrant,
  sasForDevice,
  sasForPrimary,
  serializeAnnounce,
  serializeGrant,
} from '../devices/pairing.js';
import { ArchiveClient, type SyncResult } from '../archive/client.js';
import {
  ACK_WHOLE,
  TOPIC_ACK,
  TOPIC_DEFAULT,
  TOPIC_DEVICE,
  TOPIC_MIRROR,
  TOPIC_BUNDLE,
  TOPIC_PAIR,
  TOPIC_PREKEY_RESPONSE,
  isReservedTopic,
  parseAcks,
  TOPIC_PREKEY_REQUEST,
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
  /**
   * The signed `AuthFrame` exactly as it arrived, for a message that was
   * signed and fitted one frame. Kept so a layer above can hand the proof of
   * authorship on to somebody else — history backfill to a newly paired
   * device is the case that needs it, since a frame relayed by another device
   * is otherwise only as trustworthy as that device.
   *
   * Absent for unsigned messages and for chunked ones: a chunk's signature
   * covers that chunk, not the payload the reassembler produced.
   */
  signed?: Uint8Array;
  /**
   * The recipient key `signed` is bound to. A signature covers (topic,
   * recipient, frame), so verifying it anywhere else needs this — and a forger
   * cannot pick a convenient value, because the signature covers it too.
   */
  signedFor?: Uint8Array;
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
  /**
   * What a pairing grant carried, for a SECONDARY device: the account secret
   * for one epoch and the account's identity PUBLIC key. Mutually exclusive
   * with `seed`, and must be accompanied by `device` — a secondary holds no
   * identity secret, so it has to sign with its own key.
   */
  grant?: { accountSecret: Uint8Array; identityPub: Uint8Array; epoch: number };
  /** 32-byte seed; the app owns backup/recovery (mnemonic etc.). */
  seed?: Uint8Array;
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
  /**
   * Run as a SECONDARY device of an account.
   *
   * A secondary holds the account secret (so it decrypts everything the
   * primary does, from the same single envelope) but not the identity secret,
   * so it cannot sign as the account. It signs with its own device key
   * instead, and recipients check that key against the account's published
   * device list. Supply the grant a pairing produced.
   */
  device?: {
    /** This device's own keypair. Never leaves the device. */
    keypair: { sk: Uint8Array; pub: Uint8Array };
    /** The account identity this device belongs to, public key only. */
    identityPub: Uint8Array;
  };
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
  /**
   * Service bits to advertise. Default `NODE_P2PMSG_LEAF`. The envelope
   * format bit (`NODE_P2PMSG_V2`) is always added: a peer that cannot tell
   * which format we read will not send us anything.
   */
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
  /**
   * A device is asking to be paired with this account. `sas` is the string the
   * user must compare against the one shown on the new device — it is the only
   * thing authenticating the exchange, so nothing should be granted until a
   * human confirms it matches.
   */
  pairingRequest: { sas: string; devicePub: Uint8Array; label: string };
  /**
   * The account rotated its epoch — usually because a device was revoked.
   * Every derived key has moved; a device that did not receive this can no
   * longer read anything new.
   */
  accountEpoch: { epoch: number; deviceList: Uint8Array };
  /**
   * A message another of OUR devices sent. Surfaced separately from `message`
   * so an application can render it as outgoing rather than incoming.
   */
  mirrored: { to: string; topic: string; payload: Uint8Array; timestamp: number };
  /** This device was granted membership of an account. */
  paired: { accountEpoch: number; accountSecret: Uint8Array; identityPub: Uint8Array; cert: Uint8Array; caps: number; deviceList: Uint8Array };
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

function requireSeed(seed: Uint8Array | undefined): Uint8Array {
  if (!seed) throw new Error('MessagingClient needs either a seed or a pairing grant');
  return seed;
}

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
  /** Outstanding pairing offers we made, keyed by their topic. */
  private readonly pairingOffers = new Map<string, { pairSk: Uint8Array; pairPub: Uint8Array; salt: Uint8Array; expiresAt: number }>();
  /** Devices that announced themselves and are awaiting the user's confirmation. */
  private readonly pairingRequests = new Map<string, { devicePub: Uint8Array; label: string; replyPub: Uint8Array }>();
  /** Batches sent-message copies for our other devices. */
  private readonly mirror = new MirrorBatcher(MAX_MIRROR_BYTES);
  private mirrorTimer: ReturnType<typeof setTimeout> | null = null;
  /** Set on the device being added, between requestPairing and the grant. */
  private pendingPairing: { device: DeviceIdentity; replyPub: Uint8Array; offer: PairingOffer } | undefined;
  readonly keyring: Keyring;
  /** Set when this client runs as a secondary device. */
  private readonly device: MessagingClientOptions['device'];
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
  private readonly lastPrekeyReply = new Map<string, { at: number; count: number }>();
  private readonly lastDeviceRefresh = new Map<string, number>();

  private constructor(o: MessagingClientOptions, store: Store, keyring: Keyring, contacts: Contacts, outbox: Outbox) {
    super();
    this.network = o.network;
    this.store = store;
    this.keyring = keyring;
    this.device = o.device;
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
    if (keyring.isPrimary) {
      // Discovery requests arrive addressed to the IDENTITY key. It is the one
      // key of ours a stranger is certain to hold — it is the address they
      // looked us up by — and using it keeps the request opaque: no topic in
      // the clear, nothing derived from the address, just an envelope to
      // somebody. Only the primary registers it, because only the primary can
      // sign the bundle that answers.
      this.keys.addSessionKey(keyring.requireIdentitySecret().sk, keyring.identity.pub);
    }
    if (this.device) {
      // A secondary is individually addressable at its own device key. The
      // primary needs that to hand it a new account secret after a rotation —
      // by then the shared inbox key has moved and this is the only key the
      // device still holds.
      this.keys.addSessionKey(this.device.keypair.sk, this.device.keypair.pub);
    }
    if (keyring.previousPrekey) this.keys.addGraceInbox(keyring.previousPrekey.sk);

    const poolOpts: PeerPoolOptions = { network: o.network };
    if (o.transportVersion !== undefined) poolOpts.transportVersion = o.transportVersion;
    if (o.peers) poolOpts.seeds = o.peers;
    if (o.targetPeers !== undefined) poolOpts.targetPeers = o.targetPeers;
    if (o.dnsSeeds) poolOpts.dnsSeeds = o.dnsSeeds;
    if (o.transportFactory) poolOpts.transportFactory = o.transportFactory;
    if (o.userAgent) poolOpts.userAgent = o.userAgent;
    if (o.services !== undefined) poolOpts.services = o.services;
    // One clock for the whole client. The pool times its backoffs with it, and
    // each peer measures its clock offset against it — the number the bus then
    // uses to correct our envelope stamps. Measured against one clock and
    // applied to another, that correction is worse than none.
    if (o.now) poolOpts.now = o.now;
    this.pool = o.pool ?? new PeerPool(poolOpts);

    this.grinder = new PowGrinder(o.powWorkers !== undefined ? { workers: o.powWorkers } : {});
    const busOpts: ConstructorParameters<typeof BusClient>[0] = {
      keys: this.keys,
      sink: this.pool,
      grinder: this.grinder,
      network: o.network,
      // The application's clock, not the process's: `now` is the injection
      // point for the whole client, and an envelope stamped from a different
      // clock than the frame inside it is a contradiction waiting to be
      // debugged. The bus still corrects it with the peer offset on top,
      // which is what makes a device with a wrong system clock work at all.
      now: () => Math.floor(this.now() / 1000),
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
    if (o.grant && !o.device) {
      throw new Error('a device built from a grant must also be given its device keypair');
    }
    const keyring = o.grant
      ? await Keyring.forDevice(o.grant, store, now)
      : await Keyring.open(requireSeed(o.seed), store, now);
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
   * Sign an inner frame with whichever key this device is entitled to use: the
   * account identity on a primary, or this device's own key on a secondary.
   *
   * Centralised so callers building their own frames (group messages, for
   * instance) cannot accidentally take the primary-only path and produce a
   * signature a secondary device has no key for.
   */
  signInnerFrame(
    base: Omit<AuthFrame, 'sender' | 'sig' | 'devicePub'>,
    topic: string,
    recipient: Uint8Array,
  ): Uint8Array {
    return this.device
      ? signAuthFrameWithDevice(base, this.device.identityPub, this.device.keypair, topic, recipient)
      : signAuthFrame(base, this.keyring.requireIdentitySecret(), topic, recipient);
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
   * Peers this client is currently handshaked with.
   *
   * Empty is a real state, not an error: the pool redials, and a send made
   * while it is empty sits in the outbox until there is somewhere to put it.
   * An application that wants to say "offline" should say it from here.
   */
  peers(): Array<{ id: string; address: string; services: bigint }> {
    const pool = this.pool;
    if (!(pool instanceof PeerPool)) return [];
    return pool.peers().map((p) => ({ id: p.id, address: p.address, services: p.services }));
  }

  /**
   * Connected peers that advertise NODE_P2PMSG_ARCHIVE, i.e. the ones a
   * `syncArchive()` could actually reach. Empty means there is nothing to
   * catch up from, which is worth showing a user rather than reporting a sync
   * that retrieved nothing.
   */
  archivePeers(): string[] {
    const pool = this.pool;
    if (!(pool instanceof PeerPool)) return [];
    return pool
      .peers()
      .filter((p) => (p.services & ServiceFlags.NODE_P2PMSG_ARCHIVE) === ServiceFlags.NODE_P2PMSG_ARCHIVE)
      .map((p) => p.id);
  }

  /**
   * Run an archive sync with a detection key that is not this account's own —
   * a group's, for instance. Returns how many envelopes the bus accepted.
   */
  async syncArchiveWith(detectionKey: Uint8Array, precision: number, limit?: number): Promise<number> {
    const pool = this.pool;
    if (!(pool instanceof PeerPool)) return 0;
    const archive = new ArchiveClient({
      pool,
      bus: this.bus,
      store: this.store,
      precision,
      powBits: this.bus.powBits,
      ...(limit !== undefined ? { limit } : {}),
    });
    try {
      return (await archive.sync(detectionKey)).accepted;
    } finally {
      archive.close();
    }
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
    if (this.mirrorTimer) clearTimeout(this.mirrorTimer);
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
    // A `navmsg1…` string carries the prekey but NOT the clue key — that is
    // 1152 bytes and lives in the discovery response instead. Without it we
    // cannot flag messages to this contact, and their offline delivery would
    // silently never work. So discover anyway, in the background: the contact
    // is usable immediately either way.
    if (!this.contacts.get(identity)?.clueKey) {
      void this.discover(identity).catch(() => {
        // Offline, or the peer is not reachable yet. Sends still work; they
        // just are not archivable until discovery succeeds.
      });
    }
    return encodeIdentity(identity);
  }

  private async learnBundle(bundle: Bundle | ExtendedBundle): Promise<void> {
    if (!verifyBundle(bundle)) throw new Error('bundle signature invalid');
    const existing = this.contacts.get(bundle.identity);
    // NEVER go backwards, for the same reason the device list must not: a
    // signed bundle stays valid forever, so an old one can replace a newer
    // one and put us back on keys the contact has moved off. It is not even a
    // deliberate attack in the usual case — discovery re-sends while it waits,
    // and an answer to an earlier attempt can arrive after a rotation, which
    // is exactly how a revoked device kept receiving mail.
    //
    // `fmdEpoch` is the account epoch, so it orders bundles. A basic bundle
    // carries no epoch and cannot be ordered; it arrives only when a user
    // pastes a `navmsg1…`, which is a deliberate act, so it is taken as given.
    if (
      isExtendedBundle(bundle) &&
      existing?.clueKeyEpoch !== undefined &&
      bundle.fmdEpoch < existing.clueKeyEpoch
    ) {
      return;
    }
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
      // The device list is self-authenticating, so verify it on its own terms
      // before trusting any device it names.
      if (bundle.deviceList.length > 0) {
        try {
          const list = parseDeviceList(bundle.deviceList);
          if (verifyDeviceList(bundle.identity, list).ok) {
            // NEVER go backwards. A list is a signed snapshot, so an old one
            // stays valid forever — replaying the list from before a
            // revocation would re-admit the revoked device. Only a list whose
            // accountEpoch is at least what we already hold may replace it.
            const stored = existing?.deviceList;
            let acceptable = true;
            if (stored && stored.length > 0) {
              try {
                acceptable = list.accountEpoch >= parseDeviceList(stored).accountEpoch;
              } catch {
                acceptable = true; // ours is unreadable; take the new one
              }
            }
            if (acceptable) await this.contacts.setDeviceList(bundle.identity, bundle.deviceList);
          }
        } catch {
          // Malformed list: keep the rest of the bundle, ignore the list.
        }
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
        const entry = this.discoveries.get(key);
        this.discoveries.delete(key);
        this.keys.removeSessionKey(pub);
        // Reject through the STORED reject, not the one captured here: a
        // concurrent discover() chains onto the stored callbacks, and
        // rejecting the local one would leave every chained caller hanging
        // forever instead of failing.
        (entry?.reject ?? reject)(new Error(`prekey discovery for ${encodeIdentity(id)} timed out`));
      }, timeoutMs);
      this.discoveries.set(key, { sessionPub: pub, resolve, reject, timer });
    });
    // Re-send while we wait. The bus is a lossy flood network and a stem send
    // reaches ONE peer, which forwards probabilistically — so a single request
    // is not delivery, it is one attempt. Ordinary messages get this from the
    // outbox; discovery had nothing, and simply timed out whenever a stem
    // route failed to reach the target.
    //
    // The reply key is reused across attempts, so a late answer to an earlier
    // attempt still resolves, and the last attempt fluffs: by then reliability
    // matters more than hiding which node the lookup entered from. The request
    // names no requester, and — being addressed to the target's identity key
    // rather than broadcast on a topic derived from it — does not name the
    // target to anyone but the target either.
    const attempts = Math.max(1, DISCOVERY_ATTEMPTS);
    const gap = Math.floor(timeoutMs / attempts);
    for (let attempt = 0; attempt < attempts; attempt++) {
      if (!this.discoveries.has(key)) break; // already answered
      const frame: AuthFrame = {
        msgId: randomBytes(MSG_ID_BYTES),
        timestamp: this.nowSeconds(),
        replyPub: pub,
        payload: new Uint8Array(0),
      };
      const body = serializeUserMsgFrame({ topic: TOPIC_PREKEY_REQUEST, body: serializeAuthFrame(frame) });
      try {
        // To the identity key: the one key of the target we are guaranteed to
        // hold, since it IS the address we are looking up.
        await this.bus.send(USER_DATA_KIND, id, body, { stem: attempt < attempts - 1 });
      } catch (e) {
        this.emit('error', e instanceof Error ? e : new Error(String(e)));
      }
      if (attempt === attempts - 1) break;
      await Promise.race([
        result.catch(() => undefined),
        new Promise((r) => setTimeout(r, gap)),
      ]);
    }
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
      const inner =
        opts.sign === false ? serializeAuthFrame(base) : this.signInnerFrame(base, topic, BROADCAST_RECIPIENT);
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
   * Whether this account has more than one device.
   *
   * A one-shot reply key lives in ONE device's memory, so publishing it tells
   * a contact to address their next message somewhere our other devices
   * cannot read. With siblings we therefore keep the conversation on the
   * account prekey, which every device of the account derives. That trades a
   * session key's forward secrecy for the phone seeing the same conversation
   * as the desktop, and the trade goes away when the double ratchet lands:
   * its receiving keys are derived from the account secret precisely so every
   * device can advance the same chain (`docs/ratchet.md`).
   */
  private hasSiblingDevices(): boolean {
    if (this.keyring.deviceList.length === 0) return false;
    try {
      return parseDeviceList(this.keyring.deviceList).devices.length > 1;
    } catch {
      return false;
    }
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
    // Captured before markSent, which increments it.
    const firstAttempt = entry.attempts === 0;
    const replyPub = o.sign && !this.hasSiblingDevices() ? this.mintReplyKey(entry.recipient) : undefined;
    const pending = this.outbox.pendingChunks(entry);
    for (const idx of pending) {
      const base: Omit<AuthFrame, 'sender' | 'sig'> = {
        msgId: entry.msgId,
        timestamp: this.nowSeconds(),
        payload: entry.chunks[idx]!,
        ...(replyPub ? { replyPub } : {}),
        ...(entry.chunks.length > 1 ? { chunk: { idx, total: entry.chunks.length } } : {}),
      };
      const inner = o.sign ? this.signInnerFrame(base, entry.topic, entry.recipient) : serializeAuthFrame(base);
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
    // Only the first transmission is mirrored: a retry is the same message,
    // and our other devices already have it.
    if (o.sign && firstAttempt) {
      this.queueMirror({
        recipient: entry.recipient,
        topic: entry.topic,
        timestamp: this.nowSeconds(),
        payload: entry.chunks.length === 1 ? entry.chunks[0]! : concatChunks(entry.chunks),
      });
    }
  }

  private scheduleRetry(delayMs: number): void {
    if (this.closed) return;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.mirrorTimer) clearTimeout(this.mirrorTimer);
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



  /**
   * Remove a device from the account.
   *
   * Rotates the account epoch, so every derived key moves and the removed
   * device can no longer read anything new, republishes the device list
   * without it, and hands the new secret to each device that remains.
   *
   * Two things worth telling the user rather than hiding. The previous prekey
   * stays in the grace ring so messages already in flight are not lost, which
   * means the revoked device can still read THAT window — pass
   * `{ immediate: true }` to give the window up and cut the device off now,
   * at the cost of dropping messages from senders still holding the old
   * bundle until their retry finds the new one. And revocation is
   * forward-only either way: it cannot unread what the device already read.
   */
  async revokeDevice(
    devicePub: Uint8Array,
    opts: { notifyContacts?: boolean } = {},
  ): Promise<{ epoch: number; deviceList: Uint8Array }> {
    if (!this.keyring.isPrimary) throw new Error('only the primary device can revoke devices');
    if (this.keyring.deviceList.length === 0) throw new Error('this account has no device list');
    const current = parseDeviceList(this.keyring.deviceList);
    const target = toHex(devicePub);
    const remaining = current.devices.filter((d) => toHex(d.devicePub) !== target);
    if (remaining.length === current.devices.length) throw new Error('that device is not on the list');

    // Rotate FIRST: the new list is only meaningful alongside the epoch it
    // belongs to, and peers refuse a list whose epoch went backwards.
    await this.keyring.rotateAccountEpoch();
    // And move the key we actually listen on. Rotating the keyring alone
    // republishes a prekey nothing decrypts: every sender who then discovers
    // the new bundle addresses a key the bus has never been told about, and
    // the account goes quietly deaf.
    this.keys.rotateInbox(this.keyring.prekey.sk, this.keyring.prekey.pub);

    const identity = this.keyring.requireIdentitySecret();
    const list = signDeviceList(
      { version: DEVICE_LIST_VERSION, accountEpoch: this.keyring.epoch, devices: remaining },
      identity.sk,
    );
    const deviceList = serializeDeviceList(list);
    this.keyring.deviceList = deviceList;

    // Hand the new secret to the devices that are still ours. Each is reachable
    // at its own device key, which is why a secondary registers that key.
    for (const d of remaining) {
      if (toHex(d.devicePub) === toHex(identity.pub)) continue;
      await this.sendAccountEpoch(d.devicePub, d.cert, d.caps, deviceList);
    }
    // Tell our contacts their cached key is stale. Until they know, every
    // message they send goes to a key the revoked device still holds — and
    // dropping our own grace window would not change that, because the
    // revoked device reads with its own copy, not with ours. The senders are
    // the only lever there is. It costs one envelope per contact, so it is
    // the caller's call.
    if (opts.notifyContacts) await this.announceBundle();
    this.emit('accountEpoch', { epoch: this.keyring.epoch, deviceList });
    return { epoch: this.keyring.epoch, deviceList };
  }

  /**
   * Push our current bundle to every contact we hold keys for, so they stop
   * addressing a key that has moved.
   *
   * Best effort and unacked: a contact that is offline learns the new bundle
   * the usual way, by discovering it when a send fails to be acked.
   */
  async announceBundle(): Promise<number> {
    if (!this.keyring.isPrimary) return 0;
    const bundleBytes = serializeExtendedBundle(this.keyring.extendedBundle());
    let sent = 0;
    for (const contact of this.contacts.all()) {
      const dest = contact.bundle?.prekey;
      if (!dest) continue;
      try {
        const inner = signAuthFrame(
          { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), payload: bundleBytes },
          this.keyring.requireIdentitySecret(),
          TOPIC_BUNDLE,
          contact.identity,
        );
        await this.bus.send(USER_DATA_KIND, dest, serializeUserMsgFrame({ topic: TOPIC_BUNDLE, body: inner }), {
          stem: true,
        });
        sent++;
      } catch (e) {
        this.emit('error', e instanceof Error ? e : new Error(String(e)));
      }
    }
    return sent;
  }

  /** An unsolicited bundle from a contact whose keys moved. */
  private async onBundleAnnounce(frame: AuthFrame): Promise<void> {
    if (!frame.sender) return;
    try {
      const bundle = parseExtendedBundle(frame.payload);
      // The bundle names its own identity and is self-authenticating, but the
      // frame must come from that identity too: otherwise anyone could push
      // anyone's (stale, genuine) bundle and roll a contact's keys backwards.
      if (!equal(bundle.identity, frame.sender)) return;
      await this.learnBundle(bundle);
    } catch {
      // Malformed, or a signature that does not check out: ignore it. The
      // contact's cached bundle is left exactly as it was.
    }
  }

  /** Send the current account epoch to one of our own devices. */
  private async sendAccountEpoch(
    devicePub: Uint8Array,
    cert: Uint8Array,
    caps: number,
    deviceList: Uint8Array,
  ): Promise<void> {
    const identity = this.keyring.requireIdentitySecret();
    const payload = serializeGrant({
      accountEpoch: this.keyring.epoch,
      accountSecret: this.keyring.accountSecret(),
      identityPub: identity.pub,
      cert,
      caps,
      deviceList,
    });
    const inner = signAuthFrame(
      { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), payload },
      identity,
      TOPIC_DEVICE,
      devicePub,
    );
    const body = serializeUserMsgFrame({ topic: TOPIC_DEVICE, body: inner });
    await this.bus.send(USER_DATA_KIND, devicePub, body, { stem: true });
  }

  /** The primary rotated the account epoch and sent us the new secret. */
  private onAccountEpoch(frame: AuthFrame): void {
    if (!this.device || !frame.sender) return;
    // Only our own account's identity may move our keys.
    if (toHex(frame.sender) !== toHex(this.device.identityPub)) return;
    let grant;
    try {
      grant = parseGrant(frame.payload);
    } catch {
      return;
    }
    if (toHex(grant.identityPub) !== toHex(this.device.identityPub)) return;
    // A device that was just revoked must not be able to follow the rotation,
    // so check we are still on the list this message carries.
    try {
      const list = parseDeviceList(grant.deviceList);
      if (!verifyDeviceList(grant.identityPub, list).ok) return;
      if (!isListedDevice(list, this.device.keypair.pub)) return;
    } catch {
      return;
    }
    try {
      this.keyring.adoptAccountEpoch(grant.accountSecret, grant.accountEpoch);
    } catch {
      return; // stale or backwards: ignore
    }
    // rotateInbox, not setInbox: the key we are leaving goes into the grace
    // ring, so mail from senders who have not yet discovered the new bundle
    // still arrives here — the same window the primary keeps.
    this.keys.rotateInbox(this.keyring.prekey.sk, this.keyring.prekey.pub);
    this.emit('accountEpoch', { epoch: grant.accountEpoch, deviceList: grant.deviceList });
  }


  // --------------------------------------------------------------------- mirror

  /**
   * Queue a copy of something we sent for our other devices.
   *
   * No-op when the account has no other device: the copy costs a whole
   * envelope and a whole proof of work, and there is nobody to read it.
   */
  private queueMirror(entry: MirrorEntry): void {
    if (!this.hasOtherDevices()) return;
    const batch = this.mirror.add(entry);
    if (batch) {
      void this.sendMirror(batch).catch((e: unknown) => this.emit('error', e instanceof Error ? e : new Error(String(e))));
      return;
    }
    // Otherwise let it accumulate briefly, so a burst of messages costs one
    // proof of work rather than one each.
    if (this.mirrorTimer) return;
    this.mirrorTimer = setTimeout(() => {
      this.mirrorTimer = null;
      const pending = this.mirror.flush();
      if (pending.length > 0) {
        void this.sendMirror(pending).catch((e: unknown) => this.emit('error', e instanceof Error ? e : new Error(String(e))));
      }
    }, MIRROR_FLUSH_MS);
  }

  /** Flush any pending mirror copies now. */
  async flushMirror(): Promise<void> {
    if (this.mirrorTimer) {
      clearTimeout(this.mirrorTimer);
      this.mirrorTimer = null;
    }
    const pending = this.mirror.flush();
    if (pending.length > 0) await this.sendMirror(pending);
  }

  private hasOtherDevices(): boolean {
    if (this.keyring.deviceList.length === 0) return false;
    try {
      // The primary lists itself, so "more than one entry" is the test.
      return parseDeviceList(this.keyring.deviceList).devices.length > 1;
    } catch {
      return false;
    }
  }

  /** Addressed to our own inbox key, so every device of ours decrypts it. */
  private async sendMirror(entries: MirrorEntry[]): Promise<void> {
    const payload = serializeMirror(entries);
    // Bound to the account IDENTITY, not the inbox key: the frame arrives
    // inbox-scoped, and an inbox-scoped frame is verified against the identity
    // — which every device of the account knows, and the prekey is not.
    const inner = this.signInnerFrame(
      { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), payload },
      TOPIC_MIRROR,
      this.keyring.identity.pub,
    );
    const body = serializeUserMsgFrame({ topic: TOPIC_MIRROR, body: inner });
    await this.bus.send(USER_DATA_KIND, this.keyring.prekey.pub, body, { stem: true });
  }

  private onMirror(frame: AuthFrame): void {
    // Only our own account may mirror to us, and only from a device that is
    // not this one — our own copy would just be an echo.
    if (!frame.sender || toHex(frame.sender) !== toHex(this.keyring.identity.pub)) return;
    let entries: MirrorEntry[];
    try {
      entries = parseMirror(frame.payload);
    } catch {
      return;
    }
    for (const e of entries) {
      this.emit('mirrored', {
        to: encodeIdentity(e.recipient),
        topic: e.topic,
        payload: e.payload,
        timestamp: Number(e.timestamp),
      });
    }
  }

  // -------------------------------------------------------------------- pairing

  /**
   * Begin admitting another device. Returns the `navpair1…` string to show as
   * a QR.
   *
   * The offer is a bearer secret and single-use: anyone who photographs it can
   * reach the next step. What stops them is the short authentication string —
   * see `pairingRequest`.
   */
  startPairing(): { offer: string; expiresAt: number } {
    if (!this.keyring.isPrimary) throw new Error('only the primary device can admit other devices');
    const pairSk = generateSecret();
    const pairPub = publicKey(pairSk);
    const salt = randomBytes(16);
    const expiresAt = this.now() + PAIRING_TTL_MS;
    // Register the pairing key so the announce, which is addressed to it,
    // decrypts; it expires with the offer.
    this.keys.addSessionKey(pairSk, pairPub, PAIRING_TTL_MS);
    this.pairingOffers.set(pairingTopic(pairPub), { pairSk, pairPub, salt, expiresAt });
    return {
      offer: encodePairingOffer({ version: PAIRING_VERSION, network: this.network, pairPub, salt }),
      expiresAt,
    };
  }

  /** Abandon any outstanding pairing offer. */
  cancelPairing(): void {
    for (const [, o] of this.pairingOffers) this.keys.removeSessionKey(o.pairPub);
    this.pairingOffers.clear();
    this.pairingRequests.clear();
  }

  /**
   * Answer someone else's offer, as the device being added.
   *
   * Returns the short authentication string to display. The account grants
   * nothing until the user confirms it matches the primary's.
   */
  async requestPairing(offerText: string, label: string): Promise<{ sas: string; device: DeviceIdentity }> {
    const offer = decodePairingOffer(offerText);
    if (offer.network !== this.network) throw new Error(`offer is for ${offer.network}, not ${this.network}`);
    const device = generateDevice();
    // Mint a reply key so the grant comes back to us and to nobody else.
    const replySk = generateSecret();
    const replyPub = publicKey(replySk);
    this.keys.addSessionKey(replySk, replyPub, PAIRING_TTL_MS);
    this.pendingPairing = { device, replyPub, offer };

    const topic = pairingTopic(offer.pairPub);
    // Unsigned: this device has no identity yet, and the offer key is what
    // authorises it to speak here at all.
    const inner = serializeAuthFrame({
      msgId: randomBytes(MSG_ID_BYTES),
      timestamp: this.nowSeconds(),
      replyPub,
      payload: serializeAnnounce({ devicePub: device.pub, label }),
    });
    const body = serializeUserMsgFrame({ topic, body: inner });
    await this.bus.send(USER_DATA_KIND, offer.pairPub, body, { stem: true });
    return { sas: sasForDevice(device.sk, offer.pairPub, offer.salt), device };
  }

  /**
   * Grant the device that produced `devicePub`, after the user confirmed the
   * two strings match. Signs it into the account, publishes the updated device
   * list, and sends it the account secret.
   */
  async confirmPairing(
    devicePub: Uint8Array,
    caps = 0,
    opts: { notifyContacts?: boolean } = {},
  ): Promise<void> {
    const pending = this.pairingRequests.get(toHex(devicePub));
    if (!pending) throw new Error('no pairing request from that device');
    const identity = this.keyring.requireIdentitySecret();
    const createdAt = BigInt(this.nowSeconds());
    const entry = {
      deviceId: deviceId(devicePub),
      devicePub: devicePub.slice(),
      createdAt,
      caps,
      label: pending.label,
      cert: signDeviceCert(identity.sk, { devicePub, createdAt, caps }),
    };

    // Keep whatever devices were already listed; this one joins them.
    let devices: DeviceEntry[] = [];
    if (this.keyring.deviceList.length > 0) {
      try {
        devices = parseDeviceList(this.keyring.deviceList).devices;
      } catch {
        // Unreadable list: start a fresh one rather than refuse to pair.
      }
    }
    if (devices.length === 0) {
      // The primary lists ITSELF first. Its "device key" is the identity key,
      // which is what signs its frames. Without this the list would become
      // empty — and therefore invalid — the moment the last secondary is
      // revoked, and there would be nothing left to authenticate the account's
      // own messages against.
      devices = [
        {
          deviceId: deviceId(identity.pub),
          devicePub: identity.pub,
          createdAt,
          caps: DeviceCaps.PRIMARY | DeviceCaps.CAN_PAIR,
          label: 'primary',
          cert: signDeviceCert(identity.sk, {
            devicePub: identity.pub,
            createdAt,
            caps: DeviceCaps.PRIMARY | DeviceCaps.CAN_PAIR,
          }),
        },
      ];
    }
    devices = [...devices, entry];
    const list = signDeviceList(
      { version: DEVICE_LIST_VERSION, accountEpoch: this.keyring.epoch, devices },
      identity.sk,
    );
    const deviceList = serializeDeviceList(list);
    this.keyring.deviceList = deviceList;

    const grant = serializeGrant({
      accountEpoch: this.keyring.epoch,
      accountSecret: this.keyring.accountSecret(),
      identityPub: identity.pub,
      cert: entry.cert,
      caps,
      deviceList,
    });
    const inner = signAuthFrame(
      { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), payload: grant },
      identity,
      TOPIC_PAIR,
      pending.replyPub,
    );
    const body = serializeUserMsgFrame({ topic: TOPIC_PAIR, body: inner });
    await this.bus.send(USER_DATA_KIND, pending.replyPub, body, { stem: true });
    this.pairingRequests.delete(toHex(devicePub));

    // Tell our contacts about the new device, by republishing the bundle the
    // list travels in. A contact holding the list from before this device
    // existed rejects everything it signs — correctly, since a device that is
    // not on the list is exactly what a revoked one looks like. They would
    // find out eventually, when a dropped frame made them discover again, but
    // "eventually" means the new device's first message to each contact is
    // lost. Pass `notifyContacts: false` to take that trade deliberately.
    if (opts.notifyContacts !== false) await this.announceBundle();
  }

  /** A device announced itself on one of our pairing topics. */
  private onPairingAnnounce(topic: string, frame: AuthFrame): void {
    const offer = this.pairingOffers.get(topic);
    if (!offer || this.now() > offer.expiresAt) return;
    if (!frame.replyPub) return; // nowhere to send the grant
    let announce;
    try {
      announce = parseAnnounce(frame.payload);
    } catch {
      return;
    }
    this.pairingRequests.set(toHex(announce.devicePub), {
      devicePub: announce.devicePub,
      label: announce.label,
      replyPub: frame.replyPub,
    });
    this.emit('pairingRequest', {
      sas: sasForPrimary(offer.pairSk, announce.devicePub, offer.salt),
      devicePub: announce.devicePub,
      label: announce.label,
    });
  }

  /** The primary granted us membership. */
  private onPairingGrant(frame: AuthFrame): void {
    const pending = this.pendingPairing;
    if (!pending || !frame.sender) return;
    let grant;
    try {
      grant = parseGrant(frame.payload);
    } catch {
      return;
    }
    // The grant is signed by the identity it claims to be, and the device list
    // must name us — otherwise this is not a grant we can act on.
    if (toHex(grant.identityPub) !== toHex(frame.sender)) return;
    if (!verifyDeviceCert(grant.identityPub, { devicePub: pending.device.pub, createdAt: 0n, caps: grant.caps }, grant.cert)) {
      // createdAt is not known to us, so fall back to the list, which is what
      // peers will actually check against.
      try {
        const list = parseDeviceList(grant.deviceList);
        if (!verifyDeviceList(grant.identityPub, list).ok || !isListedDevice(list, pending.device.pub)) return;
      } catch {
        return;
      }
    }
    this.pendingPairing = undefined;
    this.emit('paired', grant);
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
    //   pairing grant      the joining device's reply key. The sender cannot
    //                      bind to that device's identity: it has none yet,
    //                      which is the entire reason it is pairing.
    //   shared-key traffic the shared key itself. A sender addressing a GROUP
    //                      cannot bind to any one member's identity; that is
    //                      the whole point of one envelope for the group.
    //   everything else    our identity, which a 1:1 sender does know
    const sharedBound = m.sessionPub !== undefined && this.sharedKeys.has(toHex(m.sessionPub));
    const recipientForSig =
      scope === 'broadcast' ? BROADCAST_RECIPIENT
      : topic === TOPIC_PREKEY_RESPONSE || topic === TOPIC_PAIR || topic === TOPIC_DEVICE ?
        (m.sessionPub ?? BROADCAST_RECIPIENT)
      : sharedBound ? m.sessionPub!
      : this.keyring.identity.pub;
    if (!verifyAuthFrame(frame, topic, recipientForSig)) return;
    // A device-signed frame proves only that the named DEVICE key signed it.
    // Whether that device belongs to the account is a separate question, and
    // the answer is the sender's published device list — without which a
    // revoked device would still verify against its own key.
    if (frame.devicePub && frame.sender && !(await this.deviceIsListed(frame.sender, frame.devicePub))) return;
    // Our own echo. Compare the key that SIGNED the frame against the key this
    // device signs with — not against the account identity, which a secondary
    // shares with the primary and would therefore mistake every message from
    // it for an echo of its own.
    const ourSigner = this.device ? this.device.keypair.pub : this.keyring.identity.pub;
    const frameSigner = frame.devicePub ?? frame.sender;
    if (frameSigner && equal(frameSigner, ourSigner) && scope !== 'broadcast') return;

    if (topic === TOPIC_PREKEY_REQUEST) return this.onPrekeyRequest(frame, m);
    if (topic === TOPIC_PREKEY_RESPONSE) return this.onPrekeyResponse(frame, m);
    if (topic === TOPIC_ACK) return this.onAck(frame, scope);
    if (topic.startsWith(TOPIC_PAIR + '/')) return this.onPairingAnnounce(topic, frame);
    if (topic === TOPIC_PAIR) return this.onPairingGrant(frame);
    if (topic === TOPIC_DEVICE) return this.onAccountEpoch(frame);
    if (topic === TOPIC_MIRROR) return this.onMirror(frame);
    if (topic === TOPIC_BUNDLE) return this.onBundleAnnounce(frame);
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
      ...(frame.sender && frame.sig && !frame.chunk ?
        { signed: outer.body, signedFor: recipientForSig }
      : {}),
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

  private async onPrekeyRequest(frame: AuthFrame, m: InboundMessage): Promise<void> {
    if (!frame.replyPub) return;
    // It decrypted under our identity key, which is the whole check: nobody
    // else can produce an envelope we open with it, so there is no "somebody
    // else's request" case left to filter out.
    if (m.recipient !== 'session' || !m.sessionPub) return;
    if (!equal(m.sessionPub, this.keyring.identity.pub)) return;
    // A secondary device cannot sign a bundle, and answering with an
    // unsigned one would be worse than staying quiet: the primary answers.
    if (!this.keyring.isPrimary) return;
    // Rate limit per reply key. A requester re-sends while it waits, because
    // one stem send is an attempt rather than a delivery — so answering only
    // once per key would leave a lost response unrecoverable for the whole
    // window. Allow a few answers per key instead: the amplification stays
    // bounded at PREKEY_REPLIES_PER_KEY per reply key, and a requester that
    // is plainly still asking gets an answer.
    const k = toHex(frame.replyPub);
    const seen = this.lastPrekeyReply.get(k);
    if (seen && this.now() - seen.at < 10_000 && seen.count >= PREKEY_REPLIES_PER_KEY) return;
    let replyCount = 1;
    if (seen && this.now() - seen.at < 10_000) replyCount = ++seen.count;
    else this.lastPrekeyReply.set(k, { at: this.now(), count: 1 });
    if (this.lastPrekeyReply.size > 1024) this.lastPrekeyReply.clear();
    // Answer with the EXTENDED bundle: the clue key is what lets the requester
    // flag messages to us, and discovery is the only place it is published.
    const bundleBytes = serializeExtendedBundle(this.keyring.extendedBundle());
    const inner = signAuthFrame(
      { msgId: randomBytes(MSG_ID_BYTES), timestamp: this.nowSeconds(), payload: bundleBytes },
      this.keyring.requireIdentitySecret(),
      TOPIC_PREKEY_RESPONSE,
      frame.replyPub, // bind to the requester's reply key so the response cannot be replayed elsewhere
    );
    const body = serializeUserMsgFrame({ topic: TOPIC_PREKEY_RESPONSE, body: inner });
    // The first answer stems. A repeat means the requester is still asking, so
    // the stem route most likely dropped the previous one — fluff instead of
    // losing it the same way twice.
    await this.bus.send(USER_DATA_KIND, frame.replyPub, body, { stem: replyCount === 1 });
  }

  /**
   * Whether `devicePub` appears on `identity`'s verified device list.
   *
   * False when we hold no list yet: a device-signed frame from an account we
   * have never discovered is dropped rather than trusted. The sender's outbox
   * retries, and by then discovery has usually filled the gap.
   */
  private async deviceIsListed(identity: Uint8Array, devicePub: Uint8Array): Promise<boolean> {
    const raw = this.contacts.get(identity)?.deviceList;
    try {
      if (raw && raw.length > 0 && isListedDevice(parseDeviceList(raw), devicePub)) return true;
    } catch {
      // A list we cannot parse is a list we do not have.
    }
    // Either we hold no list, or we hold one that predates this device. Both
    // look the same from here and both are fixed the same way: ask again. A
    // STALE list is the one that bites — pair a phone, and every contact
    // holding the list from before it existed drops everything the phone
    // sends, silently and for as long as nothing else makes them look.
    this.refreshDeviceList(identity);
    return false;
  }

  /**
   * Re-discover a contact, at most once a minute.
   *
   * The rate limit is the point: this fires on a frame naming a device we do
   * not know, and that is exactly what an attacker would send in a loop to
   * make us discover on demand.
   */
  private refreshDeviceList(identity: Uint8Array): void {
    const key = toHex(identity);
    const last = this.lastDeviceRefresh.get(key) ?? 0;
    if (this.now() - last < DEVICE_REFRESH_COOLDOWN_MS) return;
    this.lastDeviceRefresh.set(key, this.now());
    if (this.lastDeviceRefresh.size > 1024) this.lastDeviceRefresh.clear();
    void this.discover(identity).catch(() => {
      // Offline or unreachable. The next frame from that device tries again.
    });
  }

  private async onPrekeyResponse(frame: AuthFrame, m: InboundMessage): Promise<void> {
    if (m.recipient !== 'session' || !m.sessionPub || !frame.sender) return;
    // Accept any form: a peer on an older build answers with the 192-byte v1
    // bundle (no clue key) or a v2 bundle (no device list). Length no longer
    // identifies the form, since a v3 bundle carries a variable device list,
    // so let the parser decide.
    if (frame.payload.length < BUNDLE_BYTES) return;
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
    // Carry our own reply key so the sender's next message to us rides a fresh
    // session key — unless this account has other devices, which could not
    // read a message addressed to a key only this one holds.
    const replyPub = this.hasSiblingDevices() ? undefined : this.mintReplyKey(p.identity);
    // Acks are signed like any other frame, so a secondary device acks with
    // its own key rather than being unable to ack at all.
    const inner = this.signInnerFrame(
      {
        msgId: randomBytes(MSG_ID_BYTES),
        timestamp: this.nowSeconds(),
        ...(replyPub ? { replyPub } : {}),
        payload: serializeAcks(p.entries),
      },
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
