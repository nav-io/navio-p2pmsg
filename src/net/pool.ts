/**
 * Keeps `targetPeers` handshaked peers alive. Address sources: explicit seeds,
 * DNS seeds (Node only), and `addr`/`addrv2` gossip filtered on NODE_P2PMSG.
 * Reconnects with capped exponential backoff and jitter.
 */
import { Emitter } from './emitter.js';
import { DefaultPorts, ServiceFlags, hasService, type NetAddress, type NetworkName } from './messages.js';
import { Peer, type PeerOptions, type PeerVersionInfo } from './peer.js';
import { TcpTransport } from './tcp-transport.js';
import { formatHostPort, parsePeerAddress, type Transport } from './transport.js';
import { WsTransport } from './ws-transport.js';

export type TransportFactory = (address: string, network: NetworkName) => Transport;

export interface PeerPoolOptions {
  network: NetworkName;
  /** Peer addresses / URLs to dial first. Never evicted. */
  seeds?: string[];
  /** Number of handshaked peers to maintain. Default 3. */
  targetPeers?: number;
  /** DNS seed hostnames. Default `['seed.nav.io']` on mainnet, none elsewhere. */
  dnsSeeds?: string[];
  /** Resolve DNS seeds (Node only). Default: true under Node, false in browsers. */
  allowDns?: boolean;
  /** Build a transport for an address. Default: TCP for `host:port`, WS for `ws(s)://`. */
  transportFactory?: TransportFactory;
  services?: bigint;
  userAgent?: string;
  /** Extra options forwarded to every `Peer`. */
  peerOptions?: Partial<Omit<PeerOptions, 'network' | 'services' | 'userAgent'>>;
  /** Backoff floor / cap in ms. Defaults 1 s / 60 s. */
  minBackoffMs?: number;
  maxBackoffMs?: number;
  /** Safety-net maintenance interval. Default 5 s. */
  maintainIntervalMs?: number;
  /** Max addresses kept in the in-memory book. Default 1000. */
  maxAddresses?: number;
  /** Clock (unix ms). Default `Date.now`. */
  now?: () => number;
  /** Random source in [0,1). Default `Math.random`. */
  random?: () => number;
}

export interface PeerInfo {
  /** Unique per connection attempt (`address#n`). */
  id: string;
  address: string;
  services: bigint;
  userAgent: string;
  startHeight: number;
  version: number;
  clockOffsetSeconds: number;
  connectedAt: number;
}

export interface PoolMessage {
  peerId: string;
  stem: boolean;
  payload: Uint8Array;
}

export type PeerPoolEvents = {
  /** A peer completed its handshake. */
  peer: PeerInfo;
  /** A peer connection ended (handshaked or not). */
  peerclose: { peerId: string; address: string; error?: Error; wasConnected: boolean };
  /** A `p2pmsg` / `dp2pmsg` envelope from any peer. */
  message: PoolMessage;
  /** A `p2pmsgs` archive response from a peer we queried. */
  archive: { peerId: string; payload: Uint8Array };
  /** New address learned via gossip / DNS. */
  addr: { address: string; services: bigint };
  /** Non-fatal errors (dial failures, DNS failures, peer errors). */
  error: Error;
};

type AddressSource = 'seed' | 'dns' | 'gossip' | 'manual';

interface BookEntry {
  address: string;
  services: bigint;
  source: AddressSource;
  failures: number;
  nextTryAt: number;
  lastSeen: number;
}

interface Slot {
  id: string;
  address: string;
  peer: Peer;
  connected: boolean;
}

const DEFAULT_DNS_SEEDS: Record<NetworkName, string[]> = {
  mainnet: ['seed.nav.io'],
  testnet: [],
  regtest: [],
};

function isNode(): boolean {
  const p = (globalThis as { process?: { versions?: { node?: string } } }).process;
  return typeof p?.versions?.node === 'string';
}

export function defaultTransportFactory(address: string, network: NetworkName): Transport {
  const a = parsePeerAddress(address, DefaultPorts[network]);
  if (a.kind === 'ws') return new WsTransport(a.url!);
  if (!isNode()) throw new Error(`cannot dial ${address}: raw TCP is unavailable in this runtime, use ws(s):// peers`);
  return new TcpTransport(a.host, a.port);
}

/** Normalise an address string to its address-book key. */
const V6_DEPRIORITISE_MS = 10 * 60 * 1000;

/** `[v6]:port` book addresses and ws URLs with a bracketed v6 host. */
export function isIPv6Address(address: string): boolean {
  return address.startsWith('[') || /^wss?:\/\/\[/.test(address);
}

/** Errors that mean "this host cannot reach that address family at all". */
export function isNoRouteError(err: Error): boolean {
  const code = (err as NodeJS.ErrnoException).code ?? '';
  return code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || code === 'EADDRNOTAVAIL' || /EHOSTUNREACH|ENETUNREACH|EADDRNOTAVAIL/.test(err.message);
}

export function normalizeAddress(address: string, network: NetworkName): string {
  const a = parsePeerAddress(address, DefaultPorts[network]);
  if (a.kind === 'ws') return a.url!;
  return formatHostPort(a.host.toLowerCase(), a.port);
}

export class PeerPool extends Emitter<PeerPoolEvents> {
  readonly network: NetworkName;
  private readonly opts: Required<
    Pick<
      PeerPoolOptions,
      | 'targetPeers'
      | 'allowDns'
      | 'services'
      | 'userAgent'
      | 'minBackoffMs'
      | 'maxBackoffMs'
      | 'maintainIntervalMs'
      | 'maxAddresses'
    >
  > & {
    dnsSeeds: string[];
    transportFactory: TransportFactory;
    peerOptions: Partial<PeerOptions>;
    now: () => number;
    random: () => number;
  };
  private readonly book = new Map<string, BookEntry>();
  private readonly slots = new Map<string, Slot>();
  private readonly dialing = new Set<string>();
  private running = false;
  private maintainTimer: ReturnType<typeof setInterval> | null = null;
  /**
   * When an IPv6 dial fails with a "no route" error the host most likely has
   * no IPv6 connectivity; until this time IPv6 candidates are tried only
   * after every IPv4 candidate. Cleared by any successful IPv6 connection.
   */
  private v6DeprioritisedUntil = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private dnsInFlight = false;
  private dnsResolvedAt = 0;
  private seq = 0;

  constructor(options: PeerPoolOptions) {
    super();
    this.network = options.network;
    const node = isNode();
    this.opts = {
      targetPeers: options.targetPeers ?? 3,
      dnsSeeds: options.dnsSeeds ?? DEFAULT_DNS_SEEDS[options.network],
      allowDns: options.allowDns ?? node,
      transportFactory: options.transportFactory ?? defaultTransportFactory,
      services: options.services ?? ServiceFlags.NODE_P2PMSG_LEAF,
      userAgent: options.userAgent ?? '/navio-p2pmsg:0.1.0/',
      peerOptions: options.peerOptions ?? {},
      minBackoffMs: options.minBackoffMs ?? 1_000,
      maxBackoffMs: options.maxBackoffMs ?? 60_000,
      maintainIntervalMs: options.maintainIntervalMs ?? 5_000,
      maxAddresses: options.maxAddresses ?? 1000,
      now: options.now ?? (() => Date.now()),
      random: options.random ?? (() => Math.random()),
    };
    for (const s of options.seeds ?? []) this.addPeerAddress(s, { source: 'seed' });
  }

  get started(): boolean {
    return this.running;
  }

  /** Begin dialing. Resolves immediately; connections are reported via `peer` events. */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.maintainTimer = setInterval(() => this.maintain(), this.opts.maintainIntervalMs);
    this.maintain();
  }

  /** Close every connection and stop reconnecting. */
  stop(): void {
    if (!this.running) return;
    this.running = false;
    if (this.maintainTimer) clearInterval(this.maintainTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.maintainTimer = null;
    this.retryTimer = null;
    for (const slot of [...this.slots.values()]) slot.peer.close();
    this.slots.clear();
    this.dialing.clear();
  }

  /** Handshaked peers. */
  peers(): PeerInfo[] {
    const out: PeerInfo[] = [];
    for (const s of this.slots.values()) if (s.connected) out.push(this.info(s));
    return out;
  }

  /** Number of handshaked peers. */
  get connectedCount(): number {
    let n = 0;
    for (const s of this.slots.values()) if (s.connected) n++;
    return n;
  }

  /** The underlying `Peer` for a peer id (handshaked or not). */
  getPeer(peerId: string): Peer | undefined {
    return this.slots.get(peerId)?.peer;
  }

  /** Known addresses (for diagnostics / persistence by the caller). */
  addresses(): { address: string; services: bigint; source: AddressSource }[] {
    return [...this.book.values()].map((e) => ({ address: e.address, services: e.services, source: e.source }));
  }

  /**
   * Send an envelope. `stem` → `dp2pmsg` to ONE random connected peer;
   * fluff → `p2pmsg` to every connected peer. Returns the number of peers it went to.
   */
  broadcast(envelope: Uint8Array, opts: { stem: boolean }): number {
    const connected = [...this.slots.values()].filter((s) => s.connected);
    if (connected.length === 0) return 0;
    const targets = opts.stem ? [connected[Math.floor(this.opts.random() * connected.length)]!] : connected;
    let n = 0;
    for (const s of targets) {
      try {
        s.peer.sendP2pMsg(envelope, opts.stem);
        n++;
      } catch (e) {
        this.emit('error', e instanceof Error ? e : new Error(String(e)));
      }
    }
    return n;
  }

  /** Median of connected peers' `clockOffsetSeconds`; 0 with no peers. */
  medianClockOffset(): number {
    const xs = [...this.slots.values()]
      .filter((s) => s.connected)
      .map((s) => s.peer.clockOffsetSeconds)
      .sort((a, b) => a - b);
    if (xs.length === 0) return 0;
    const mid = xs.length >> 1;
    return xs.length % 2 === 1 ? xs[mid]! : (xs[mid - 1]! + xs[mid]!) / 2;
  }

  /** Add a candidate address. Seeds and manual additions are never evicted. */
  addPeerAddress(address: string, opts: { services?: bigint; source?: AddressSource } = {}): boolean {
    let key: string;
    try {
      key = normalizeAddress(address, this.network);
    } catch (e) {
      this.emit('error', e instanceof Error ? e : new Error(String(e)));
      return false;
    }
    const source = opts.source ?? 'manual';
    const services = opts.services ?? 0n;
    const existing = this.book.get(key);
    if (existing) {
      existing.services |= services;
      existing.lastSeen = this.opts.now();
      if (source === 'seed' || source === 'manual') existing.source = source;
      return false;
    }
    if (source === 'gossip') {
      if (!hasService(services, ServiceFlags.NODE_P2PMSG)) return false;
      if (this.book.size >= this.opts.maxAddresses && !this.evictOne()) return false;
    }
    this.book.set(key, {
      address: key,
      services,
      source,
      failures: 0,
      nextTryAt: 0,
      lastSeen: this.opts.now(),
    });
    this.emit('addr', { address: key, services });
    if (this.running) this.maintain();
    return true;
  }

  // -------------------------------------------------------------------------

  private info(s: Slot): PeerInfo {
    const v: PeerVersionInfo = s.peer.peerVersion!;
    return {
      id: s.id,
      address: s.address,
      services: v.services,
      userAgent: v.userAgent,
      startHeight: v.startHeight,
      version: v.version,
      clockOffsetSeconds: s.peer.clockOffsetSeconds,
      connectedAt: s.peer.connectedAt,
    };
  }

  private evictOne(): boolean {
    let victim: BookEntry | null = null;
    for (const e of this.book.values()) {
      if (e.source === 'seed' || e.source === 'manual') continue;
      if (this.isInUse(e.address)) continue;
      if (!victim || e.lastSeen < victim.lastSeen) victim = e;
    }
    if (!victim) return false;
    this.book.delete(victim.address);
    return true;
  }

  private isInUse(address: string): boolean {
    if (this.dialing.has(address)) return true;
    for (const s of this.slots.values()) if (s.address === address) return true;
    return false;
  }

  private maintain(): void {
    if (!this.running) return;
    const want = this.opts.targetPeers - this.slots.size;
    if (want <= 0) return;

    const now = this.opts.now();
    const candidates = [...this.book.values()].filter((e) => !this.isInUse(e.address) && e.nextTryAt <= now);
    // Shuffle (Fisher–Yates) so we do not always dial in book order.
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = Math.floor(this.opts.random() * (i + 1));
      [candidates[i], candidates[j]] = [candidates[j]!, candidates[i]!];
    }
    // No IPv6 route observed recently: stable-partition IPv4 first.
    const ordered =
      this.v6DeprioritisedUntil > now
        ? [...candidates.filter((c) => !isIPv6Address(c.address)), ...candidates.filter((c) => isIPv6Address(c.address))]
        : candidates;
    for (const c of ordered.slice(0, want)) this.dial(c);

    if (candidates.length < want) {
      this.maybeResolveDns();
      this.scheduleRetry(now);
    }
  }

  private scheduleRetry(now: number): void {
    let earliest = Infinity;
    for (const e of this.book.values()) {
      if (this.isInUse(e.address)) continue;
      if (e.nextTryAt > now && e.nextTryAt < earliest) earliest = e.nextTryAt;
    }
    if (earliest === Infinity) return;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.maintain();
    }, Math.max(1, earliest - now));
  }

  private backoff(failures: number): number {
    const base = Math.min(this.opts.maxBackoffMs, this.opts.minBackoffMs * 2 ** Math.min(failures, 20));
    // ±25 % jitter.
    return Math.round(base * (0.75 + this.opts.random() * 0.5));
  }

  private dial(entry: BookEntry): void {
    const address = entry.address;
    let transport: Transport;
    try {
      transport = this.opts.transportFactory(address, this.network);
    } catch (e) {
      entry.failures++;
      entry.nextTryAt = this.opts.now() + this.backoff(entry.failures);
      this.emit('error', e instanceof Error ? e : new Error(String(e)));
      return;
    }
    const id = `${address}#${++this.seq}`;
    const peer = new Peer(transport, {
      ...this.opts.peerOptions,
      network: this.network,
      services: this.opts.services,
      userAgent: this.opts.userAgent,
    });
    const slot: Slot = { id, address, peer, connected: false };
    this.slots.set(id, slot);
    this.dialing.add(address);

    peer.on('addr', (addrs) => this.onGossip(addrs));
    peer.on('message', (m) => this.emit('message', { peerId: id, stem: m.stem, payload: m.payload }));
    peer.on('archive', (m) => this.emit('archive', { peerId: id, payload: m.payload }));
    peer.on('error', (e) => this.emit('error', new Error(`${id}: ${e.message}`)));
    peer.on('close', (err) => {
      const wasConnected = slot.connected;
      this.slots.delete(id);
      this.dialing.delete(address);
      const e = this.book.get(address);
      if (e) {
        if (wasConnected) e.failures = 0;
        else e.failures++;
        e.nextTryAt = this.opts.now() + this.backoff(e.failures);
      }
      if (!wasConnected && err && isIPv6Address(address) && isNoRouteError(err)) {
        this.v6DeprioritisedUntil = this.opts.now() + V6_DEPRIORITISE_MS;
      }
      if (this.running) {
        this.emit('peerclose', { peerId: id, address, error: err, wasConnected });
        this.maintain();
      }
    });

    peer
      .connect()
      .then(() => {
        this.dialing.delete(address);
        if (!this.running || peer.closed) return;
        slot.connected = true;
        entry.failures = 0;
        if (isIPv6Address(address)) this.v6DeprioritisedUntil = 0;
        entry.lastSeen = this.opts.now();
        entry.services |= peer.peerVersion!.services;
        this.emit('peer', this.info(slot));
        // Over target (e.g. an address was added while dialing)? Trim.
        if (this.connectedCount > this.opts.targetPeers) peer.close();
      })
      .catch((e: unknown) => {
        // 'close' handler does the bookkeeping; just report.
        if (this.running) this.emit('error', e instanceof Error ? e : new Error(String(e)));
      });
  }

  private onGossip(addrs: NetAddress[]): void {
    let added = 0;
    for (const a of addrs) {
      if (!hasService(a.services, ServiceFlags.NODE_P2PMSG)) continue;
      if (a.port === 0) continue;
      if (this.addPeerAddress(formatHostPort(a.host, a.port), { services: a.services, source: 'gossip' })) added++;
      if (added >= 100) break;
    }
  }

  private maybeResolveDns(): void {
    if (!this.opts.allowDns || this.dnsInFlight || this.opts.dnsSeeds.length === 0) return;
    // Re-resolve at most every 10 minutes.
    if (this.opts.now() - this.dnsResolvedAt < 600_000) return;
    this.dnsInFlight = true;
    void this.resolveDns().finally(() => {
      this.dnsInFlight = false;
      this.dnsResolvedAt = this.opts.now();
      if (this.running) this.maintain();
    });
  }

  private async resolveDns(): Promise<void> {
    let dns: typeof import('node:dns');
    try {
      dns = await import('node:dns');
    } catch (e) {
      this.emit('error', new Error(`DNS seeding unavailable: ${(e as Error).message}`));
      return;
    }
    const port = DefaultPorts[this.network];
    await Promise.all(
      this.opts.dnsSeeds.map(async (seed) => {
        const hosts: string[] = [];
        const [v4, v6] = await Promise.allSettled([dns.promises.resolve4(seed), dns.promises.resolve6(seed)]);
        if (v4.status === 'fulfilled') hosts.push(...v4.value);
        if (v6.status === 'fulfilled') hosts.push(...v6.value);
        if (hosts.length === 0) {
          const reason = v4.status === 'rejected' ? (v4.reason as Error).message : 'no records';
          this.emit('error', new Error(`DNS seed ${seed}: ${reason}`));
          return;
        }
        for (const h of hosts) this.addPeerAddress(formatHostPort(h, port), { source: 'dns' });
      }),
    );
  }
}
