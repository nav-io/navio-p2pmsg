/**
 * Network constants and payload codecs for the handful of P2P messages the
 * leaf client speaks: version, verack, ping/pong, sendaddrv2, getaddr,
 * addr, addrv2 (BIP155), p2pmsg/dp2pmsg (opaque passthrough).
 */
import { Reader, Writer } from '../common/serialize.js';

export type NetworkName = 'mainnet' | 'testnet' | 'regtest';

export const NetworkMagic: Record<NetworkName, Uint8Array> = {
  mainnet: new Uint8Array([0xbd, 0x5f, 0xc3, 0x00]),
  testnet: new Uint8Array([0x24, 0x67, 0xd2, 0xc1]),
  regtest: new Uint8Array([0xfd, 0xbf, 0x9f, 0xfb]),
};

export const DefaultPorts: Record<NetworkName, number> = {
  mainnet: 48470,
  testnet: 33670,
  regtest: 18444,
};

export const PROTOCOL_VERSION = 70016;

export const ServiceFlags = {
  NODE_NONE: 0n,
  NODE_NETWORK: 1n << 0n,
  NODE_BLOOM: 1n << 2n,
  NODE_WITNESS: 1n << 3n,
  NODE_COMPACT_FILTERS: 1n << 6n,
  NODE_NETWORK_LIMITED: 1n << 10n,
  NODE_P2P_V2: 1n << 11n,
  /** Node relays the p2pmsg overlay (stem + fluff). */
  NODE_P2PMSG: 1n << 24n,
  /** Leaf client: receives fluff, never chosen as stem successor, relays nothing. */
  NODE_P2PMSG_LEAF: 1n << 25n,
  /**
   * The peer RETAINS the flagged envelopes it relays and will serve them back
   * on `getp2pmsgs`, so a client that was offline can catch up through it.
   * Orthogonal to relaying: an archiving node normally sets NODE_P2PMSG too.
   */
  NODE_P2PMSG_ARCHIVE: 1n << 26n,
} as const;

export function hasService(services: bigint, flag: bigint): boolean {
  return (services & flag) === flag;
}

export const MessageType = {
  VERSION: 'version',
  VERACK: 'verack',
  PING: 'ping',
  PONG: 'pong',
  SENDADDRV2: 'sendaddrv2',
  GETADDR: 'getaddr',
  ADDR: 'addr',
  ADDRV2: 'addrv2',
  P2PMSG: 'p2pmsg',
  DP2PMSG: 'dp2pmsg',
  // Both fit the 12-byte command field. A longer name is silently dead on the
  // wire — navio-core's own `getoutputdata` (13 chars) is the cautionary tale.
  GETP2PMSGS: 'getp2pmsgs',
  P2PMSGS: 'p2pmsgs',
} as const;

// ---------------------------------------------------------------------------
// IP address helpers
// ---------------------------------------------------------------------------

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** 16-byte network-order address; IPv4 is encoded as IPv4-mapped IPv6 (::ffff:a.b.c.d). */
export function ipToBytes(host: string): Uint8Array {
  const out = new Uint8Array(16);
  const v4 = parseIpv4(host);
  if (v4) {
    out[10] = 0xff;
    out[11] = 0xff;
    out.set(v4, 12);
    return out;
  }
  let s = host;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  const groups = parseIpv6Groups(s);
  if (!groups) throw new Error(`invalid IP address: ${host}`);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = groups[i]! >> 8;
    out[i * 2 + 1] = groups[i]! & 0xff;
  }
  return out;
}

export function ipv4ToBytes(host: string): Uint8Array {
  const v4 = parseIpv4(host);
  if (!v4) throw new Error(`invalid IPv4 address: ${host}`);
  return v4;
}

function parseIpv4(s: string): Uint8Array | null {
  const m = IPV4_RE.exec(s);
  if (!m) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(m[i + 1]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIpv6Groups(s: string): number[] | null {
  if (s.length === 0) return null;
  // Trailing dotted IPv4 (e.g. ::ffff:1.2.3.4).
  let tailV4: Uint8Array | null = null;
  const lastColon = s.lastIndexOf(':');
  if (lastColon >= 0 && s.slice(lastColon + 1).includes('.')) {
    tailV4 = parseIpv4(s.slice(lastColon + 1));
    if (!tailV4) return null;
    s = s.slice(0, lastColon + 1) + `${((tailV4[0]! << 8) | tailV4[1]!).toString(16)}:${((tailV4[2]! << 8) | tailV4[3]!).toString(16)}`;
  }
  const parts = s.split('::');
  if (parts.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (side === '') return [];
    const gs = side.split(':');
    const out: number[] = [];
    for (const g of gs) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parseSide(parts[0]!);
  if (!head) return null;
  if (parts.length === 1) return head.length === 8 ? head : null;
  const tail = parseSide(parts[1]!);
  if (!tail) return null;
  const fill = 8 - head.length - tail.length;
  if (fill < 1) return null;
  return [...head, ...new Array<number>(fill).fill(0), ...tail];
}

/** Render a 16-byte address: dotted quad for IPv4-mapped, compressed IPv6 otherwise. */
export function bytesToIp(b: Uint8Array): string {
  if (b.length === 4) return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
  if (b.length !== 16) throw new Error(`invalid IP byte length: ${b.length}`);
  let mapped = b[10] === 0xff && b[11] === 0xff;
  for (let i = 0; i < 10 && mapped; i++) if (b[i] !== 0) mapped = false;
  if (mapped) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) groups.push((b[i * 2]! << 8) | b[i * 2 + 1]!);
  // Longest run of zeros (length >= 2) gets compressed to '::'.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':');
  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':');
  return `${head}::${tail}`;
}

// ---------------------------------------------------------------------------
// version / verack
// ---------------------------------------------------------------------------

export interface NetAddrNoTime {
  services: bigint;
  /** IPv4 dotted quad or IPv6 text. */
  host: string;
  port: number;
}

export interface VersionMessage {
  version: number;
  services: bigint;
  /** Unix seconds. */
  timestamp: bigint;
  addrRecv: NetAddrNoTime;
  addrFrom: NetAddrNoTime;
  nonce: bigint;
  userAgent: string;
  startHeight: number;
  relay: boolean;
}

function writeNetAddrNoTime(w: Writer, a: NetAddrNoTime): void {
  w.u64(a.services);
  w.bytes(ipToBytes(a.host));
  w.u8(a.port >> 8).u8(a.port & 0xff); // port is big-endian on the wire
}

function readNetAddrNoTime(r: Reader): NetAddrNoTime {
  const services = r.u64();
  const host = bytesToIp(r.bytes(16));
  const port = (r.u8() << 8) | r.u8();
  return { services, host, port };
}

export function encodeVersion(v: VersionMessage): Uint8Array {
  const w = new Writer();
  w.i32(v.version);
  w.u64(v.services);
  w.i64(v.timestamp);
  writeNetAddrNoTime(w, v.addrRecv);
  writeNetAddrNoTime(w, v.addrFrom);
  w.u64(v.nonce);
  w.varString(v.userAgent);
  w.i32(v.startHeight);
  w.u8(v.relay ? 1 : 0);
  return w.finish();
}

/** Lenient decode: tolerates truncated trailing fields (old peers may omit user_agent / relay). */
export function decodeVersion(payload: Uint8Array): VersionMessage {
  const r = new Reader(payload);
  const version = r.i32();
  const services = r.u64();
  const timestamp = r.i64();
  const addrRecv = readNetAddrNoTime(r);
  let addrFrom: NetAddrNoTime = { services: 0n, host: '::', port: 0 };
  let nonce = 0n;
  let userAgent = '';
  let startHeight = 0;
  let relay = true;
  if (r.remaining >= 26) addrFrom = readNetAddrNoTime(r);
  if (r.remaining >= 8) nonce = r.u64();
  if (r.remaining >= 1) userAgent = r.varString();
  if (r.remaining >= 4) startHeight = r.i32();
  if (r.remaining >= 1) relay = r.u8() !== 0;
  return { version, services, timestamp, addrRecv, addrFrom, nonce, userAgent, startHeight, relay };
}

// ---------------------------------------------------------------------------
// ping / pong
// ---------------------------------------------------------------------------

export function encodePing(nonce: bigint): Uint8Array {
  return new Writer().u64(nonce).finish();
}

/** Decodes a ping or pong nonce. Returns null if the payload has no nonce (pre-BIP31). */
export function decodePing(payload: Uint8Array): bigint | null {
  if (payload.length < 8) return null;
  return new Reader(payload).u64();
}

export const encodePong = encodePing;
export const decodePong = decodePing;

// ---------------------------------------------------------------------------
// addr / addrv2
// ---------------------------------------------------------------------------

export interface NetAddress {
  host: string;
  port: number;
  services: bigint;
  /** Unix seconds, as gossiped. */
  time: number;
}

/** BIP155 network ids. */
export const Bip155Network = {
  IPV4: 1,
  IPV6: 2,
  TORV2: 3,
  TORV3: 4,
  I2P: 5,
  CJDNS: 6,
} as const;

const MAX_ADDR_TO_SEND = 1000;
const BIP155_MAX_ADDR_SIZE = 512;

export function encodeAddr(addrs: NetAddress[]): Uint8Array {
  const w = new Writer();
  w.compactSize(addrs.length);
  for (const a of addrs) {
    w.u32(a.time);
    writeNetAddrNoTime(w, a);
  }
  return w.finish();
}

export function decodeAddr(payload: Uint8Array): NetAddress[] {
  const r = new Reader(payload);
  const n = r.compactSize();
  if (n > MAX_ADDR_TO_SEND) throw new Error(`addr message too large: ${n}`);
  const out: NetAddress[] = [];
  for (let i = 0; i < n; i++) {
    const time = r.u32();
    const a = readNetAddrNoTime(r);
    out.push({ time, ...a });
  }
  return out;
}

function readCompactSizeBig(r: Reader): bigint {
  const first = r.u8();
  if (first < 253) return BigInt(first);
  if (first === 253) return BigInt(r.u16());
  if (first === 254) return BigInt(r.u32());
  return r.u64();
}

export function encodeAddrV2(addrs: NetAddress[]): Uint8Array {
  const w = new Writer();
  w.compactSize(addrs.length);
  for (const a of addrs) {
    w.u32(a.time);
    w.compactSize(a.services);
    const v4 = parseIpv4(a.host);
    if (v4) {
      w.u8(Bip155Network.IPV4);
      w.varBytes(v4);
    } else {
      w.u8(Bip155Network.IPV6);
      w.varBytes(ipToBytes(a.host));
    }
    w.u8(a.port >> 8).u8(a.port & 0xff);
  }
  return w.finish();
}

/**
 * Decode a BIP155 `addrv2` payload. Entries on networks other than IPv4/IPv6
 * (Tor, I2P, CJDNS, unknown) are skipped, not errors.
 */
export function decodeAddrV2(payload: Uint8Array): NetAddress[] {
  const r = new Reader(payload);
  const n = r.compactSize();
  if (n > MAX_ADDR_TO_SEND) throw new Error(`addrv2 message too large: ${n}`);
  const out: NetAddress[] = [];
  for (let i = 0; i < n; i++) {
    const time = r.u32();
    const services = readCompactSizeBig(r);
    const network = r.u8();
    const len = r.compactSize();
    if (len > BIP155_MAX_ADDR_SIZE) throw new Error(`addrv2 address too long: ${len}`);
    const addr = r.bytes(len);
    const port = (r.u8() << 8) | r.u8();
    if (network === Bip155Network.IPV4 && len === 4) {
      out.push({ host: bytesToIp(addr), port, services, time });
    } else if (network === Bip155Network.IPV6 && len === 16) {
      out.push({ host: bytesToIp(addr), port, services, time });
    }
    // else: unsupported network or malformed length for a known one → skip
  }
  return out;
}
