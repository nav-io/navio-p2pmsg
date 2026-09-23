/**
 * Wire format of the archive query, matching navio-core `src/p2pmsg/archive.h`.
 *
 *   p2pmsgchal  u8[32] challenge          (unsolicited, after verack)
 *   getp2pmsgs  u8 version | ArchiveStamp | u64 cursor | u16 limit | u8 precision
 *               | u32 scan_budget | u8[32] challenge
 *               | CompactSize n, u8[n] detection_key | i64 not_before
 *   p2pmsgs     u8 version | u64 next_cursor | u8 complete
 *               | CompactSize n, n x { u64 id, i64 received_at, CompactSize, envelope }
 *
 * Both command names fit the 12-byte command field. A longer one is silently
 * dead on the wire — navio-core's own `getoutputdata` (13 chars) is the proof.
 */
import { sha256 } from '@noble/hashes/sha256';
import { Reader, Writer } from '../common/serialize.js';
import { hashMeetsTarget } from '../bus/pow.js';
import { FMD_GAMMA, FMD_SCALAR_SIZE } from '../bus/fmd.js';

export const ARCHIVE_PROTOCOL_VERSION = 1;
export const ARCHIVE_STAMP_VERSION = 1;

/** Caps the serving node enforces regardless of the stamp paid. */
export const MAX_ARCHIVE_LIMIT = 500;
export const MAX_ARCHIVE_RESPONSE_BYTES = 2 * 1024 * 1024;
export const MAX_ARCHIVE_SCAN_ENTRIES = 50_000;
/**
 * Entries a query may walk when it names no budget. Small enough to stay free,
 * large enough to be useful — silence must not buy the maximum scan.
 */
export const DEFAULT_ARCHIVE_SCAN_BUDGET = 1000;

/**
 * Proof of work on a query.
 *
 * Deliberately not the envelope's `PoWHeader`: that header carries a session
 * ephemeral pubkey and a payload kind, neither of which means anything for a
 * query, and its pubkey field cannot even encode a placeholder (an all-zero G1
 * point is not a valid compressed encoding).
 */
export interface ArchiveStamp {
  version: number;
  /** unix seconds */
  timestamp: bigint;
  /** commits to the query fields */
  queryHash: Uint8Array; // 32
  nonce: bigint;
}

export function writeArchiveStamp(w: Writer, s: ArchiveStamp): Writer {
  if (s.queryHash.length !== 32) throw new Error('queryHash must be 32 bytes');
  return w.u8(s.version).i64(s.timestamp).bytes(s.queryHash).u64(s.nonce);
}

export function parseArchiveStamp(r: Reader): ArchiveStamp {
  return { version: r.u8(), timestamp: r.i64(), queryHash: r.bytes(32).slice(), nonce: r.u64() };
}

export function archiveStampHash(s: ArchiveStamp): Uint8Array {
  return sha256(writeArchiveStamp(new Writer(), s).finish());
}

/**
 * Difficulty for a query: `base` plus a term that doubles with the work
 * requested, capped at base+8. A scan costs (entries WALKED) x (precision + 2)
 * group multiplications, so the requester pays for both numbers it picks.
 *
 * Priced on `scanBudget`, not on `limit`: `limit` bounds MATCHES, and the two
 * diverge completely for a high-precision key — a 24-bit key almost never
 * matches, so pricing on limit made the cheapest query on the wire the most
 * expensive one to serve.
 *
 * Must stay identical to `ArchiveStampBits` in navio-core or every query is
 * rejected as underpowered.
 */
export function archiveStampBits(baseBits: number, scanBudget: number, precision: number): number {
  let units = Math.max(scanBudget, 1) * Math.max(precision, 1);
  const freeAllowance = 1000 * 4;
  let extra = 0;
  while (units > freeAllowance && extra < 8) {
    units >>= 1;
    extra++;
  }
  return baseBits + extra;
}

/** Grind `nonce` until the stamp meets `bits`. Returns false if `maxIters` ran out. */
export function grindArchiveStamp(stamp: ArchiveStamp, bits: number, maxIters = 1 << 26): boolean {
  for (let i = 0; i < maxIters; i++) {
    stamp.nonce = BigInt(i);
    if (hashMeetsTarget(archiveStampHash(stamp), bits)) return true;
  }
  return false;
}

export interface ArchiveRequest {
  version: number;
  stamp: ArchiveStamp;
  /** Return entries with id > cursor. */
  cursor: bigint;
  limit: number;
  /** n, so `detectionKey` is n * 32 bytes. */
  precision: number;
  /**
   * Entries the server may WALK for this query. What the stamp is priced on
   * and what the walk stops at; the server caps it at
   * `MAX_ARCHIVE_SCAN_ENTRIES`.
   */
  scanBudget: number;
  /**
   * The challenge this server issued on THIS connection (`p2pmsgchal`).
   * Committed to by the stamp, so a grind bought for one node on one
   * connection is worthless anywhere else.
   */
  challenge: Uint8Array; // 32
  detectionKey: Uint8Array;
  /** 0 = no lower bound on `receivedAt`. */
  notBefore: bigint;
}

/** The query fields, i.e. everything the stamp commits to. */
function writeQueryFields(w: Writer, q: Omit<ArchiveRequest, 'stamp'>): Writer {
  if (q.challenge.length !== 32) throw new Error('challenge must be 32 bytes');
  return w
    .u8(q.version)
    .u64(q.cursor)
    .u16(q.limit)
    .u8(q.precision)
    .u32(q.scanBudget)
    .bytes(q.challenge)
    .varBytes(q.detectionKey)
    .i64(q.notBefore);
}

/**
 * What `stamp.queryHash` must equal. Every field is covered, so a peer cannot
 * pay for a cheap scan and then ask for an expensive one.
 */
export function archiveQueryHash(q: Omit<ArchiveRequest, 'stamp'>): Uint8Array {
  return sha256(writeQueryFields(new Writer(), q).finish());
}

export function serializeArchiveRequest(req: ArchiveRequest): Uint8Array {
  if (req.challenge.length !== 32) throw new Error('challenge must be 32 bytes');
  const w = new Writer().u8(req.version);
  writeArchiveStamp(w, req.stamp);
  return w
    .u64(req.cursor)
    .u16(req.limit)
    .u8(req.precision)
    .u32(req.scanBudget)
    .bytes(req.challenge)
    .varBytes(req.detectionKey)
    .i64(req.notBefore)
    .finish();
}

export function parseArchiveRequest(bytes: Uint8Array): ArchiveRequest {
  const r = new Reader(bytes);
  const version = r.u8();
  const stamp = parseArchiveStamp(r);
  const req: ArchiveRequest = {
    version,
    stamp,
    cursor: r.u64(),
    limit: r.u16(),
    precision: r.u8(),
    scanBudget: r.u32(),
    challenge: r.bytes(32).slice(),
    detectionKey: r.varBytes().slice(),
    notBefore: r.i64(),
  };
  r.assertDone();
  return req;
}

export interface ArchiveResponseItem {
  id: bigint;
  receivedAt: bigint;
  envelope: Uint8Array;
}

export interface ArchiveResponse {
  version: number;
  /**
   * Highest id SCANNED, not highest returned. Advancing to it never re-walks
   * ground already covered, even when nothing matched.
   */
  nextCursor: bigint;
  /**
   * The requested window was scanned to the end. False means the node stopped
   * at a cap and there is more — conflating the two silently loses messages.
   */
  complete: boolean;
  items: ArchiveResponseItem[];
}

export function serializeArchiveResponse(res: ArchiveResponse): Uint8Array {
  const w = new Writer().u8(res.version).u64(res.nextCursor).u8(res.complete ? 1 : 0).compactSize(res.items.length);
  for (const it of res.items) w.u64(it.id).i64(it.receivedAt).varBytes(it.envelope);
  return w.finish();
}

export function parseArchiveResponse(bytes: Uint8Array): ArchiveResponse {
  const r = new Reader(bytes);
  const version = r.u8();
  const nextCursor = r.u64();
  const complete = r.u8() === 1;
  const n = r.compactSize();
  const items: ArchiveResponseItem[] = [];
  for (let i = 0; i < n; i++) {
    items.push({ id: r.u64(), receivedAt: r.i64(), envelope: r.varBytes().slice() });
  }
  r.assertDone();
  return { version, nextCursor, complete, items };
}

/** Build a stamped request. Grinds the stamp, which is the point of the design. */
export function buildArchiveRequest(
  q: Omit<ArchiveRequest, 'stamp' | 'version'>,
  opts: { baseBits: number; nowSeconds: number },
): ArchiveRequest {
  if (q.precision < 1 || q.precision > FMD_GAMMA) throw new Error(`precision must be 1..${FMD_GAMMA}`);
  if (q.detectionKey.length !== q.precision * FMD_SCALAR_SIZE) {
    throw new Error('detection key length must match the precision');
  }
  const fields = { ...q, version: ARCHIVE_PROTOCOL_VERSION };
  const stamp: ArchiveStamp = {
    version: ARCHIVE_STAMP_VERSION,
    timestamp: BigInt(opts.nowSeconds),
    queryHash: archiveQueryHash(fields),
    nonce: 0n,
  };
  const bits = archiveStampBits(opts.baseBits, q.scanBudget, q.precision);
  if (!grindArchiveStamp(stamp, bits)) throw new Error('could not grind an archive query stamp');
  return { ...fields, stamp };
}
