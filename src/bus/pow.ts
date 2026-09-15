/**
 * Hashcash-style PoW stamp matching navio-core `src/p2pmsg/pow.cpp`.
 *
 * PoWHeader (98 bytes, fixed):
 *   u8 version | i64 timestamp | u8 kind | u8[48] session_eph | u8[32] payload_hash | u64 nonce
 *
 * Hash = single SHA256 over the 98 bytes. Accept iff `UintToArith256(hash) <= (2^256-1) >> bits`.
 * `UintToArith256` reads the digest as a LITTLE-ENDIAN integer, so the `bits`
 * leading zero bits live at the END of the digest (byte 31 first, msb first).
 *
 * Grinding uses a SHA-256 midstate: the first 64 header bytes form a complete
 * block that never contains the nonce (bytes 90..97), so its compression is
 * done once and each attempt only runs the final block.
 *
 * Measured (Node 26, Apple M2 Max, but on a machine with load average ~120,
 * so absolute numbers are pessimistic): ~325k hashes/s with the midstate
 * compressor below vs ~105k/s for `@noble/hashes` `sha256(hdr)` per attempt and
 * ~160k/s for `sha256.create().update(first64).clone()` per attempt, i.e. the
 * midstate path is ~3x plain hashing. On an idle core expect a few million/s.
 */
import { sha256 } from '@noble/hashes/sha256';
import { Reader, Writer } from '../common/serialize.js';

export const POW_HEADER_SIZE = 98;
export const POW_TIMESTAMP_TOLERANCE_SECONDS = 120;
/** navio-core default difficulty on mainnet/testnet (`-p2pmsgpowbits`). */
export const DEFAULT_POW_BITS = 23;

export interface PoWHeader {
  version: number;
  /** unix seconds */
  timestamp: bigint;
  kind: number;
  /** 48 bytes, = EciesPacket.eph */
  sessionEph: Uint8Array;
  /** 32 bytes, = EciesPacket MsgHash */
  payloadHash: Uint8Array;
  nonce: bigint;
}

export function writePoWHeader(w: Writer, h: PoWHeader): Writer {
  if (h.sessionEph.length !== 48) throw new Error('sessionEph must be 48 bytes');
  if (h.payloadHash.length !== 32) throw new Error('payloadHash must be 32 bytes');
  return w.u8(h.version).i64(h.timestamp).u8(h.kind).bytes(h.sessionEph).bytes(h.payloadHash).u64(h.nonce);
}

export function serializePoWHeader(h: PoWHeader): Uint8Array {
  return writePoWHeader(new Writer(), h).finish();
}

export function parsePoWHeader(r: Reader): PoWHeader {
  const version = r.u8();
  const timestamp = r.i64();
  const kind = r.u8();
  const sessionEph = r.bytes(48).slice();
  const payloadHash = r.bytes(32).slice();
  const nonce = r.u64();
  return { version, timestamp, kind, sessionEph, payloadHash, nonce };
}

/** Single SHA256 over the serialised header. */
export function powHash(h: PoWHeader): Uint8Array {
  return sha256(serializePoWHeader(h));
}

/**
 * `UintToArith256(hash) <= (2^256-1) >> bits`, i.e. the top `bits` bits of the
 * digest read as a little-endian integer are zero: byte 31 (msb first), then 30, ...
 */
export function hashMeetsTarget(hash: Uint8Array, bits: number): boolean {
  if (hash.length !== 32) throw new Error('hash must be 32 bytes');
  if (bits <= 0) return true;
  if (bits >= 256) {
    for (let i = 0; i < 32; i++) if (hash[i] !== 0) return false;
    return true;
  }
  const fullBytes = bits >>> 3;
  const rem = bits & 7;
  for (let i = 31; i > 31 - fullBytes; i--) if (hash[i] !== 0) return false;
  if (rem === 0) return true;
  return hash[31 - fullBytes]! >>> (8 - rem) === 0;
}

export function checkPoW(h: PoWHeader, bits: number): boolean {
  return hashMeetsTarget(powHash(h), bits);
}

/** True iff the header timestamp is within `tolerance` seconds of `nowSeconds`. */
export function checkTimestamp(h: PoWHeader, nowSeconds: number | bigint, toleranceSeconds = POW_TIMESTAMP_TOLERANCE_SECONDS): boolean {
  const now = BigInt(nowSeconds);
  const tol = BigInt(toleranceSeconds);
  if (h.timestamp > now + tol) return false;
  if (h.timestamp < now - tol) return false;
  return true;
}

// ---------------------------------------------------------------------------
// SHA-256 compression function (FIPS 180-4), used for the midstate grinder.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** One SHA-256 compression: `state` (8 words) updated in place with `W` (>= 16 message words; expanded in place). */
function compress(state: Uint32Array, W: Uint32Array): void {
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15]!;
    const w2 = W[i - 2]!;
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16]! + s0 + W[i - 7]! + s1) | 0;
  }
  let a = state[0]!, b = state[1]!, c = state[2]!, d = state[3]!;
  let e = state[4]!, f = state[5]!, g = state[6]!, h = state[7]!;
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K[i]! + W[i]!) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  state[0] = (state[0]! + a) | 0; state[1] = (state[1]! + b) | 0;
  state[2] = (state[2]! + c) | 0; state[3] = (state[3]! + d) | 0;
  state[4] = (state[4]! + e) | 0; state[5] = (state[5]! + f) | 0;
  state[6] = (state[6]! + g) | 0; state[7] = (state[7]! + h) | 0;
}

function loadBlock(W: Uint32Array, block: Uint8Array, off: number): void {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4;
    W[i] = ((block[j]! << 24) | (block[j + 1]! << 16) | (block[j + 2]! << 8) | block[j + 3]!) >>> 0;
  }
}

/** Little-endian-integer target test on the 8 state words (word 7 = digest bytes 28..31). */
function stateMeetsTarget(state: Uint32Array, bits: number): boolean {
  let remaining = bits;
  for (let wi = 7; wi >= 0 && remaining > 0; wi--) {
    const w = state[wi]!;
    // digest bytes of this word, big-endian; the LE integer's msb is the LAST byte.
    const swapped = (((w & 0xff) << 24) | ((w & 0xff00) << 8) | ((w >>> 8) & 0xff00) | (w >>> 24)) >>> 0;
    if (remaining >= 32) {
      if (swapped !== 0) return false;
      remaining -= 32;
    } else {
      return swapped >>> (32 - remaining) === 0;
    }
  }
  return true;
}

/**
 * Precomputed SHA-256 midstate for a 98-byte PoW header: the first block
 * (bytes 0..63) is compressed once; `hashWithNonce` only runs the final block.
 */
export class PowMidstate {
  private readonly mid = new Uint32Array(8);
  private readonly W = new Uint32Array(64);
  private readonly state = new Uint32Array(8);
  private readonly w6base: number;
  private readonly tail: Uint32Array;

  constructor(header98: Uint8Array) {
    if (header98.length !== POW_HEADER_SIZE) throw new Error('header must be 98 bytes');
    this.mid.set(IV);
    loadBlock(this.W, header98, 0);
    compress(this.mid, this.W);
    // Final block: header[64..89] (26 fixed bytes), nonce LE (8), 0x80, zeros, bit-length 784.
    const blk = new Uint8Array(64);
    blk.set(header98.subarray(64, 90), 0);
    blk[34] = 0x80;
    blk[62] = 0x03; blk[63] = 0x10; // 98*8 = 784 = 0x310 (big-endian u64 at 56..63)
    this.tail = new Uint32Array(16);
    loadBlock(this.tail, blk, 0);
    this.w6base = (this.tail[6]! & 0xffff0000) >>> 0;
  }

  /** Run the final block for nonce (lo, hi) as two u32 halves; state left in `this.state`. */
  private run(lo: number, hi: number): Uint32Array {
    const W = this.W;
    W.set(this.tail);
    // nonce bytes n0..n7 (LE) sit at block offsets 26..33 => words 6 (low half), 7, 8 (high half)
    W[6] = (this.w6base | ((lo & 0xff) << 8) | ((lo >>> 8) & 0xff)) >>> 0;
    W[7] = ((((lo >>> 16) & 0xff) << 24) | (((lo >>> 24) & 0xff) << 16) | ((hi & 0xff) << 8) | ((hi >>> 8) & 0xff)) >>> 0;
    W[8] = ((((hi >>> 16) & 0xff) << 24) | (((hi >>> 24) & 0xff) << 16) | 0x8000) >>> 0;
    const st = this.state;
    st.set(this.mid);
    compress(st, W);
    return st;
  }

  /** Full 32-byte digest for a given nonce (equals `powHash` of the header with that nonce). */
  hashWithNonce(nonce: bigint): Uint8Array {
    const n = BigInt.asUintN(64, nonce);
    const st = this.run(Number(n & 0xffffffffn), Number(n >> 32n));
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const w = st[i]!;
      out[i * 4] = w >>> 24; out[i * 4 + 1] = (w >>> 16) & 0xff;
      out[i * 4 + 2] = (w >>> 8) & 0xff; out[i * 4 + 3] = w & 0xff;
    }
    return out;
  }

  /**
   * Try nonces `start, start+stride, ...` for up to `maxIters` attempts (0 = unbounded).
   * Returns the first nonce meeting `bits`, or null when exhausted.
   */
  search(start: bigint, stride: number, bits: number, maxIters: number): bigint | null {
    const s = BigInt.asUintN(64, start);
    let lo = Number(s & 0xffffffffn);
    let hi = Number(s >> 32n);
    const step = Math.max(1, Math.floor(stride)) >>> 0;
    const unbounded = maxIters <= 0;
    for (let i = 0; unbounded || i < maxIters; i++) {
      if (stateMeetsTarget(this.run(lo, hi), bits)) {
        return (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
      }
      lo += step;
      if (lo > 0xffffffff) {
        lo -= 0x100000000;
        hi = (hi + 1) >>> 0;
      }
    }
    return null;
  }
}

export interface GrindOptions {
  /** Attempts before giving up (0 = unbounded). */
  maxIters?: number;
  /** First nonce to try (default: header.nonce). */
  startNonce?: bigint;
  /** Nonce increment between attempts (default 1; worker i of N uses start i, stride N). */
  stride?: number;
}

/**
 * Synchronous grind. Returns the nonce meeting `bits`, or null if `maxIters`
 * was exhausted. Does not mutate `header`.
 */
export function grindSync(header: PoWHeader, bits: number, opts: GrindOptions = {}): bigint | null {
  const mid = new PowMidstate(serializePoWHeader(header));
  return mid.search(opts.startNonce ?? header.nonce, opts.stride ?? 1, bits, opts.maxIters ?? 0);
}

/** Copy of `header` with a different nonce. */
export function withNonce(header: PoWHeader, nonce: bigint): PoWHeader {
  return { ...header, nonce };
}
