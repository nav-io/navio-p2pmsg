/**
 * Fuzzy Message Detection (FMD2), matching navio-core `src/p2pmsg/fmd.cpp`.
 *
 * Scheme: Beck, Len, Miers, Green, "Fuzzy Message Detection", ePrint 2021/089,
 * Figure 3, instantiated over BLS12-381 G1.
 *
 * WHAT IT IS FOR. The bus carries no recipient field: an envelope is
 * `kind || PoWHeader || EciesPacket`, and the only way to learn who a message
 * is for is to hold the key and try. Excellent for privacy, and exactly why a
 * store cannot hold messages for someone who is offline — it has nothing to
 * index on.
 *
 * A flag gives a store something to filter on that matches the recipient's
 * messages plus a `2^-n` fraction of everyone else's, where `n` is chosen by
 * the RETRIEVING client. The property that matters: holding someone's public
 * clue key does NOT let you test whether a flag is theirs. Testing needs a
 * detection key, derived from the secret. A plain tag like
 * `H(pubkey || epoch)` fails exactly there.
 *
 * WHAT A DETECTOR LEARNS. The set matching the precision-`n` key it was given
 * — your messages plus `2^-n` of everything else — and nothing about which is
 * which. A detection key keeps working on FUTURE flags, so it is scoped to a
 * key epoch and rotated with the inbox prekey.
 *
 * NOT USED: the compact single-point clue key (`x_i = x + H(X||i)`, 48 bytes
 * instead of 1152). `H(X||i)` is public, so a detector given a precision-`n`
 * key recovers `x` and can then test at full precision — precision would stop
 * being the client's choice and become the detector's.
 */
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { concat, utf8 } from '../common/bytes.js';
import {
  BLS_ORDER,
  frFromBytesWide,
  frInv,
  frToBytes,
  g1Add,
  g1Mul,
  g1MulBase,
  generateSecret,
  isDecodableG1,
  isInfinityG1,
  scalarOf,
} from './bls.js';

/** Number of flag bits, i.e. the maximum detection precision (`2^-gamma`). */
export const FMD_GAMMA = 24;
export const FMD_POINT_SIZE = 48;
export const FMD_SCALAR_SIZE = 32;
/** gamma is a multiple of 8, so the packed bits have no spare padding. */
export const FMD_BITS_SIZE = FMD_GAMMA / 8;
/** `u` (48) || `y` (32) || `c` (3). */
export const FMD_FLAG_SIZE = FMD_POINT_SIZE + FMD_SCALAR_SIZE + FMD_BITS_SIZE;
/** gamma compressed G1 points. */
export const FMD_CLUE_KEY_SIZE = FMD_GAMMA * FMD_POINT_SIZE;

// Domain separation. H : G^3 -> {0,1} and G : G x {0,1}^gamma -> Zq in the
// paper; distinct tags keep them independent random oracles.
const TAG_BIT = utf8('navio-p2pmsg/fmd/v1/bit');
const TAG_SCALAR = utf8('navio-p2pmsg/fmd/v1/scalar');
const TAG_KEY = utf8('navio-p2pmsg/fmd/v1/key');

/**
 * `H(u || s || w) -> one bit`. `s` is `h_i^r` for the sender and `u^{x_i}` for
 * the detector; they are the same point exactly when the flag was made for this
 * key, which is what makes the scheme work.
 */
function hashBit(u: Uint8Array, s: Uint8Array, w: Uint8Array): number {
  return sha256(concat(TAG_BIT, u, s, w))[0]! & 1;
}

/** `G(u || c_1..c_gamma) -> Zq`, hashed wide and reduced so it is unbiased. */
function hashScalar(u: Uint8Array, bits: Uint8Array): bigint {
  return frFromBytesWide(sha512(concat(TAG_SCALAR, u, bits)));
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function getBit(bits: Uint8Array, i: number): number {
  return (bits[i >> 3]! >> (i & 7)) & 1;
}

function setBit(bits: Uint8Array, i: number, v: number): void {
  if (v) bits[i >> 3]! |= 1 << (i & 7);
}

/** The public key a sender needs in order to flag a message to someone. */
export interface FmdClueKey {
  /** gamma compressed G1 points, `h_i = g^{x_i}`. */
  h: Uint8Array[];
}

/** The recipient's root secret: gamma INDEPENDENT scalars. */
export interface FmdSecretKey {
  /** gamma 32-byte big-endian scalars. */
  x: Uint8Array[];
}

/** `FMD_CLUE_KEY_SIZE` bytes, `h_1 .. h_gamma` compressed. */
export function serializeClueKey(ck: FmdClueKey): Uint8Array {
  if (ck.h.length !== FMD_GAMMA) throw new Error(`clue key must hold ${FMD_GAMMA} points`);
  return concat(...ck.h);
}

/** Parse and validate every point: canonical, on curve, in subgroup, not infinity. */
export function parseClueKey(bytes: Uint8Array): FmdClueKey {
  if (bytes.length !== FMD_CLUE_KEY_SIZE) throw new Error('clue key must be 1152 bytes');
  const h: Uint8Array[] = [];
  for (let i = 0; i < FMD_GAMMA; i++) {
    const p = bytes.slice(i * FMD_POINT_SIZE, (i + 1) * FMD_POINT_SIZE);
    if (!isDecodableG1(p)) throw new Error(`clue key point ${i} is not a valid G1 encoding`);
    // Infinity would make h_i^r infinity for every r, so every sender would
    // derive the same bit and the flag would carry no information.
    if (isInfinityG1(p)) throw new Error(`clue key point ${i} is the point at infinity`);
    h.push(p);
  }
  return { h };
}

/** True iff `bytes` is a well-formed clue key. */
export function isValidClueKey(bytes: Uint8Array): boolean {
  try {
    parseClueKey(bytes);
    return true;
  } catch {
    return false;
  }
}

export function clueKeyOf(sk: FmdSecretKey): FmdClueKey {
  return { h: sk.x.map((x) => g1MulBase(scalarOf(x))) };
}

/** A fresh random root secret. */
export function generateFmdSecret(): FmdSecretKey {
  return { x: Array.from({ length: FMD_GAMMA }, () => generateSecret()) };
}

/**
 * Deterministic derivation, so a key survives a restore from seed.
 * `x_i = SHA512("navio-p2pmsg/fmd/v1/key" || seed || u32le(epoch) || u32le(i)) mod r`
 * — byte-identical to `FmdSecretKey::FromSeed` in navio-core.
 */
export function fmdSecretFromSeed(seed: Uint8Array, epoch = 0): FmdSecretKey {
  const x: Uint8Array[] = [];
  for (let i = 0; i < FMD_GAMMA; i++) {
    const wide = sha512(concat(TAG_KEY, seed, u32le(epoch), u32le(i)));
    x.push(frToBytes(frFromBytesWide(wide)));
  }
  return { x };
}

/**
 * Detection key for false-positive rate `2^-n`: the first `n` scalars.
 *
 * SECRET and long-lived: whoever holds it can test every future flag at this
 * precision until the clue key rotates. The `x_i` are independent, so a
 * precision-`n` key yields nothing about `n+1`.
 */
export function extractDetectionKey(sk: FmdSecretKey, n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 1 || n > FMD_GAMMA) {
    throw new Error(`precision must be an integer in 1..${FMD_GAMMA}`);
  }
  return concat(...sk.x.slice(0, n));
}

/**
 * Flag a message to `ck`. `FMD_FLAG_SIZE` bytes.
 *
 * Costs `gamma + 2` group multiplications — negligible beside the envelope's
 * proof of work.
 */
export function fmdFlag(ck: FmdClueKey): Uint8Array {
  if (ck.h.length !== FMD_GAMMA) throw new Error(`clue key must hold ${FMD_GAMMA} points`);

  // u = g^r is the shared ElGamal element; every k_i is keyed off h_i^r.
  const r = scalarOf(generateSecret());
  const u = g1MulBase(r);

  // w = g^z is a chameleon-hash commitment. Binding (y, m) to the whole
  // ciphertext below is what makes the scheme CCA-secure: mauling any c_i
  // changes m, so w fails to reproduce and every bit is randomised.
  const z = scalarOf(generateSecret());
  const w = g1MulBase(z);

  const bits = new Uint8Array(FMD_BITS_SIZE);
  for (let i = 0; i < FMD_GAMMA; i++) {
    setBit(bits, i, hashBit(u, g1Mul(ck.h[i]!, r), w) ^ 1);
  }

  const m = hashScalar(u, bits);
  const y = ((z - m + BLS_ORDER) % BLS_ORDER) * frInv(r) % BLS_ORDER;
  return concat(u, frToBytes(y), bits);
}

/**
 * Test `flag` against a detection key from `extractDetectionKey`. Precision is
 * taken from the key length. False for any malformed input.
 *
 * Costs `n + 2` group multiplications; this is the per-envelope cost of an
 * archive scan.
 */
export function fmdTest(detectionKey: Uint8Array, flag: Uint8Array): boolean {
  if (flag.length !== FMD_FLAG_SIZE) return false;
  if (detectionKey.length === 0 || detectionKey.length % FMD_SCALAR_SIZE !== 0) return false;
  const n = detectionKey.length / FMD_SCALAR_SIZE;
  if (n > FMD_GAMMA) return false;

  const u = flag.subarray(0, FMD_POINT_SIZE);
  // An infinity u makes u^{x_i} infinity for EVERY key, so one flag would match
  // every recipient: free spam into everyone's bucket at once.
  if (!isDecodableG1(u) || isInfinityG1(u)) return false;

  const y = frFromBytesWide(flag.subarray(FMD_POINT_SIZE, FMD_POINT_SIZE + FMD_SCALAR_SIZE));
  const bits = flag.subarray(FMD_POINT_SIZE + FMD_SCALAR_SIZE);

  try {
    const m = hashScalar(u, bits);
    // Recover the sender's w from the collision (y, m):
    // g^m * u^y = g^m * g^{ry} = g^{m + (z-m)} = g^z.
    const w = g1Add(g1MulBase(m), g1Mul(u, y));

    for (let i = 0; i < n; i++) {
      const xi = detectionKey.subarray(i * FMD_SCALAR_SIZE, (i + 1) * FMD_SCALAR_SIZE);
      const k = hashBit(u, g1Mul(u, frFromBytesWide(xi)), w);
      // Every bit of a genuine flag decrypts to the sentinel 1.
      if ((k ^ getBit(bits, i)) !== 1) return false;
    }
    return true;
  } catch {
    return false;
  }
}
