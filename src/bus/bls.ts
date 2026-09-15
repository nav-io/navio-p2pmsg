/**
 * BLS12-381 keys, ECDH and signatures matching navio-core's `blsct` module.
 *
 * - Public keys: G1 compressed (48 bytes, blst/mcl "compressed" encoding, big-endian x with flag bits).
 * - Secret keys: Fr scalar, 32 bytes big-endian, 0 < sk < r.
 * - Signatures: G2 compressed (96 bytes). Scheme = message augmentation with the
 *   POP DST: `sig = sk * H2(pk || msg)`, matching `blsct::PrivateKey::Sign`.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { concat, randomBytes } from '../common/bytes.js';

const G1 = bls.G1.Point;
const Fr = bls.fields.Fr;
/** Group order r of BLS12-381. */
export const BLS_ORDER: bigint = Fr.ORDER;

/** Domain separation tag used by navio-core for every signature (`blsct/signature.h`). */
export const BLS_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';

export const PUBLIC_KEY_SIZE = 48;
export const SECRET_KEY_SIZE = 32;
export const SIGNATURE_SIZE = 96;

function bytesToBigint(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

function bigintToScalar(n: bigint): Uint8Array {
  const out = new Uint8Array(SECRET_KEY_SIZE);
  let v = n;
  for (let i = SECRET_KEY_SIZE - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Interpret a 32-byte big-endian secret as a scalar, validating 0 < sk < r. */
export function scalarOf(sk: Uint8Array): bigint {
  if (sk.length !== SECRET_KEY_SIZE) throw new Error('secret key must be 32 bytes');
  const n = bytesToBigint(sk);
  if (n === 0n || n >= BLS_ORDER) throw new Error('secret key out of range');
  return n;
}

/** Random non-zero Fr scalar, 32 bytes big-endian. */
export function generateSecret(): Uint8Array {
  for (;;) {
    const b = randomBytes(SECRET_KEY_SIZE);
    const n = bytesToBigint(b);
    if (n !== 0n && n < BLS_ORDER) return b;
  }
}

/** Validate and copy a 32-byte big-endian secret. Throws if zero or >= r. */
export function secretFromBytes(b: Uint8Array): Uint8Array {
  scalarOf(b);
  return new Uint8Array(b);
}

/**
 * Deterministic scalar from seed material (e.g. HKDF output): interpret as a
 * big-endian integer and map uniformly onto [1, r-1] via `(x mod (r-1)) + 1`.
 */
export function scalarFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length === 0) throw new Error('empty seed');
  const n = (bytesToBigint(seed) % (BLS_ORDER - 1n)) + 1n;
  return bigintToScalar(n);
}

/** G1 public key (compressed, 48 bytes) for a secret scalar. */
export function publicKey(sk: Uint8Array): Uint8Array {
  return G1.BASE.multiply(scalarOf(sk)).toBytes(true);
}

/**
 * True iff `bytes` is a canonical compressed G1 encoding of a point on the
 * curve, in the prime-order subgroup and not the point at infinity.
 */
export function isValidPublicKey(bytes: Uint8Array): boolean {
  if (bytes.length !== PUBLIC_KEY_SIZE) return false;
  try {
    const p = G1.fromBytes(bytes); // asserts on-curve + subgroup
    return !p.equals(G1.ZERO);
  } catch {
    return false;
  }
}

/**
 * True iff `bytes` decodes as a G1 point navio-core's deserialiser accepts:
 * canonical encoding, on curve, in subgroup. Unlike `isValidPublicKey` the
 * point at infinity IS accepted (`BlstG1Point::SetVch` permits it; ECIES
 * rejects it later at decrypt time).
 */
export function isDecodableG1(bytes: Uint8Array): boolean {
  if (bytes.length !== PUBLIC_KEY_SIZE) return false;
  try {
    G1.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}

export function isInfinityG1(bytes: Uint8Array): boolean {
  try {
    return G1.fromBytes(bytes).equals(G1.ZERO);
  } catch {
    return false;
  }
}

/** ECDH: compressed encoding of `pub * sk` (48 bytes). Throws on invalid `pub`. */
export function ecdh(sk: Uint8Array, pub: Uint8Array): Uint8Array {
  const p = G1.fromBytes(pub);
  if (p.equals(G1.ZERO)) throw new Error('ecdh with point at infinity');
  return p.multiply(scalarOf(sk)).toBytes(true);
}

function hashToG2(pk: Uint8Array, msg: Uint8Array) {
  const h = bls.G2.hashToCurve(concat(pk, msg), { DST: BLS_DST });
  return bls.G2.Point.fromAffine(h.toAffine());
}

/** `sig = sk * H2(pk || msg)` with the POP DST (blsct message-augmentation scheme). 96 bytes. */
export function signAugmented(sk: Uint8Array, msg: Uint8Array): Uint8Array {
  const pk = publicKey(sk);
  const h = hashToG2(pk, msg);
  return bls.longSignatures.sign(h, sk).toBytes(true);
}

/** Verify a `signAugmented` signature. Never throws; malformed inputs are simply false. */
export function verifyAugmented(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length !== SIGNATURE_SIZE || !isValidPublicKey(pk)) return false;
  try {
    const h = hashToG2(pk, msg);
    return bls.longSignatures.verify(sig, h, pk);
  } catch {
    return false;
  }
}

/** Well-known broadcast keypair: secret scalar 1, public = G1 generator. NOT a secret. */
export const BROADCAST_SECRET: Uint8Array = bigintToScalar(1n);
export const BROADCAST_PUBLIC: Uint8Array = publicKey(BROADCAST_SECRET);
