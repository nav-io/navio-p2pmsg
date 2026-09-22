/**
 * ElligatorSwift for secp256k1 (BIP324).
 *
 * A normal compressed public key is instantly recognisable on the wire. BIP324
 * instead sends a 64-byte encoding that is computationally indistinguishable
 * from uniform random bytes, so a v2 handshake has no fixed structure for a
 * censor to match on. That is the entire point of the construction, and the
 * reason the v2 handshake starts with garbage rather than a magic number.
 *
 * `xswiftec` maps a pair of field elements (u, t) to an X coordinate;
 * `xswiftecInv` inverts it for a chosen branch, which is how we encode a key we
 * actually own. Both follow the BIP324 reference implementation exactly —
 * including which square root is taken, since a different root yields a
 * different (still valid) encoding and would break the published vectors.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  add,
  div,
  fromBytes,
  inv,
  isValidX,
  mod,
  mul,
  neg,
  P,
  sqr,
  sqrt,
  sub,
  toBytes,
} from './field.js';

export const ELLSWIFT_SIZE = 64;

/** sqrt(-3) mod p, the constant the map is built around. */
const MINUS_3_SQRT = sqrt(mod(-3n))!;

/** u³ + 7, the curve equation's right-hand side at u. */
function uCubedPlus7(u: bigint): bigint {
  return add(mul(sqr(u), u), 7n);
}

/**
 * Decode a field-element pair to an X coordinate on the curve. Total: every
 * (u, t) maps somewhere, which is what makes the encoding indistinguishable
 * from random bytes.
 */
export function xswiftec(uIn: bigint, tIn: bigint): bigint {
  let u = uIn;
  let t = tIn;
  // Zero inputs are remapped rather than rejected, so no 64-byte string is
  // invalid.
  if (u === 0n) u = 1n;
  if (t === 0n) t = 1n;
  if (add(uCubedPlus7(u), sqr(t)) === 0n) t = mul(2n, t);

  const X = div(sub(uCubedPlus7(u), sqr(t)), mul(2n, t))!;
  const Y = div(add(X, t), mul(MINUS_3_SQRT, u))!;

  const candidates = [
    add(u, mul(4n, sqr(Y))),
    div(sub(neg(div(X, Y)!), u), 2n)!,
    div(sub(div(X, Y)!, u), 2n)!,
  ];
  for (const x of candidates) {
    if (isValidX(x)) return x;
  }
  // Unreachable for a well-formed field: one of the three is always on the
  // curve. Throwing beats returning a bogus X that would then be "ECDH'd".
  throw new Error('xswiftec: no valid X coordinate');
}

/**
 * Find `t` such that `xswiftec(u, t) === x`, for one of the up to 8 branches.
 * Returns undefined when this branch has no solution — the caller retries with
 * another `u`/`case`, which is what makes encoding a rejection sampler.
 */
export function xswiftecInv(x: bigint, u: bigint, c: number): bigint | undefined {
  let v: bigint;
  let s: bigint;

  if ((c & 2) === 0) {
    if (isValidX(neg(add(x, u)))) return undefined;
    v = x;
    const denom = add(add(sqr(u), mul(u, v)), sqr(v));
    const q = div(neg(uCubedPlus7(u)), denom);
    if (q === undefined) return undefined;
    s = q;
  } else {
    s = sub(x, u);
    if (s === 0n) return undefined;
    const r = sqrt(mul(neg(s), add(mul(4n, uCubedPlus7(u)), mul(mul(3n, s), sqr(u)))));
    if (r === undefined) return undefined;
    // Branch 1 of a pair whose two roots coincide would not be uniformly
    // sampled, so it is dropped rather than double-counted.
    if (c & 1 && r === 0n) return undefined;
    const rs = div(r, s);
    if (rs === undefined) return undefined;
    v = div(add(neg(u), rs), 2n)!;
  }

  const w = sqrt(s);
  if (w === undefined) return undefined;

  const half = inv(2n);
  const minus = mul(mul(u, sub(1n, MINUS_3_SQRT)), half);
  const plus = mul(mul(u, add(1n, MINUS_3_SQRT)), half);
  switch (c & 5) {
    case 0:
      return mul(neg(w), add(minus, v));
    case 1:
      return mul(w, add(plus, v));
    case 4:
      return mul(w, add(minus, v));
    default: // 5
      return mul(neg(w), add(plus, v));
  }
}

/** 64-byte ElligatorSwift encoding → 32-byte X coordinate. */
export function ellswiftDecode(ellswift: Uint8Array): Uint8Array {
  if (ellswift.length !== ELLSWIFT_SIZE) throw new Error('ellswift must be 64 bytes');
  const u = fromBytes(ellswift.subarray(0, 32));
  const t = fromBytes(ellswift.subarray(32));
  return toBytes(xswiftec(u, t));
}

/**
 * Encode an X coordinate as 64 ElligatorSwift bytes, by rejection sampling over
 * random `u` and branch. Expected a handful of iterations.
 */
export function xelligatorSwift(x: bigint, randomBytes32: () => Uint8Array): Uint8Array {
  for (;;) {
    const u = fromBytes(randomBytes32());
    if (u === 0n) continue;
    // One random branch per attempt, so every valid encoding is equally likely
    // — trying branches in order would bias the output and undo the
    // indistinguishability the encoding exists for.
    const c = randomBytes32()[0]! & 7;
    const t = xswiftecInv(x, u, c);
    if (t === undefined) continue;
    const out = new Uint8Array(ELLSWIFT_SIZE);
    out.set(toBytes(u), 0);
    out.set(toBytes(t), 32);
    return out;
  }
}

export interface EllswiftKeyPair {
  /** 32-byte secp256k1 secret. */
  priv: Uint8Array;
  /** 64-byte ElligatorSwift encoding of the public key. */
  ellswift: Uint8Array;
}

/** Fresh ephemeral keypair for a handshake. */
export function ellswiftCreate(randomBytes32: () => Uint8Array): EllswiftKeyPair {
  for (;;) {
    const priv = randomBytes32();
    let pubX: bigint;
    try {
      pubX = secp256k1.Point.BASE.multiply(bytesToScalar(priv)).toAffine().x;
    } catch {
      continue; // zero or out-of-range scalar
    }
    return { priv, ellswift: xelligatorSwift(pubX, randomBytes32) };
  }
}

/**
 * X coordinate of `priv * decode(theirEllswift)`. The scalar multiplication
 * runs in the curve library, so the secret never meets the plain-bigint
 * arithmetic in `./field.js`.
 */
export function ellswiftEcdhXonly(theirEllswift: Uint8Array, priv: Uint8Array): Uint8Array {
  const xBytes = ellswiftDecode(theirEllswift);
  const point = secp256k1.Point.fromHex(concatHex('02', xBytes));
  return toBytes(point.multiply(bytesToScalar(priv)).toAffine().x);
}

function bytesToScalar(b: Uint8Array): bigint {
  if (b.length !== 32) throw new Error('private key must be 32 bytes');
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  if (n === 0n || n >= secp256k1.Point.Fn.ORDER) throw new Error('private key out of range');
  return n;
}

function concatHex(prefix: string, b: Uint8Array): string {
  let s = prefix;
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export { P };
