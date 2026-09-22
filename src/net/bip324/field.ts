/**
 * Minimal secp256k1 base-field arithmetic for ElligatorSwift.
 *
 * Deliberately hand-rolled rather than borrowed from the curve library: the
 * ElligatorSwift maps depend on WHICH square root is returned, and the BIP324
 * reference fixes that as `a^((p+1)/4)` with no normalisation to an even or
 * canonical root. A library `sqrt` that normalises would silently produce the
 * negated `t` for every encoding — still a valid encoding, but it would fail
 * the BIP's `xswiftec_inv` vectors and make our output non-reproducible.
 *
 * These are ordinary bigint operations, not constant-time. That is acceptable
 * here and nowhere else: the inputs to the map are our own ephemeral handshake
 * key and the peer's public encoding, both of which are public by the time
 * they matter, and the secret scalar never touches this module — ECDH runs in
 * the audited curve implementation.
 */

/** secp256k1 base field modulus, 2^256 - 2^32 - 977. */
export const P = 2n ** 256n - 2n ** 32n - 977n;

export function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

export function add(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

export function neg(a: bigint): bigint {
  return mod(-a);
}

export function sqr(a: bigint): bigint {
  return mod(a * a);
}

export function pow(a: bigint, e: bigint): bigint {
  let result = 1n;
  let base = mod(a);
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base);
    base = mod(base * base);
    exp >>= 1n;
  }
  return result;
}

/** Multiplicative inverse. Throws on zero — callers that can hit it must check. */
export function inv(a: bigint): bigint {
  const x = mod(a);
  if (x === 0n) throw new Error('field inverse of zero');
  return pow(x, P - 2n);
}

/** `a / b`, or undefined when `b` is zero. */
export function div(a: bigint, b: bigint): bigint | undefined {
  if (mod(b) === 0n) return undefined;
  return mul(a, inv(b));
}

const SQRT_EXPONENT = (P + 1n) / 4n;

/**
 * The square root the BIP324 reference uses: `a^((p+1)/4)`, valid because
 * p % 4 == 3, and `undefined` when `a` is not a quadratic residue. Not
 * normalised — the caller gets exactly the root the reference would.
 */
export function sqrt(a: bigint): bigint | undefined {
  const x = mod(a);
  const s = pow(x, SQRT_EXPONENT);
  return sqr(s) === x ? s : undefined;
}

/** True iff `a` is a square (including zero). */
export function isSquare(a: bigint): boolean {
  return sqrt(a) !== undefined;
}

/** True iff `x` is the X coordinate of a point on y² = x³ + 7. */
export function isValidX(x: bigint): boolean {
  return isSquare(add(mul(sqr(x), x), 7n));
}

export function fromBytes(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  // BIP324 reduces the 32-byte encodings mod p rather than rejecting them, so
  // an ElligatorSwift input above p is valid and maps like its reduction.
  return mod(n);
}

export function toBytes(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = mod(n);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
