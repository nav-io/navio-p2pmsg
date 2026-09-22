/** Byte helpers shared by every layer. No Buffer, no Node APIs. */

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.startsWith('0x')) h = h.slice(2);
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** Web Crypto refuses more than this in one call, in every runtime. */
const MAX_RANDOM_CHUNK = 65536;

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  // Filled in chunks: `getRandomValues` throws above 64 KiB, which would
  // otherwise turn any large buffer into a confusing runtime error far from
  // the call that asked for it.
  for (let at = 0; at < n; at += MAX_RANDOM_CHUNK) {
    globalThis.crypto.getRandomValues(out.subarray(at, Math.min(n, at + MAX_RANDOM_CHUNK)));
  }
  return out;
}
