/**
 * Identity / prekey bundle text encodings.
 *   identity: bech32m HRP "navid", 48-byte G1 pubkey
 *   bundle:   bech32m HRP "navmsg", identity(48) || prekey(48) || prekey_sig(96)
 * Hex is accepted as input everywhere.
 */
import { bech32m } from '@scure/base';
import { fromHex, toHex } from '../common/bytes.js';

export const IDENTITY_HRP = 'navid';
export const BUNDLE_HRP = 'navmsg';
export const BUNDLE_BYTES = 48 + 48 + 96;

export interface Bundle {
  identity: Uint8Array; // 48
  prekey: Uint8Array; // 48
  prekeySig: Uint8Array; // 96
}

function enc(hrp: string, data: Uint8Array): string {
  return bech32m.encode(hrp, bech32m.toWords(data), false);
}

function dec(expectHrp: string, s: string, len: number): Uint8Array {
  const { prefix, words } = bech32m.decode(s as `${string}1${string}`, false);
  if (prefix !== expectHrp) throw new Error(`expected ${expectHrp}1..., got ${prefix}`);
  const bytes = bech32m.fromWords(words);
  if (bytes.length !== len) throw new Error(`expected ${len} bytes, got ${bytes.length}`);
  return new Uint8Array(bytes);
}

export function encodeIdentity(pub: Uint8Array): string {
  if (pub.length !== 48) throw new Error('identity must be 48 bytes');
  return enc(IDENTITY_HRP, pub);
}

export function decodeIdentity(s: string): Uint8Array {
  const t = s.trim();
  if (/^[0-9a-fA-F]{96}$/.test(t)) return fromHex(t);
  return dec(IDENTITY_HRP, t.toLowerCase(), 48);
}

export function serializeBundle(b: Bundle): Uint8Array {
  if (b.identity.length !== 48 || b.prekey.length !== 48 || b.prekeySig.length !== 96) throw new Error('bad bundle');
  const out = new Uint8Array(BUNDLE_BYTES);
  out.set(b.identity, 0);
  out.set(b.prekey, 48);
  out.set(b.prekeySig, 96);
  return out;
}

export function parseBundle(bytes: Uint8Array): Bundle {
  if (bytes.length !== BUNDLE_BYTES) throw new Error(`bundle must be ${BUNDLE_BYTES} bytes`);
  return { identity: bytes.slice(0, 48), prekey: bytes.slice(48, 96), prekeySig: bytes.slice(96, 192) };
}

export function encodeBundle(b: Bundle): string {
  return enc(BUNDLE_HRP, serializeBundle(b));
}

export function decodeBundle(s: string): Bundle {
  const t = s.trim();
  if (/^[0-9a-fA-F]{384}$/.test(t)) return parseBundle(fromHex(t));
  return parseBundle(dec(BUNDLE_HRP, t.toLowerCase(), BUNDLE_BYTES));
}

/** Accepts navid1…, navmsg1…, or hex of either; returns what it found. */
export function decodeContact(s: string): { identity: Uint8Array; bundle?: Bundle } {
  const t = s.trim();
  const lower = t.toLowerCase();
  if (lower.startsWith(BUNDLE_HRP + '1') || /^[0-9a-fA-F]{384}$/.test(t)) {
    const bundle = decodeBundle(t);
    return { identity: bundle.identity, bundle };
  }
  return { identity: decodeIdentity(t) };
}

export function identityHex(pub: Uint8Array): string {
  return toHex(pub);
}
