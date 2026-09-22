/**
 * Identity / prekey bundle text encodings.
 *   identity: bech32m HRP "navid", 48-byte G1 pubkey
 *   bundle:   bech32m HRP "navmsg", identity(48) || prekey(48) || prekey_sig(96)
 * Hex is accepted as input everywhere.
 */
import { bech32m } from '@scure/base';
import { fromHex, toHex } from '../common/bytes.js';
import { FMD_CLUE_KEY_SIZE } from '../bus/fmd.js';
import { Reader, Writer } from '../common/serialize.js';

export const IDENTITY_HRP = 'navid';
export const BUNDLE_HRP = 'navmsg';
export const BUNDLE_BYTES = 48 + 48 + 96;

export interface Bundle {
  identity: Uint8Array; // 48
  prekey: Uint8Array; // 48
  prekeySig: Uint8Array; // 96
}

/**
 * Wire form of a bundle, version 2: everything in `Bundle` plus the FMD clue
 * key a sender needs in order to flag a message so the recipient can retrieve
 * it after being offline.
 *
 * It is deliberately NOT part of the `navmsg1…` text encoding: 1152 bytes of
 * clue key would make the address string unusable, and it is not needed to
 * address someone — only to make a message archivable. It travels in the
 * `_p2pmsg/prekey` discovery response instead, where it costs nothing to share.
 *
 *   u8       version = 2
 *   u8[48]   identity
 *   u8[48]   prekey
 *   u8[96]   prekey_sig
 *   u32      fmd_epoch
 *   u8[1152] fmd_clue_key
 *   u8[96]   fmd_sig        = Sign(identity_sk, u32le(epoch) || clue_key)
 *   CompactSize n, u8[n]     device_list (may be empty)
 *
 * The device list is self-authenticating — it carries its own signature under
 * the identity key — so it needs no separate signature here.
 */
export const EXTENDED_BUNDLE_VERSION = 3;
/** Version 2: everything below except the trailing device list. */
export const EXTENDED_BUNDLE_V2_BYTES = 1 + 48 + 48 + 96 + 4 + FMD_CLUE_KEY_SIZE + 96;

export interface ExtendedBundle extends Bundle {
  fmdEpoch: number;
  fmdClueKey: Uint8Array; // 1152
  fmdSig: Uint8Array; // 96
  /**
   * The account's signed device list, or empty when the account has never
   * paired a second device.
   *
   * Published here because a receiver needs it to verify a DEVICE-signed
   * frame, and it has to arrive before the first such message rather than
   * after. See `../devices/list.js`.
   */
  deviceList: Uint8Array;
}

/** The bytes the FMD signature covers. */
export function fmdSigMessage(epoch: number, clueKey: Uint8Array): Uint8Array {
  return new Writer().u32(epoch).bytes(clueKey).finish();
}

export function serializeExtendedBundle(b: ExtendedBundle): Uint8Array {
  if (b.identity.length !== 48 || b.prekey.length !== 48 || b.prekeySig.length !== 96) throw new Error('bad bundle');
  if (b.fmdClueKey.length !== FMD_CLUE_KEY_SIZE) throw new Error('bad clue key length');
  if (b.fmdSig.length !== 96) throw new Error('bad fmd signature length');
  return new Writer()
    .u8(EXTENDED_BUNDLE_VERSION)
    .bytes(b.identity)
    .bytes(b.prekey)
    .bytes(b.prekeySig)
    .u32(b.fmdEpoch)
    .bytes(b.fmdClueKey)
    .bytes(b.fmdSig)
    .varBytes(b.deviceList)
    .finish();
}

export function parseExtendedBundle(bytes: Uint8Array): ExtendedBundle {
  const r = new Reader(bytes);
  const version = r.u8();
  const out: ExtendedBundle = {
    identity: new Uint8Array(0),
    prekey: new Uint8Array(0),
    prekeySig: new Uint8Array(0),
    fmdEpoch: 0,
    fmdClueKey: new Uint8Array(0),
    fmdSig: new Uint8Array(0),
    deviceList: new Uint8Array(0),
  };
  if (version !== EXTENDED_BUNDLE_VERSION && version !== 2) {
    throw new Error(`unsupported bundle version ${version}`);
  }
  out.identity = r.bytes(48).slice();
  out.prekey = r.bytes(48).slice();
  out.prekeySig = r.bytes(96).slice();
  out.fmdEpoch = r.u32();
  out.fmdClueKey = r.bytes(FMD_CLUE_KEY_SIZE).slice();
  out.fmdSig = r.bytes(96).slice();
  // Version 2 predates device lists; an older peer simply has none.
  if (version === EXTENDED_BUNDLE_VERSION) out.deviceList = r.varBytes().slice();
  r.assertDone();
  return out;
}

/**
 * Parse whichever bundle form arrived. v1 is exactly 192 bytes and carries no
 * version byte; v2 and v3 start with one. An older peer's response therefore
 * stays readable, and a newer one degrades to "no device list".
 */
export function parseAnyBundle(bytes: Uint8Array): Bundle | ExtendedBundle {
  if (bytes.length === BUNDLE_BYTES) return parseBundle(bytes);
  return parseExtendedBundle(bytes);
}

export function isExtendedBundle(b: Bundle | ExtendedBundle): b is ExtendedBundle {
  return 'fmdClueKey' in b;
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
