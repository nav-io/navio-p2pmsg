/**
 * Device pairing: no server, no account, no QR service.
 *
 * The primary shows a QR; the new device scans it; they meet on the bus.
 *
 *   1. Primary mints a single-use pairing keypair and displays `navpair1…`.
 *   2. New device generates its own device key and answers on a topic derived
 *      from a HASH of the pairing key, so the topic identifies nothing and
 *      expires with the pairing.
 *   3. BOTH show a short authentication string. The user compares them.
 *   4. On confirmation the primary sends the account secret, the device
 *      certificate and the device list.
 *
 * Step 3 is the only thing authenticating the channel. Without it, anyone who
 * photographed the QR could complete the pairing — the ECDH alone proves
 * nothing about WHO is on the other end.
 */
import { bech32m } from '@scure/base';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concat, toHex, utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { ecdh } from '../bus/bls.js';
import type { NetworkName } from '../net/messages.js';

export const PAIR_HRP = 'navpair';
export const PAIRING_VERSION = 1;
/** Offers are single-use and short-lived: the QR is a bearer secret. */
export const PAIRING_TTL_MS = 5 * 60 * 1000;
export const SAS_DIGITS = 6;

const NETWORKS: NetworkName[] = ['mainnet', 'testnet', 'regtest'];

export interface PairingOffer {
  version: number;
  network: NetworkName;
  /** Single-use ephemeral public key. */
  pairPub: Uint8Array; // 48
  salt: Uint8Array; // 16
}

export function serializePairingOffer(o: PairingOffer): Uint8Array {
  const idx = NETWORKS.indexOf(o.network);
  if (idx < 0) throw new Error(`unknown network ${o.network}`);
  if (o.pairPub.length !== 48) throw new Error('pairPub must be 48 bytes');
  if (o.salt.length !== 16) throw new Error('salt must be 16 bytes');
  return new Writer().u8(o.version).u8(idx).bytes(o.pairPub).bytes(o.salt).finish();
}

export function parsePairingOffer(bytes: Uint8Array): PairingOffer {
  const r = new Reader(bytes);
  const version = r.u8();
  if (version !== PAIRING_VERSION) throw new Error(`unsupported pairing version ${version}`);
  const idx = r.u8();
  const network = NETWORKS[idx];
  if (!network) throw new Error(`unknown network index ${idx}`);
  const out = { version, network, pairPub: r.bytes(48).slice(), salt: r.bytes(16).slice() };
  r.assertDone();
  return out;
}

/** `navpair1…`, the string behind the QR. */
export function encodePairingOffer(o: PairingOffer): string {
  return bech32m.encode(PAIR_HRP, bech32m.toWords(serializePairingOffer(o)), false);
}

export function decodePairingOffer(s: string): PairingOffer {
  const { prefix, words } = bech32m.decode(s.trim().toLowerCase() as `${string}1${string}`, false);
  if (prefix !== PAIR_HRP) throw new Error(`expected ${PAIR_HRP}1…, got ${prefix}`);
  return parsePairingOffer(new Uint8Array(bech32m.fromWords(words)));
}

/**
 * Topic the new device answers on. A hash of the single-use pairing key, so it
 * identifies no account and stops existing when the offer expires.
 */
export function pairingTopic(pairPub: Uint8Array): string {
  return `_p2pmsg/pair/${toHex(sha256(pairPub))}`;
}

/**
 * The digits both screens show. Derived from the ECDH secret both sides
 * compute plus the offer's salt, so a man in the middle who substituted a key
 * produces a different string and the user sees it.
 */
export function shortAuthString(sharedSecret: Uint8Array, salt: Uint8Array): string {
  const out = hkdf(sha256, sharedSecret, salt, utf8('sas'), 4);
  const n = new DataView(out.buffer, out.byteOffset, 4).getUint32(0, false) % 10 ** SAS_DIGITS;
  return n.toString().padStart(SAS_DIGITS, '0');
}

/** Primary side: `pairSk` against the device's public key. */
export function sasForPrimary(pairSk: Uint8Array, devicePub: Uint8Array, salt: Uint8Array): string {
  return shortAuthString(ecdh(pairSk, devicePub), salt);
}

/** New-device side: its own key against the pairing key from the QR. */
export function sasForDevice(deviceSk: Uint8Array, pairPub: Uint8Array, salt: Uint8Array): string {
  return shortAuthString(ecdh(deviceSk, pairPub), salt);
}

export const PairingMessage = { ANNOUNCE: 1, GRANT: 2 } as const;

/** What the new device publishes on the pairing topic. */
export interface PairingAnnounce {
  devicePub: Uint8Array; // 48
  label: string;
}

export function serializeAnnounce(a: PairingAnnounce): Uint8Array {
  if (a.devicePub.length !== 48) throw new Error('devicePub must be 48 bytes');
  return new Writer().u8(PairingMessage.ANNOUNCE).bytes(a.devicePub).varString(a.label).finish();
}

export function parseAnnounce(bytes: Uint8Array): PairingAnnounce {
  const r = new Reader(bytes);
  if (r.u8() !== PairingMessage.ANNOUNCE) throw new Error('not a pairing announce');
  const out = { devicePub: r.bytes(48).slice(), label: r.varString() };
  r.assertDone();
  return out;
}

/**
 * What the primary sends back once the user confirms the SAS. Everything the
 * new device needs to be a full participant — but never the root seed, so it
 * can neither rotate the account epoch nor survive revocation.
 */
export interface PairingGrant {
  accountEpoch: number;
  accountSecret: Uint8Array; // 32
  identityPub: Uint8Array; // 48
  /** The certificate admitting this device, signed by the identity key. */
  cert: Uint8Array; // 96
  caps: number;
  /** Serialised, signed device list including the new device. */
  deviceList: Uint8Array;
}

export function serializeGrant(g: PairingGrant): Uint8Array {
  if (g.accountSecret.length !== 32) throw new Error('accountSecret must be 32 bytes');
  if (g.identityPub.length !== 48) throw new Error('identityPub must be 48 bytes');
  if (g.cert.length !== 96) throw new Error('cert must be 96 bytes');
  return new Writer()
    .u8(PairingMessage.GRANT)
    .u32(g.accountEpoch)
    .bytes(g.accountSecret)
    .bytes(g.identityPub)
    .bytes(g.cert)
    .u8(g.caps)
    .varBytes(g.deviceList)
    .finish();
}

export function parseGrant(bytes: Uint8Array): PairingGrant {
  const r = new Reader(bytes);
  if (r.u8() !== PairingMessage.GRANT) throw new Error('not a pairing grant');
  const out = {
    accountEpoch: r.u32(),
    accountSecret: r.bytes(32).slice(),
    identityPub: r.bytes(48).slice(),
    cert: r.bytes(96).slice(),
    caps: r.u8(),
    deviceList: r.varBytes().slice(),
  };
  r.assertDone();
  return out;
}

export { concat };
