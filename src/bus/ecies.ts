/**
 * 1-layer ECIES over BLS G1 ECDH + ChaCha20-Poly1305, byte-compatible with
 * navio-core `src/p2pmsg/crypto.cpp`.
 *
 *   eph_sk  = random non-zero Fr; eph = G1 * eph_sk
 *   shared  = compress(recipient_pub * eph_sk)               (48 bytes)
 *   key     = HKDF-SHA256(ikm=shared, salt="navio-p2pmsg-ecies-v1", info="aead-key", 32)
 *   AEAD    = ChaCha20-Poly1305, nonce = 12 zero bytes, AAD = caller-supplied (the envelope kind byte)
 *   framing = u32le len || payload || zero pad, padded to {64,256,1024,3072,3584} when 4+len <= 3584
 *
 * Wire: eph(48) || CompactSize(ct.len) || ct || tag(16). MsgHash = SHA256(wire bytes).
 */
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { ecdh, generateSecret, isDecodableG1, isInfinityG1, publicKey, PUBLIC_KEY_SIZE } from './bls.js';

export const ECIES_EPH_SIZE = PUBLIC_KEY_SIZE;
export const ECIES_TAG_SIZE = 16;
export const PAD_PREFIX = 4;
export const PAD_BUCKETS: readonly number[] = [64, 256, 1024, 3072, 3584];
/** Largest payload that still gets bucket padding (4 + len <= 3584). */
export const MAX_PADDED_PAYLOAD = PAD_BUCKETS[PAD_BUCKETS.length - 1]! - PAD_PREFIX;

const HKDF_SALT = utf8('navio-p2pmsg-ecies-v1');
const HKDF_INFO = utf8('aead-key');
const ZERO_NONCE = new Uint8Array(12);

export interface EciesPacket {
  /** Sender's per-message ephemeral G1 pubkey, compressed. */
  eph: Uint8Array;
  ciphertext: Uint8Array;
  /** Poly1305 tag. */
  tag: Uint8Array;
}

function deriveKey(shared: Uint8Array): Uint8Array {
  return hkdf(sha256, shared, HKDF_SALT, HKDF_INFO, 32);
}

/** Size the framed plaintext (4 + len) is padded to. */
export function paddedSize(framed: number): number {
  for (const b of PAD_BUCKETS) if (framed <= b) return b;
  return framed;
}

export function pad(plaintext: Uint8Array): Uint8Array {
  const framed = PAD_PREFIX + plaintext.length;
  const out = new Uint8Array(paddedSize(framed));
  const len = plaintext.length >>> 0;
  out[0] = len & 0xff;
  out[1] = (len >>> 8) & 0xff;
  out[2] = (len >>> 16) & 0xff;
  out[3] = (len >>> 24) & 0xff;
  out.set(plaintext, PAD_PREFIX);
  return out;
}

export function unpad(padded: Uint8Array): Uint8Array | null {
  if (padded.length < PAD_PREFIX) return null;
  const len = (padded[0]! | (padded[1]! << 8) | (padded[2]! << 16) | (padded[3]! << 24)) >>> 0;
  if (len > padded.length - PAD_PREFIX) return null;
  return padded.slice(PAD_PREFIX, PAD_PREFIX + len);
}

/** Encrypt `plaintext` to `recipientPub` under fresh ephemeral key. `aad` is authenticated only. */
export function encrypt(recipientPub: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): EciesPacket {
  const ephSk = generateSecret();
  const eph = publicKey(ephSk);
  const key = deriveKey(ecdh(ephSk, recipientPub));
  const ctTag = chacha20poly1305(key, ZERO_NONCE, aad).encrypt(pad(plaintext));
  const split = ctTag.length - ECIES_TAG_SIZE;
  return { eph, ciphertext: ctTag.slice(0, split), tag: ctTag.slice(split) };
}

/**
 * Decrypt with secret `sk`. Returns the unpadded plaintext, or null on a bad
 * ephemeral key (infinity / off-curve / off-subgroup), AEAD failure or bad padding.
 */
export function decrypt(sk: Uint8Array, packet: EciesPacket, aad: Uint8Array = new Uint8Array(0)): Uint8Array | null {
  if (packet.eph.length !== ECIES_EPH_SIZE || packet.tag.length !== ECIES_TAG_SIZE) return null;
  if (!isDecodableG1(packet.eph) || isInfinityG1(packet.eph)) return null;
  let key: Uint8Array;
  try {
    key = deriveKey(ecdh(sk, packet.eph));
  } catch {
    return null;
  }
  const ctTag = new Uint8Array(packet.ciphertext.length + ECIES_TAG_SIZE);
  ctTag.set(packet.ciphertext, 0);
  ctTag.set(packet.tag, packet.ciphertext.length);
  let padded: Uint8Array;
  try {
    padded = chacha20poly1305(key, ZERO_NONCE, aad).decrypt(ctTag);
  } catch {
    return null;
  }
  return unpad(padded);
}

export function writePacket(w: Writer, p: EciesPacket): Writer {
  if (p.eph.length !== ECIES_EPH_SIZE) throw new Error('bad eph size');
  if (p.tag.length !== ECIES_TAG_SIZE) throw new Error('bad tag size');
  return w.bytes(p.eph).varBytes(p.ciphertext).bytes(p.tag);
}

export function serializePacket(p: EciesPacket): Uint8Array {
  return writePacket(new Writer(), p).finish();
}

/**
 * Parse a packet. Like navio-core's deserialiser, the ephemeral key must be a
 * canonical on-curve, in-subgroup encoding (throws otherwise); the point at
 * infinity parses and is rejected later by `decrypt`.
 */
export function parsePacket(r: Reader): EciesPacket {
  const eph = r.bytes(ECIES_EPH_SIZE).slice();
  if (!isDecodableG1(eph)) throw new Error('invalid ephemeral key encoding');
  const ciphertext = r.varBytes().slice();
  const tag = r.bytes(ECIES_TAG_SIZE).slice();
  return { eph, ciphertext, tag };
}

/** SHA256 over the serialised packet. Replay/PoW binding identifier. */
export function packetMsgHash(p: EciesPacket): Uint8Array {
  return sha256(serializePacket(p));
}

/** Wire size of a packet carrying `payloadLen` bytes of plaintext. */
export function packetWireSize(payloadLen: number): number {
  const ct = paddedSize(PAD_PREFIX + payloadLen);
  const cs = ct < 253 ? 1 : ct <= 0xffff ? 3 : 5;
  return ECIES_EPH_SIZE + cs + ct + ECIES_TAG_SIZE;
}
