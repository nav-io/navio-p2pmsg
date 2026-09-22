/**
 * USER_DATA (kind 7) wire frame, parsed by the node: topic + opaque body.
 * Plus the library's authenticated inner frame that lives inside `body`.
 * See DESIGN.md "USER_DATA frame" and "usermsg".
 */
import { Reader, Writer } from '../common/serialize.js';
import { concat, utf8 } from '../common/bytes.js';
import { sha256 } from '@noble/hashes/sha256';

export const USER_DATA_KIND = 7;
export const MAX_USER_MSG_BYTES = 3584;
export const MAX_TOPIC_BYTES = 64;
export const RESERVED_TOPIC_PREFIX = '_p2pmsg/';

export interface UserMsgFrame {
  topic: string;
  body: Uint8Array;
}

export function serializeUserMsgFrame(f: UserMsgFrame): Uint8Array {
  const t = utf8(f.topic);
  if (t.length < 1 || t.length > MAX_TOPIC_BYTES) throw new Error(`topic must be 1-${MAX_TOPIC_BYTES} bytes`);
  const out = new Writer().varBytes(t).varBytes(f.body).finish();
  if (out.length > MAX_USER_MSG_BYTES) throw new Error(`frame is ${out.length} bytes, max ${MAX_USER_MSG_BYTES}`);
  return out;
}

export function parseUserMsgFrame(bytes: Uint8Array): UserMsgFrame {
  const r = new Reader(bytes);
  const t = r.varBytes();
  if (t.length < 1 || t.length > MAX_TOPIC_BYTES) throw new Error('bad topic length');
  const body = r.varBytes();
  r.assertDone();
  return { topic: new TextDecoder().decode(t), body };
}

// ---------------------------------------------------------------------------
// Inner authenticated frame (AuthFrame), version 1.

export const AUTH_FRAME_VERSION = 1;
export const FLAG_SIGNED = 1 << 0;
export const FLAG_HAS_REPLY_KEY = 1 << 1;
export const FLAG_CHUNK = 1 << 2;
/**
 * The signature is by a DEVICE key rather than the account's identity key.
 *
 * Only the primary device holds the identity key, so a secondary cannot sign
 * as the account. Instead it signs with its own key and the frame carries that
 * key; the receiver checks it against the sender's published device list. A
 * device that was revoked is no longer on the list, so its signatures stop
 * being accepted — which is the whole point of revocation.
 */
export const FLAG_DEVICE_SIGNED = 1 << 3;

export const MSG_ID_BYTES = 16;
export const PUBKEY_BYTES = 48;
export const SIG_BYTES = 96;

export interface AuthFrame {
  msgId: Uint8Array; // 16
  timestamp: bigint; // unix seconds
  sender?: Uint8Array; // 48, present iff signed — the ACCOUNT identity
  /**
   * Device key that produced `sig`, present iff FLAG_DEVICE_SIGNED. When
   * absent the signature is by the identity key itself.
   */
  devicePub?: Uint8Array; // 48
  replyPub?: Uint8Array; // 48
  chunk?: { idx: number; total: number };
  payload: Uint8Array;
  sig?: Uint8Array; // 96, present iff signed
}

function flagsOf(f: AuthFrame): number {
  let flags = 0;
  if (f.sender) flags |= FLAG_SIGNED;
  if (f.replyPub) flags |= FLAG_HAS_REPLY_KEY;
  if (f.chunk) flags |= FLAG_CHUNK;
  if (f.devicePub) flags |= FLAG_DEVICE_SIGNED;
  return flags;
}

/** Everything up to and including payload — the bytes covered by the signature. */
export function serializeAuthFrameUnsigned(f: AuthFrame): Uint8Array {
  if (f.msgId.length !== MSG_ID_BYTES) throw new Error('msgId must be 16 bytes');
  const w = new Writer().u8(AUTH_FRAME_VERSION).u8(flagsOf(f)).bytes(f.msgId).i64(f.timestamp);
  if (f.sender) {
    if (f.sender.length !== PUBKEY_BYTES) throw new Error('sender must be 48 bytes');
    w.bytes(f.sender);
  }
  if (f.devicePub) {
    if (!f.sender) throw new Error('a device-signed frame must name its account identity');
    if (f.devicePub.length !== PUBKEY_BYTES) throw new Error('devicePub must be 48 bytes');
    w.bytes(f.devicePub);
  }
  if (f.replyPub) {
    if (f.replyPub.length !== PUBKEY_BYTES) throw new Error('replyPub must be 48 bytes');
    w.bytes(f.replyPub);
  }
  if (f.chunk) {
    if (f.chunk.total < 1 || f.chunk.idx >= f.chunk.total || f.chunk.total > 0xffff) throw new Error('bad chunk');
    w.u16(f.chunk.idx).u16(f.chunk.total);
  }
  w.varBytes(f.payload);
  return w.finish();
}

export function serializeAuthFrame(f: AuthFrame): Uint8Array {
  const head = serializeAuthFrameUnsigned(f);
  if (f.sender) {
    if (!f.sig || f.sig.length !== SIG_BYTES) throw new Error('signed frame needs a 96-byte sig');
    return concat(head, f.sig);
  }
  return head;
}

export function parseAuthFrame(bytes: Uint8Array): AuthFrame {
  const r = new Reader(bytes);
  const version = r.u8();
  if (version !== AUTH_FRAME_VERSION) throw new Error(`unsupported auth frame version ${version}`);
  const flags = r.u8();
  const msgId = r.bytes(MSG_ID_BYTES);
  const timestamp = r.i64();
  const f: AuthFrame = { msgId, timestamp, payload: new Uint8Array(0) };
  if (flags & FLAG_SIGNED) f.sender = r.bytes(PUBKEY_BYTES);
  if (flags & FLAG_DEVICE_SIGNED) {
    // Without an account identity there is no device list to check the key
    // against, so the frame would be unverifiable by construction.
    if (!(flags & FLAG_SIGNED)) throw new Error('device-signed frame without an identity');
    f.devicePub = r.bytes(PUBKEY_BYTES);
  }
  if (flags & FLAG_HAS_REPLY_KEY) f.replyPub = r.bytes(PUBKEY_BYTES);
  if (flags & FLAG_CHUNK) {
    const idx = r.u16();
    const total = r.u16();
    if (total < 1 || idx >= total) throw new Error('bad chunk');
    f.chunk = { idx, total };
  }
  f.payload = r.varBytes();
  if (flags & FLAG_SIGNED) f.sig = r.bytes(SIG_BYTES);
  r.assertDone();
  return f;
}

const SIG_DOMAIN = utf8('navio-p2pmsg/usermsg/v1');
export const BROADCAST_RECIPIENT = new Uint8Array(PUBKEY_BYTES); // zeros

/**
 * Digest the identity key signs: binds topic and intended recipient so a
 * frame cannot be re-encrypted to someone else or replayed on another topic.
 */
export function authFrameDigest(topic: string, recipient: Uint8Array, unsignedFrame: Uint8Array): Uint8Array {
  if (recipient.length !== PUBKEY_BYTES) throw new Error('recipient must be 48 bytes');
  const t = utf8(topic);
  return sha256(concat(SIG_DOMAIN, new Writer().varBytes(t).finish(), recipient, unsignedFrame));
}

/** Overhead of a signed frame carrying a reply key and chunk header, payload excluded. */
export const AUTH_FRAME_MAX_OVERHEAD =
  1 + 1 + MSG_ID_BYTES + 8 + PUBKEY_BYTES + PUBKEY_BYTES + PUBKEY_BYTES + 4 + 3 + SIG_BYTES; // 273, incl. a device key
