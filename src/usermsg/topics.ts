/** Library-reserved topics and the ack payload codec. */
import { sha256 } from '@noble/hashes/sha256';
import { Reader, Writer } from '../common/serialize.js';
import { toHex } from '../common/bytes.js';
import { MSG_ID_BYTES, RESERVED_TOPIC_PREFIX } from './frame.js';

export const TOPIC_PREKEY_RESPONSE = '_p2pmsg/prekey';
export const TOPIC_ACK = '_p2pmsg/ack';
export const TOPIC_PAIR = '_p2pmsg/pair';
/** Account messages between a primary and its own devices (epoch rotations). */
export const TOPIC_DEVICE = '_p2pmsg/device';
/**
 * Our own devices mirroring what they sent.
 *
 * Outgoing messages are encrypted to the RECIPIENT, so our other devices
 * cannot read them — a copy addressed to ourselves is the only way they can
 * show a complete conversation. It costs a second envelope and a second proof
 * of work, which is why mirrors are batched and why a single-device account
 * never sends one.
 */
export const TOPIC_MIRROR = '_p2pmsg/mirror';
/** Default topic for 1:1 application messages when the app gives none. */
export const TOPIC_DEFAULT = 'msg';

/** Discovery request topic for an identity: `_p2pmsg/prekey/<hex(sha256(identity))>` (64 hex = 15+64 = 79 bytes < 64? no). */
export function prekeyRequestTopic(identity: Uint8Array): string {
  // Topic max is 64 bytes; prefix is 15 bytes, so use the first 24 bytes (48 hex) of the hash.
  return `${TOPIC_PREKEY_RESPONSE}/${toHex(sha256(identity).subarray(0, 24))}`;
}

export function isReservedTopic(topic: string): boolean {
  return topic.startsWith(RESERVED_TOPIC_PREFIX);
}

export const ACK_WHOLE = 0xffff;

export interface AckEntry {
  msgId: Uint8Array;
  chunkIdx: number; // ACK_WHOLE for whole message
}

export function serializeAcks(entries: AckEntry[]): Uint8Array {
  const w = new Writer().compactSize(entries.length);
  for (const e of entries) {
    if (e.msgId.length !== MSG_ID_BYTES) throw new Error('bad msgId');
    w.bytes(e.msgId).u16(e.chunkIdx);
  }
  return w.finish();
}

export function parseAcks(bytes: Uint8Array): AckEntry[] {
  const r = new Reader(bytes);
  const n = r.compactSize();
  if (n > 1000) throw new Error('too many acks');
  const out: AckEntry[] = [];
  for (let i = 0; i < n; i++) out.push({ msgId: r.bytes(MSG_ID_BYTES), chunkIdx: r.u16() });
  r.assertDone();
  return out;
}
