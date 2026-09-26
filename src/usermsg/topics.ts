/** Library-reserved topics and the ack payload codec. */
import { Reader, Writer } from '../common/serialize.js';
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
/**
 * An unsolicited bundle: "my keys moved, here they are".
 *
 * Revoking a device rotates the account epoch, but a contact keeps addressing
 * the key it cached until it discovers the new one — and every one of those
 * messages is readable by the device that was just revoked, which holds the
 * old secret and cannot be made to forget it. Nothing local fixes that; the
 * only lever is the senders. So on revocation we can push the new bundle to
 * every contact instead of waiting for them to ask.
 */
export const TOPIC_BUNDLE = '_p2pmsg/bundle';
/** Default topic for 1:1 application messages when the app gives none. */
export const TOPIC_DEFAULT = 'msg';

/**
 * Asking a contact for their current bundle.
 *
 * A fixed topic, carried inside an envelope addressed to the target's IDENTITY
 * key. It used to be a broadcast on `_p2pmsg/prekey/<hash of the identity>`,
 * which leaked the one thing the envelope format works hardest to hide.
 * Broadcast envelopes are encrypted to a PUBLISHED key — that is what makes
 * them public — so anybody could read the topic, and the identity is a public
 * address, so anybody holding an address could precompute its hash and watch
 * the bus for it. That is a live social-graph oracle: "somebody is about to
 * contact this account", timestamped, for every address the observer knows,
 * with the response arriving moments later to say the account is online.
 *
 * Addressing the identity key instead costs nothing and reveals nothing: the
 * topic is inside the ciphertext, and only the account that owns the identity
 * can open it. On the wire a discovery request is now just another envelope to
 * somebody.
 */
export const TOPIC_PREKEY_REQUEST = '_p2pmsg/prekeyreq';

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
