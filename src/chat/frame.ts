/**
 * Chat frames: the schema the SDK owns so two applications built on this bus
 * can actually talk to each other.
 *
 * `usermsg` carries an opaque payload with a `msg_id` and a delivery ack. That
 * is a messaging primitive, not a chat protocol — "what is a reply" has to be
 * defined somewhere, and defining it per application means no two of them
 * interoperate.
 *
 * Bitcoin-serialised, matching every other frame in the repo: one serialiser
 * to audit, and compact against a 3584-byte ceiling.
 *
 *   u8           version = 1
 *   u8           type
 *   u8[32]       conv_id
 *   i64          timestamp     sender clock, a DISPLAY HINT only
 *   u64          lamport
 *   CompactSize  np, np x u8[32] parents
 *   CompactSize  bl, u8[bl] body
 */
import { sha256 } from '@noble/hashes/sha256';
import { concat, utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';

export const CHAT_FRAME_VERSION = 1;

/** Parents are capped so a frame stays small; `lamport` preserves the order. */
export const MAX_PARENTS = 4;

export const ChatFrameType = {
  TEXT: 1,
  EDIT: 2,
  DELETE: 3,
  REACTION: 4,
  RECEIPT: 5,
  PROFILE: 6,
  MEMBERSHIP: 7,
  CONTACT: 8,
  PAYMENT: 9,
  CALL: 10,
  STREAM: 11,
  /** Typing and presence. Direct channel only; never persisted, never on the bus. */
  EPHEMERAL: 12,
} as const;

export type ChatFrameTypeValue = (typeof ChatFrameType)[keyof typeof ChatFrameType];

export interface ChatFrame {
  version: number;
  type: number;
  convId: Uint8Array; // 32
  /** Unix seconds, from the sender's clock. Never trusted for ordering. */
  timestamp: bigint;
  lamport: bigint;
  /** Content hashes of the messages the sender had seen. */
  parents: Uint8Array[];
  body: Uint8Array;
}

const MSG_ID_TAG = utf8('navio-p2pmsg/chat/v1');

/**
 * Message id: SHA256 over the tag and the whole serialised frame.
 *
 * Content-addressed on purpose. Edits, reactions and deletes target something
 * immutable; the same message arriving live, from the archive and from a
 * device mirror collapses to one entry; and dedupe costs nothing.
 */
export function chatMessageId(frame: ChatFrame): Uint8Array {
  return sha256(concat(MSG_ID_TAG, serializeChatFrame(frame)));
}

export function serializeChatFrame(f: ChatFrame): Uint8Array {
  if (f.convId.length !== 32) throw new Error('convId must be 32 bytes');
  if (f.parents.length > MAX_PARENTS) throw new Error(`at most ${MAX_PARENTS} parents`);
  const w = new Writer().u8(f.version).u8(f.type).bytes(f.convId).i64(f.timestamp).u64(f.lamport);
  w.compactSize(f.parents.length);
  for (const p of f.parents) {
    if (p.length !== 32) throw new Error('parent id must be 32 bytes');
    w.bytes(p);
  }
  return w.varBytes(f.body).finish();
}

export function parseChatFrame(bytes: Uint8Array): ChatFrame {
  const r = new Reader(bytes);
  const version = r.u8();
  const type = r.u8();
  const convId = r.bytes(32).slice();
  const timestamp = r.i64();
  const lamport = r.u64();
  const np = r.compactSize();
  if (np > MAX_PARENTS) throw new Error(`at most ${MAX_PARENTS} parents`);
  const parents: Uint8Array[] = [];
  for (let i = 0; i < np; i++) parents.push(r.bytes(32).slice());
  const body = r.varBytes().slice();
  r.assertDone();
  return { version, type, convId, timestamp, lamport, parents, body };
}

// ---------------------------------------------------------------------------
// Conversation ids

const CONV_1TO1_TAG = utf8('navio-p2pmsg/conv/1to1/v1');
const CONV_SELF_TAG = utf8('navio-p2pmsg/conv/self/v1');

/**
 * Deterministic id for a 1:1 conversation. Both sides derive it independently
 * from the two identity keys, byte-ordered, so there is nothing to negotiate.
 */
export function directConversationId(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== 48 || b.length !== 48) throw new Error('identity keys must be 48 bytes');
  const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  return sha256(concat(CONV_1TO1_TAG, lo, hi));
}

/** Notes to self, and the channel our own devices mirror sent messages on. */
export function selfConversationId(identity: Uint8Array): Uint8Array {
  if (identity.length !== 48) throw new Error('identity key must be 48 bytes');
  return sha256(concat(CONV_SELF_TAG, identity));
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  }
  return a.length - b.length;
}

// ---------------------------------------------------------------------------
// Bodies

export interface AttachRef {
  contentHash: Uint8Array; // 32
  size: bigint;
  mime: string;
  /** Per-file symmetric key, so the ciphertext is safe to relay or store anywhere. */
  key: Uint8Array; // 32
  /** Inline preview, <= 1 KB, so something renders before the transfer starts. */
  thumbnail: Uint8Array;
}

export const MAX_THUMBNAIL_BYTES = 1024;

function writeAttachRef(w: Writer, a: AttachRef): void {
  if (a.contentHash.length !== 32) throw new Error('attachment hash must be 32 bytes');
  if (a.key.length !== 32) throw new Error('attachment key must be 32 bytes');
  if (a.thumbnail.length > MAX_THUMBNAIL_BYTES) throw new Error('thumbnail too large');
  w.bytes(a.contentHash).u64(a.size).varString(a.mime).bytes(a.key).varBytes(a.thumbnail);
}

function readAttachRef(r: Reader): AttachRef {
  return {
    contentHash: r.bytes(32).slice(),
    size: r.u64(),
    mime: r.varString(),
    key: r.bytes(32).slice(),
    thumbnail: r.varBytes().slice(),
  };
}

export interface TextBody {
  text: string;
  /** Identity keys mentioned, 48 bytes each. */
  mentions: Uint8Array[];
  attachments: AttachRef[];
  /** Message this one replies to. */
  replyTo?: Uint8Array; // 32
}

export function serializeTextBody(b: TextBody): Uint8Array {
  const w = new Writer().varString(b.text);
  w.compactSize(b.mentions.length);
  for (const m of b.mentions) {
    if (m.length !== 48) throw new Error('mention must be a 48-byte identity');
    w.bytes(m);
  }
  w.compactSize(b.attachments.length);
  for (const a of b.attachments) writeAttachRef(w, a);
  if (b.replyTo) {
    if (b.replyTo.length !== 32) throw new Error('replyTo must be 32 bytes');
    w.u8(1).bytes(b.replyTo);
  } else {
    w.u8(0);
  }
  return w.finish();
}

export function parseTextBody(bytes: Uint8Array): TextBody {
  const r = new Reader(bytes);
  const text = r.varString();
  const nm = r.compactSize();
  const mentions: Uint8Array[] = [];
  for (let i = 0; i < nm; i++) mentions.push(r.bytes(48).slice());
  const na = r.compactSize();
  const attachments: AttachRef[] = [];
  for (let i = 0; i < na; i++) attachments.push(readAttachRef(r));
  const body: TextBody = { text, mentions, attachments };
  if (r.u8() === 1) body.replyTo = r.bytes(32).slice();
  r.assertDone();
  return body;
}

export interface EditBody {
  target: Uint8Array; // 32
  text: string;
}

export function serializeEditBody(b: EditBody): Uint8Array {
  if (b.target.length !== 32) throw new Error('target must be 32 bytes');
  return new Writer().bytes(b.target).varString(b.text).finish();
}

export function parseEditBody(bytes: Uint8Array): EditBody {
  const r = new Reader(bytes);
  const out = { target: r.bytes(32).slice(), text: r.varString() };
  r.assertDone();
  return out;
}

export interface DeleteBody {
  target: Uint8Array; // 32
}

export function serializeDeleteBody(b: DeleteBody): Uint8Array {
  if (b.target.length !== 32) throw new Error('target must be 32 bytes');
  return new Writer().bytes(b.target).finish();
}

export function parseDeleteBody(bytes: Uint8Array): DeleteBody {
  const r = new Reader(bytes);
  const out = { target: r.bytes(32).slice() };
  r.assertDone();
  return out;
}

export interface ReactionBody {
  target: Uint8Array; // 32
  emoji: string;
  /** False removes a previously sent reaction. */
  add: boolean;
}

export function serializeReactionBody(b: ReactionBody): Uint8Array {
  if (b.target.length !== 32) throw new Error('target must be 32 bytes');
  return new Writer().bytes(b.target).varString(b.emoji).u8(b.add ? 1 : 0).finish();
}

export function parseReactionBody(bytes: Uint8Array): ReactionBody {
  const r = new Reader(bytes);
  const out = { target: r.bytes(32).slice(), emoji: r.varString(), add: r.u8() === 1 };
  r.assertDone();
  return out;
}

export interface ReceiptBody {
  /** Messages read up to, one per branch head. */
  heads: Uint8Array[];
}

export function serializeReceiptBody(b: ReceiptBody): Uint8Array {
  const w = new Writer().compactSize(b.heads.length);
  for (const h of b.heads) {
    if (h.length !== 32) throw new Error('head must be 32 bytes');
    w.bytes(h);
  }
  return w.finish();
}

export function parseReceiptBody(bytes: Uint8Array): ReceiptBody {
  const r = new Reader(bytes);
  const n = r.compactSize();
  const heads: Uint8Array[] = [];
  for (let i = 0; i < n; i++) heads.push(r.bytes(32).slice());
  r.assertDone();
  return { heads };
}

export interface ProfileBody {
  displayName: string;
  statusText: string;
  avatar?: AttachRef;
}

export function serializeProfileBody(b: ProfileBody): Uint8Array {
  const w = new Writer().varString(b.displayName).varString(b.statusText);
  if (b.avatar) {
    w.u8(1);
    writeAttachRef(w, b.avatar);
  } else {
    w.u8(0);
  }
  return w.finish();
}

export function parseProfileBody(bytes: Uint8Array): ProfileBody {
  const r = new Reader(bytes);
  const out: ProfileBody = { displayName: r.varString(), statusText: r.varString() };
  if (r.u8() === 1) out.avatar = readAttachRef(r);
  r.assertDone();
  return out;
}

/**
 * Payments in a conversation.
 *
 * Message types only: this package deliberately has no wallet and no chain
 * dependency — that is the reason it exists, and `navio-sdk` is an optional
 * peer dependency an application wires up itself. What travels here is the
 * request or the receipt, never a key or a signature over a transaction.
 */
export const PaymentOp = { REQUEST: 1, SENT: 2 } as const;

export interface PaymentBody {
  op: number;
  /** Smallest unit, as the chain counts it. */
  amount: bigint;
  /** Empty for the chain's native asset. */
  tokenId: string;
  memo: string;
  /**
   * For SENT: the output hash the payment produced. Note navio-core's
   * `sendtoblsctaddress` returns an output hash rather than a txid, so this is
   * what a recipient can actually look up.
   */
  reference: Uint8Array;
}

export function serializePaymentBody(b: PaymentBody): Uint8Array {
  if (b.amount < 0n) throw new Error('amount must not be negative');
  return new Writer().u8(b.op).u64(b.amount).varString(b.tokenId).varString(b.memo).varBytes(b.reference).finish();
}

export function parsePaymentBody(bytes: Uint8Array): PaymentBody {
  const r = new Reader(bytes);
  const out = {
    op: r.u8(),
    amount: r.u64(),
    tokenId: r.varString(),
    memo: r.varString(),
    reference: r.varBytes().slice(),
  };
  r.assertDone();
  return out;
}

export const ContactOp = { REQUEST: 1, ACCEPT: 2, DECLINE: 3 } as const;

export interface ContactBody {
  op: number;
  /** Short introduction shown with a request; empty for accept/decline. */
  intro: string;
}

export function serializeContactBody(b: ContactBody): Uint8Array {
  return new Writer().u8(b.op).varString(b.intro).finish();
}

export function parseContactBody(bytes: Uint8Array): ContactBody {
  const r = new Reader(bytes);
  const out = { op: r.u8(), intro: r.varString() };
  r.assertDone();
  return out;
}
