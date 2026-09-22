/**
 * Persistent chat state, on top of the SDK's `Store` interface.
 *
 * Keys are laid out so every index is a sorted prefix scan, which is all the
 * `Store` contract offers:
 *
 *   msg/<conv>/<lamport>/<id>   the frame, plus who sent it and when it landed
 *   ptr/<id>                    id -> conversation + lamport, so an edit can
 *                               find its target without scanning
 *   conv/<conv>                 metadata: last activity, last read, unread
 *   gap/<conv>/<id>             a cited parent we do not hold
 *   read/<conv>/<identity>      how far a contact has read
 *   term/<term>/<id>            inverted index for search
 *   tconv/<id>                  id -> conversation, so a search hit can be placed
 *
 * Lamport values are zero-padded hex so lexicographic order is numeric order.
 */
import { fromHex, toHex } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import type { Store } from '../stores/store.js';
import { ConversationDag, type DagNode, type Gap } from './dag.js';
import {
  type ChatFrame,
  ChatFrameType,
  chatMessageId,
  parseChatFrame,
  parseDeleteBody,
  parseEditBody,
  parseReactionBody,
  parseTextBody,
  serializeChatFrame,
  type AttachRef,
} from './frame.js';

const NS = 'chat';
const RECORD_VERSION = 1;

/** u64 as 16 lowercase hex digits, so string order is numeric order. */
function lamportKey(v: bigint): string {
  return v.toString(16).padStart(16, '0');
}

export interface StoredMessage {
  id: Uint8Array;
  /** Sender identity, or undefined for an unsigned (anonymous) message. */
  sender?: Uint8Array;
  frame: ChatFrame;
  /** Local clock, unix ms, when we first stored it. */
  receivedAt: number;
}

function encodeRecord(m: StoredMessage): Uint8Array {
  const w = new Writer().u8(RECORD_VERSION);
  if (m.sender) w.u8(1).bytes(m.sender);
  else w.u8(0);
  return w.i64(BigInt(m.receivedAt)).varBytes(serializeChatFrame(m.frame)).finish();
}

function decodeRecord(bytes: Uint8Array): StoredMessage {
  const r = new Reader(bytes);
  if (r.u8() !== RECORD_VERSION) throw new Error('unknown chat record version');
  const sender = r.u8() === 1 ? r.bytes(48).slice() : undefined;
  const receivedAt = Number(r.i64());
  const frame = parseChatFrame(r.varBytes());
  r.assertDone();
  const out: StoredMessage = { id: chatMessageId(frame), frame, receivedAt };
  if (sender) out.sender = sender;
  return out;
}

export interface ConversationMeta {
  convId: Uint8Array;
  /** Highest `receivedAt` seen, for sorting a conversation list. */
  lastActivityAt: number;
  /** Ids the local user has read up to. */
  readHeads: Uint8Array[];
  unread: number;
}

/**
 * Unicode-aware tokeniser for the search index. Splits on anything that is not
 * a letter or a number, so scripts without spaces still yield their words and
 * punctuation never becomes part of a term.
 */
export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((t) => t.length > 0);
}

/** A message as an application should render it, after edits and deletes. */
export interface MessageView {
  id: Uint8Array;
  sender?: Uint8Array;
  timestamp: bigint;
  lamport: bigint;
  receivedAt: number;
  text: string;
  mentions: Uint8Array[];
  attachments: AttachRef[];
  replyTo?: Uint8Array;
  /** The text was replaced by a later edit from the same sender. */
  edited: boolean;
  /**
   * A tombstone was received. The content is dropped locally and peers are
   * asked to do the same — but it is a REQUEST, not an erasure: anyone who
   * received the message could have kept it.
   */
  deleted: boolean;
  /** emoji -> identities that reacted, hex-keyed. */
  reactions: Map<string, string[]>;
  /**
   * Identities (hex) that have read at least this far. Derived from their read
   * receipts by causal ancestry, so reading a later message implies everything
   * before it — a receipt does not have to name every id.
   */
  readBy: string[];
}

export class ChatStore {
  constructor(private readonly store: Store) {}

  async putMessage(m: StoredMessage): Promise<boolean> {
    const idHex = toHex(m.id);
    if (await this.store.get(NS, `ptr/${idHex}`)) return false; // already have it
    const convHex = toHex(m.frame.convId);
    const key = `msg/${convHex}/${lamportKey(m.frame.lamport)}/${idHex}`;
    await this.store.put(NS, key, encodeRecord(m));
    await this.store.put(NS, `ptr/${idHex}`, new Writer().varString(key).finish());
    // A message we were missing is no longer a gap.
    await this.store.delete(NS, `gap/${convHex}/${idHex}`);
    if (m.frame.type === ChatFrameType.TEXT) {
      await this.indexText(m.frame.convId, m.id, parseTextBody(m.frame.body).text);
    } else if (m.frame.type === ChatFrameType.DELETE) {
      // Drop the target from the search index as well as from the view: an
      // index that still matches deleted text would leak exactly the content
      // the user asked to remove.
      const target = await this.getMessage(parseDeleteBody(m.frame.body).target);
      if (target && target.frame.type === ChatFrameType.TEXT && sameSender(target.sender, m.sender)) {
        await this.unindex(target.id, parseTextBody(target.frame.body).text);
      }
    }
    return true;
  }

  async getMessage(id: Uint8Array): Promise<StoredMessage | undefined> {
    const ptr = await this.store.get(NS, `ptr/${toHex(id)}`);
    if (!ptr) return undefined;
    const key = new Reader(ptr).varString();
    const raw = await this.store.get(NS, key);
    return raw ? decodeRecord(raw) : undefined;
  }

  /** Every message in a conversation, in stored (lamport) order. */
  async messages(convId: Uint8Array): Promise<StoredMessage[]> {
    const entries = await this.store.list(NS, `msg/${toHex(convId)}/`);
    return entries.map((e) => decodeRecord(e.value));
  }

  /** Conversation ids we hold anything for. */
  async conversations(): Promise<Uint8Array[]> {
    const entries = await this.store.list(NS, 'conv/');
    return entries.map((e) => fromHex(e.key.slice('conv/'.length)));
  }

  async meta(convId: Uint8Array): Promise<ConversationMeta> {
    const raw = await this.store.get(NS, `conv/${toHex(convId)}`);
    if (!raw) return { convId: convId.slice(), lastActivityAt: 0, readHeads: [], unread: 0 };
    const r = new Reader(raw);
    r.u8();
    const lastActivityAt = Number(r.i64());
    const unread = r.u32();
    const n = r.compactSize();
    const readHeads: Uint8Array[] = [];
    for (let i = 0; i < n; i++) readHeads.push(r.bytes(32).slice());
    return { convId: convId.slice(), lastActivityAt, readHeads, unread };
  }

  async setMeta(m: ConversationMeta): Promise<void> {
    const w = new Writer().u8(RECORD_VERSION).i64(BigInt(m.lastActivityAt)).u32(m.unread);
    w.compactSize(m.readHeads.length);
    for (const h of m.readHeads) w.bytes(h);
    await this.store.put(NS, `conv/${toHex(m.convId)}`, w.finish());
  }

  /** Record how far `identity` has read, from a RECEIPT frame. */
  async setReadBy(convId: Uint8Array, identity: Uint8Array, heads: Uint8Array[]): Promise<void> {
    const w = new Writer().u8(RECORD_VERSION).compactSize(heads.length);
    for (const h of heads) w.bytes(h);
    await this.store.put(NS, `read/${toHex(convId)}/${toHex(identity)}`, w.finish());
  }

  /** identity (hex) -> the heads it last reported reading. */
  async readState(convId: Uint8Array): Promise<Map<string, Uint8Array[]>> {
    const prefix = `read/${toHex(convId)}/`;
    const out = new Map<string, Uint8Array[]>();
    for (const e of await this.store.list(NS, prefix)) {
      const r = new Reader(e.value);
      r.u8();
      const n = r.compactSize();
      const heads: Uint8Array[] = [];
      for (let i = 0; i < n; i++) heads.push(r.bytes(32).slice());
      out.set(e.key.slice(prefix.length), heads);
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Search

  private async indexText(convId: Uint8Array, id: Uint8Array, text: string): Promise<void> {
    const idHex = toHex(id);
    await this.store.put(NS, `tconv/${idHex}`, convId);
    for (const term of new Set(tokenize(text))) {
      await this.store.put(NS, `term/${term}/${idHex}`, new Uint8Array(0));
    }
  }

  private async unindex(id: Uint8Array, text: string): Promise<void> {
    const idHex = toHex(id);
    for (const term of new Set(tokenize(text))) {
      await this.store.delete(NS, `term/${term}/${idHex}`);
    }
  }

  /**
   * Message ids matching every term in `query`. The last term is matched as a
   * PREFIX so search-as-you-type works; earlier terms must match whole.
   */
  async search(query: string, opts: { convId?: Uint8Array; limit?: number } = {}): Promise<Uint8Array[]> {
    const terms = tokenize(query);
    if (terms.length === 0) return [];

    let hits: Set<string> | undefined;
    for (let i = 0; i < terms.length; i++) {
      const term = terms[i]!;
      const last = i === terms.length - 1;
      const prefix = last ? `term/${term}` : `term/${term}/`;
      const found = new Set<string>();
      for (const e of await this.store.list(NS, prefix)) {
        const slash = e.key.lastIndexOf('/');
        found.add(e.key.slice(slash + 1));
      }
      hits = hits === undefined ? found : new Set([...hits].filter((h) => found.has(h)));
      if (hits.size === 0) return [];
    }

    const out: Uint8Array[] = [];
    for (const idHex of hits ?? []) {
      if (opts.convId) {
        const conv = await this.store.get(NS, `tconv/${idHex}`);
        if (!conv || toHex(conv) !== toHex(opts.convId)) continue;
      }
      out.push(fromHex(idHex));
      if (opts.limit && out.length >= opts.limit) break;
    }
    return out;
  }

  async recordGap(convId: Uint8Array, missing: Uint8Array): Promise<void> {
    await this.store.put(NS, `gap/${toHex(convId)}/${toHex(missing)}`, new Uint8Array(0));
  }

  async gaps(convId: Uint8Array): Promise<Uint8Array[]> {
    const prefix = `gap/${toHex(convId)}/`;
    const entries = await this.store.list(NS, prefix);
    return entries.map((e) => fromHex(e.key.slice(prefix.length)));
  }

  /** Rebuild the in-memory DAG for a conversation. */
  async dag(convId: Uint8Array): Promise<ConversationDag> {
    const dag = new ConversationDag();
    for (const m of await this.messages(convId)) dag.add(toNode(m));
    return dag;
  }

  /**
   * Conversation contents in display order, with edits, deletes and reactions
   * already applied.
   */
  async view(convId: Uint8Array): Promise<{ messages: MessageView[]; gaps: Gap[] }> {
    const stored = await this.messages(convId);
    const dag = new ConversationDag();
    const byId = new Map<string, StoredMessage>();
    for (const m of stored) {
      dag.add(toNode(m));
      byId.set(toHex(m.id), m);
    }

    const views = new Map<string, MessageView>();
    for (const m of stored) {
      if (m.frame.type !== ChatFrameType.TEXT) continue;
      const body = parseTextBody(m.frame.body);
      const v: MessageView = {
        id: m.id,
        timestamp: m.frame.timestamp,
        lamport: m.frame.lamport,
        receivedAt: m.receivedAt,
        text: body.text,
        mentions: body.mentions,
        attachments: body.attachments,
        edited: false,
        deleted: false,
        reactions: new Map(),
        readBy: [],
      };
      if (m.sender) v.sender = m.sender;
      if (body.replyTo) v.replyTo = body.replyTo;
      views.set(toHex(m.id), v);
    }

    // Apply mutations in causal order, so the last edit wins deterministically
    // rather than by arrival time.
    const latestEdit = new Map<string, bigint>();
    for (const node of dag.ordered()) {
      const m = byId.get(toHex(node.id));
      if (!m) continue;
      switch (m.frame.type) {
        case ChatFrameType.EDIT: {
          const body = parseEditBody(m.frame.body);
          const target = views.get(toHex(body.target));
          // Only the original author may edit. Without this check anyone who
          // can reach the conversation could rewrite someone else's words.
          if (!target || !sameSender(target.sender, m.sender)) break;
          const prev = latestEdit.get(toHex(body.target));
          if (prev !== undefined && prev > m.frame.lamport) break;
          latestEdit.set(toHex(body.target), m.frame.lamport);
          target.text = body.text;
          target.edited = true;
          break;
        }
        case ChatFrameType.DELETE: {
          const body = parseDeleteBody(m.frame.body);
          const target = views.get(toHex(body.target));
          if (!target || !sameSender(target.sender, m.sender)) break;
          target.deleted = true;
          target.text = '';
          target.attachments = [];
          break;
        }
        case ChatFrameType.REACTION: {
          const body = parseReactionBody(m.frame.body);
          const target = views.get(toHex(body.target));
          if (!target || !m.sender) break;
          const who = toHex(m.sender);
          const set = new Set(target.reactions.get(body.emoji) ?? []);
          // Last write per (reactor, target, emoji) wins, in causal order.
          if (body.add) set.add(who);
          else set.delete(who);
          if (set.size > 0) target.reactions.set(body.emoji, [...set]);
          else target.reactions.delete(body.emoji);
          break;
        }
        default:
          break;
      }
    }

    // Read receipts name only the heads a reader had seen, so reading a later
    // message implies everything causally before it. Walk each reader's
    // ancestry once rather than expecting receipts to enumerate every id.
    for (const [who, heads] of await this.readState(convId)) {
      const seen = new Set<string>();
      const stack = heads.map((h) => toHex(h));
      while (stack.length > 0) {
        const key = stack.pop()!;
        if (seen.has(key)) continue;
        seen.add(key);
        const m = byId.get(key);
        if (m) for (const p of m.frame.parents) stack.push(toHex(p));
      }
      for (const key of seen) views.get(key)?.readBy.push(who);
    }

    const ordered = dag
      .ordered()
      .map((n) => views.get(toHex(n.id)))
      .filter((v): v is MessageView => v !== undefined);
    return { messages: ordered, gaps: dag.gaps() };
  }
}

function toNode(m: StoredMessage): DagNode {
  return { id: m.id, lamport: m.frame.lamport, timestamp: m.frame.timestamp, parents: m.frame.parents };
}

function sameSender(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (!a || !b) return false;
  return toHex(a) === toHex(b);
}
