/**
 * ChatClient: conversations, replies, reactions, edits, deletes, read state,
 * contact requests.
 *
 * Sits on `MessagingClient`, which stays the dumb authenticated transport. All
 * this layer adds is the schema, the causal ordering and the local state — but
 * that is exactly what two applications need to agree on before they can talk
 * to each other at all.
 */
import { Emitter } from '../net/emitter.js';
import { fromUtf8, toHex, utf8 } from '../common/bytes.js';
import type { Store } from '../stores/store.js';
import { Writer, Reader } from '../common/serialize.js';
import type { IncomingMessage, MessagingClient } from '../usermsg/client.js';
import { decodeIdentity, encodeIdentity } from '../usermsg/bundle.js';
import { ConversationDag, type Gap } from './dag.js';
import {
  type AttachRef,
  type ChatFrame,
  ChatFrameType,
  chatMessageId,
  ContactOp,
  directConversationId,
  parseChatFrame,
  parseContactBody,
  selfConversationId,
  serializeChatFrame,
  serializeContactBody,
  serializeDeleteBody,
  serializeEditBody,
  serializeReactionBody,
  serializeReceiptBody,
  serializeTextBody,
} from './frame.js';
import { ChatStore, type MessageView, type StoredMessage } from './store.js';

const NS = 'chatmeta';
/** Chat rides its own topic prefix so other apps on the bus are unaffected. */
export const CHAT_TOPIC_PREFIX = 'c/';

export function chatTopic(convId: Uint8Array): string {
  return CHAT_TOPIC_PREFIX + toHex(convId).slice(0, 16);
}

export interface ContactRequest {
  identity: string;
  intro: string;
  receivedAt: number;
}

export type ChatEvents = {
  /** A new chat message, already ordered and resolved. */
  message: { convId: Uint8Array; message: MessageView };
  /** An edit, delete, reaction or read receipt changed an existing message. */
  update: { convId: Uint8Array; message: MessageView };
  /**
   * A cited parent we do not hold. The conversation has a visible hole; the
   * application should say so rather than pretend nothing is missing.
   */
  gap: { convId: Uint8Array; gaps: Gap[] };
  /** First contact from an unknown identity. Not yet in any conversation. */
  request: ContactRequest;
  error: Error;
};

export interface ChatClientOptions {
  client: MessagingClient;
  store: Store;
  now?: () => number;
}

export interface SendTextOptions {
  replyTo?: Uint8Array;
  mentions?: Uint8Array[];
  attachments?: AttachRef[];
}

export class ChatClient extends Emitter<ChatEvents> {
  private readonly chat: ChatStore;
  private readonly now: () => number;
  private readonly dags = new Map<string, ConversationDag>();
  /** Unsubscribe from the transport's message event. Named to avoid clashing
   *  with Emitter's own `off`. */
  private unsubscribe: (() => void) | undefined;
  private closed = false;

  private constructor(
    private readonly client: MessagingClient,
    private readonly store: Store,
    now: () => number,
  ) {
    super();
    this.chat = new ChatStore(store);
    this.now = now;
  }

  static async create(o: ChatClientOptions): Promise<ChatClient> {
    const c = new ChatClient(o.client, o.store, o.now ?? (() => Date.now()));
    c.unsubscribe = o.client.on('message', (m) => {
      void c.onMessage(m).catch((e: unknown) => c.emit('error', e instanceof Error ? e : new Error(String(e))));
    });
    return c;
  }

  close(): void {
    this.closed = true;
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  /** Our own identity, `navid1…`. */
  get identity(): string {
    return this.client.identity;
  }

  /** Conversation id shared with a contact. Both sides derive the same value. */
  conversationWith(contact: string): Uint8Array {
    return directConversationId(decodeIdentity(this.client.identity), decodeIdentity(contact));
  }

  /** Our own conversation: notes to self, and where our devices mirror sends. */
  selfConversation(): Uint8Array {
    return selfConversationId(decodeIdentity(this.client.identity));
  }

  // -------------------------------------------------------------------------
  // Sending

  async sendText(to: string, text: string, opts: SendTextOptions = {}): Promise<Uint8Array> {
    const body = serializeTextBody({
      text,
      mentions: opts.mentions ?? [],
      attachments: opts.attachments ?? [],
      ...(opts.replyTo ? { replyTo: opts.replyTo } : {}),
    });
    return this.sendFrame(to, ChatFrameType.TEXT, body);
  }

  async edit(to: string, target: Uint8Array, text: string): Promise<Uint8Array> {
    return this.sendFrame(to, ChatFrameType.EDIT, serializeEditBody({ target, text }));
  }

  /**
   * Ask for a message to be removed. A tombstone, not an erasure: anyone who
   * received it could have kept it, and the protocol cannot change that.
   */
  async delete(to: string, target: Uint8Array): Promise<Uint8Array> {
    return this.sendFrame(to, ChatFrameType.DELETE, serializeDeleteBody({ target }));
  }

  async react(to: string, target: Uint8Array, emoji: string, add = true): Promise<Uint8Array> {
    return this.sendFrame(to, ChatFrameType.REACTION, serializeReactionBody({ target, emoji, add }));
  }

  /** Mark everything currently known in a conversation as read. */
  async markRead(to: string): Promise<void> {
    const convId = this.conversationWith(to);
    const dag = await this.dagFor(convId);
    const heads = dag.heads();
    const meta = await this.chat.meta(convId);
    await this.chat.setMeta({ ...meta, readHeads: heads, unread: 0 });
    if (heads.length > 0) await this.sendFrame(to, ChatFrameType.RECEIPT, serializeReceiptBody({ heads }));
  }

  /** Introduce ourselves to someone who does not have us as a contact yet. */
  async sendContactRequest(to: string, intro = ''): Promise<Uint8Array> {
    return this.sendFrame(to, ChatFrameType.CONTACT, serializeContactBody({ op: ContactOp.REQUEST, intro }));
  }

  private async sendFrame(to: string, type: number, body: Uint8Array): Promise<Uint8Array> {
    if (this.closed) throw new Error('ChatClient is closed');
    const convId = this.conversationWith(to);
    const dag = await this.dagFor(convId);
    const frame: ChatFrame = {
      version: 1,
      type,
      convId,
      timestamp: BigInt(Math.floor(this.now() / 1000)),
      lamport: dag.nextLamport(),
      parents: dag.heads(),
      body,
    };
    const id = chatMessageId(frame);
    // Store our own message before it goes out: it is part of the history the
    // next frame parents on, and a send that fails should not leave a hole.
    await this.ingest(
      { id, sender: decodeIdentity(this.client.identity), frame, receivedAt: this.now() },
      /*local=*/ true,
    );
    await this.client.send(to, serializeChatFrame(frame), { topic: chatTopic(convId) });
    return id;
  }

  // -------------------------------------------------------------------------
  // Receiving

  private async onMessage(m: IncomingMessage): Promise<void> {
    if (this.closed) return;
    if (!m.topic.startsWith(CHAT_TOPIC_PREFIX)) return;
    if (!m.from) return; // unsigned: no sender to attribute, and no conversation
    if (await this.isBlocked(m.from)) return;

    let frame: ChatFrame;
    try {
      frame = parseChatFrame(m.payload);
    } catch {
      return; // not a chat frame, or a newer encoding: ignore quietly
    }

    const sender = decodeIdentity(m.from);
    // The conversation id is derived from the two identities, so a sender
    // cannot place a message in someone else's conversation.
    const expected = this.conversationWith(m.from);
    if (toHex(frame.convId) !== toHex(expected)) return;

    if (frame.type === ChatFrameType.CONTACT) {
      await this.onContactFrame(m.from, frame);
      return;
    }

    if (!(await this.isKnown(m.from))) {
      // First contact from a stranger goes to the request queue, not the
      // inbox. PoW alone is a weak gate: cheap for a spammer with hardware,
      // expensive for a phone.
      await this.queueRequest(m.from, '');
      return;
    }

    await this.ingest({ id: chatMessageId(frame), sender, frame, receivedAt: this.now() }, /*local=*/ false);
  }

  private async onContactFrame(from: string, frame: ChatFrame): Promise<void> {
    const body = parseContactBody(frame.body);
    if (body.op === ContactOp.REQUEST) {
      if (await this.isKnown(from)) return; // already accepted; nothing to ask
      await this.queueRequest(from, body.intro);
    } else if (body.op === ContactOp.ACCEPT) {
      await this.markKnown(from);
    }
  }

  private async ingest(m: StoredMessage, local: boolean): Promise<void> {
    const fresh = await this.chat.putMessage(m);
    if (!fresh) return;

    const dag = await this.dagFor(m.frame.convId);
    dag.add({ id: m.id, lamport: m.frame.lamport, timestamp: m.frame.timestamp, parents: m.frame.parents });

    const meta = await this.chat.meta(m.frame.convId);
    await this.chat.setMeta({
      ...meta,
      lastActivityAt: Math.max(meta.lastActivityAt, m.receivedAt),
      unread: local ? meta.unread : meta.unread + (m.frame.type === ChatFrameType.TEXT ? 1 : 0),
    });

    const gaps = dag.gaps();
    for (const g of gaps) await this.chat.recordGap(m.frame.convId, g.id);
    if (gaps.length > 0) this.emit('gap', { convId: m.frame.convId, gaps });

    const view = await this.chat.view(m.frame.convId);
    if (m.frame.type === ChatFrameType.TEXT) {
      const rendered = view.messages.find((v) => toHex(v.id) === toHex(m.id));
      if (rendered) this.emit('message', { convId: m.frame.convId, message: rendered });
      return;
    }
    // A mutation changes an existing message rather than adding one.
    const targetId = mutationTarget(m.frame);
    if (!targetId) return;
    const rendered = view.messages.find((v) => toHex(v.id) === toHex(targetId));
    if (rendered) this.emit('update', { convId: m.frame.convId, message: rendered });
  }

  // -------------------------------------------------------------------------
  // History and contacts

  /** A conversation in display order, with gaps reported alongside. */
  history(convId: Uint8Array): Promise<{ messages: MessageView[]; gaps: Gap[] }> {
    return this.chat.view(convId);
  }

  conversations(): Promise<Uint8Array[]> {
    return this.chat.conversations();
  }

  unreadCount(convId: Uint8Array): Promise<number> {
    return this.chat.meta(convId).then((m) => m.unread);
  }

  /** Pending contact requests, oldest first. */
  async requests(): Promise<ContactRequest[]> {
    const entries = await this.store.list(NS, 'req/');
    return entries
      .map((e) => {
        const r = new Reader(e.value);
        r.u8();
        return { identity: r.varString(), intro: r.varString(), receivedAt: Number(r.i64()) };
      })
      .sort((a, b) => a.receivedAt - b.receivedAt);
  }

  /** Accept a request: the sender becomes a contact and can reach the inbox. */
  async acceptRequest(identity: string): Promise<void> {
    await this.markKnown(identity);
    await this.store.delete(NS, `req/${keyOf(identity)}`);
    await this.sendFrame(identity, ChatFrameType.CONTACT, serializeContactBody({ op: ContactOp.ACCEPT, intro: '' }));
  }

  async declineRequest(identity: string): Promise<void> {
    await this.store.delete(NS, `req/${keyOf(identity)}`);
  }

  /**
   * Block an identity. Local only and never published, so blocking is
   * invisible to the person blocked.
   */
  async block(identity: string): Promise<void> {
    await this.store.put(NS, `block/${keyOf(identity)}`, new Uint8Array([1]));
    await this.store.delete(NS, `req/${keyOf(identity)}`);
  }

  async unblock(identity: string): Promise<void> {
    await this.store.delete(NS, `block/${keyOf(identity)}`);
  }

  async isBlocked(identity: string): Promise<boolean> {
    return (await this.store.get(NS, `block/${keyOf(identity)}`)) !== undefined;
  }

  /** Whether this identity is an accepted contact. */
  async isKnown(identity: string): Promise<boolean> {
    return (await this.store.get(NS, `known/${keyOf(identity)}`)) !== undefined;
  }

  /** Accept an identity without a request, e.g. one the user added by address. */
  async markKnown(identity: string): Promise<void> {
    await this.store.put(NS, `known/${keyOf(identity)}`, new Uint8Array([1]));
  }

  private async queueRequest(identity: string, intro: string): Promise<void> {
    const key = `req/${keyOf(identity)}`;
    if (await this.store.get(NS, key)) return; // already queued; do not re-notify
    const receivedAt = this.now();
    await this.store.put(
      NS,
      key,
      new Writer().u8(1).varString(identity).varString(intro).i64(BigInt(receivedAt)).finish(),
    );
    this.emit('request', { identity, intro, receivedAt });
  }

  private async dagFor(convId: Uint8Array): Promise<ConversationDag> {
    const key = toHex(convId);
    let dag = this.dags.get(key);
    if (!dag) {
      dag = await this.chat.dag(convId);
      this.dags.set(key, dag);
    }
    return dag;
  }
}

function mutationTarget(frame: ChatFrame): Uint8Array | undefined {
  try {
    switch (frame.type) {
      case ChatFrameType.EDIT:
        return new Reader(frame.body).bytes(32).slice();
      case ChatFrameType.DELETE:
      case ChatFrameType.REACTION:
        return new Reader(frame.body).bytes(32).slice();
      default:
        return undefined;
    }
  } catch {
    return undefined;
  }
}

function keyOf(identity: string): string {
  return toHex(decodeIdentity(identity));
}

export { fromUtf8, utf8, encodeIdentity };
