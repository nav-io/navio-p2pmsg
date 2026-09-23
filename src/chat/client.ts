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
import { decodeIdentity, encodeBundle, encodeIdentity, parseBundle, serializeBundle } from '../usermsg/bundle.js';
import { ConversationDag, type Gap } from './dag.js';
import {
  type AttachRef,
  MAX_THUMBNAIL_BYTES,
  type ChatFrame,
  ChatFrameType,
  chatMessageId,
  ContactOp,
  directConversationId,
  parseChatFrame,
  parseContactBody,
  parseProfileBody,
  parsePaymentBody,
  type PaymentBody,
  PaymentOp,
  serializePaymentBody,
  parseReceiptBody,
  type ProfileBody,
  serializeProfileBody,
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
import { decryptFile, encryptFile, type FileClient, type FileServer } from '../stream/file.js';
import { BackfillClient, BackfillServer, type SyncEntry } from '../stream/backfill.js';
import {
  type GroupSnapshot,
  mergeHeads,
  type ReadSnapshot,
  StateSyncClient,
  StateSyncServer,
} from '../stream/statesync.js';
import type { StreamChannel } from '../stream/transport.js';

/**
 * Largest attachment that fits the bus without a direct channel.
 *
 * A frame is 3584 bytes and the chunker allows 16 of them, so this is the real
 * ceiling — roughly 53 KB, and 16 proofs of work. Enough for a thumbnail or a
 * voice note; not for a video, which is what the direct channel is for.
 */
export const MAX_BUS_ATTACHMENT_BYTES = 50 * 1024;
import { USER_DATA_KIND, serializeUserMsgFrame } from '../usermsg/frame.js';
import { randomBytes } from '../common/bytes.js';
import { extractDetectionKey, fmdFlag, parseClueKey } from '../bus/fmd.js';
import { deriveGroupEpoch, type GroupEpochKeys, randomEpochSecret } from './group/schedule.js';
import {
  GroupRole,
  type GroupState,
  memberOf,
  parseGroupState,
  serializeGroupState,
  signGroupState,
  validateGroupState,
} from './group/state.js';
import { applyGroupOp, type GroupOp } from './group/ops.js';
import { checkInvite, decodeInvite, encodeInvite, type GroupInvite, InviteKind, signInvite } from './group/invite.js';

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
  /** A contact published a new display name, status or avatar. */
  profile: { identity: string; profile: ProfileBody };
  /** A payment request or receipt. The application decides what to do with it. */
  payment: { from: string; convId: Uint8Array; payment: PaymentBody };
  /** Group membership or metadata changed. */
  group: { groupId: Uint8Array; state: GroupState };
  /**
   * Groups a revoked device could still read, because rotating the ACCOUNT
   * epoch does not rotate a GROUP's keys. Groups we administer are rekeyed
   * automatically; these are the ones only someone else can rotate.
   */
  groupsNeedRekey: { groupIds: Uint8Array[] };
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
  private unsubscribeEpoch: (() => void) | undefined;
  private unsubscribeMirror: (() => void) | undefined;
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
    await c.loadGroups();
    // A revoked device keeps every group secret it was given, so the account
    // epoch moving is exactly when the groups we administer must rotate too.
    c.unsubscribeEpoch = o.client.on('accountEpoch', () => {
      void c.rekeyAdministeredGroups().catch((e: unknown) =>
        c.emit('error', e instanceof Error ? e : new Error(String(e))),
      );
    });
    c.unsubscribe = o.client.on('message', (m) => {
      void c.onMessage(m).catch((e: unknown) => c.emit('error', e instanceof Error ? e : new Error(String(e))));
    });
    // What our other devices send is part of this conversation too. Without
    // this a second device shows half a conversation — and never learns about
    // a group the first one created, because the membership frame that
    // carries the epoch secret goes to the members, not to our own devices.
    c.unsubscribeMirror = o.client.on('mirrored', (m) => {
      void c.onMirrored(m).catch((e: unknown) => c.emit('error', e instanceof Error ? e : new Error(String(e))));
    });
    return c;
  }

  close(): void {
    this.closed = true;
    this.unsubscribe?.();
    this.unsubscribe = undefined;
    this.unsubscribeEpoch?.();
    this.unsubscribeEpoch = undefined;
    this.unsubscribeMirror?.();
    this.unsubscribeMirror = undefined;
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
  /**
   * Ask a contact for a payment. Carries no keys and touches no chain — an
   * application wires the amount to a wallet itself.
   */
  async requestPayment(to: string, amount: bigint, opts: { tokenId?: string; memo?: string } = {}): Promise<Uint8Array> {
    return this.sendFrame(
      to,
      ChatFrameType.PAYMENT,
      serializePaymentBody({
        op: PaymentOp.REQUEST,
        amount,
        tokenId: opts.tokenId ?? '',
        memo: opts.memo ?? '',
        reference: new Uint8Array(0),
      }),
    );
  }

  /**
   * Tell a contact a payment was made. `reference` is the output hash — note
   * navio-core returns one of those rather than a txid, so it is what the
   * recipient can actually look up.
   */
  async notifyPaymentSent(
    to: string,
    amount: bigint,
    reference: Uint8Array,
    opts: { tokenId?: string; memo?: string } = {},
  ): Promise<Uint8Array> {
    return this.sendFrame(
      to,
      ChatFrameType.PAYMENT,
      serializePaymentBody({
        op: PaymentOp.SENT,
        amount,
        tokenId: opts.tokenId ?? '',
        memo: opts.memo ?? '',
        reference,
      }),
    );
  }

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

    if (frame.type === ChatFrameType.MEMBERSHIP) {
      await this.onMembershipFrame(m.from, frame);
      return;
    }

    const group = await this.groupState(frame.convId);
    if (group) {
      // Group traffic: the sender must be a member, and must have joined no
      // later than the epoch this message belongs to.
      if (!memberOf(group, sender)) return;
      await this.ingest(
        { id: chatMessageId(frame), sender, frame, receivedAt: this.now(), ...proof(m) },
        /*local=*/ false,
      );
      return;
    }

    // The 1:1 conversation id is derived from the two identities, so a sender
    // cannot place a message in someone else's conversation.
    const expected = this.conversationWith(m.from);
    if (toHex(frame.convId) !== toHex(expected)) return;

    if (frame.type === ChatFrameType.CONTACT) {
      await this.onContactFrame(m.from, frame);
      return;
    }

    if (frame.type === ChatFrameType.RECEIPT) {
      // Read state, not conversation content: recorded against the sender and
      // surfaced as `readBy`, never stored as a message.
      if (!(await this.isKnown(m.from))) return;
      const heads = parseReceiptBody(frame.body).heads;
      // Emit for the messages whose read state actually CHANGED, not for the
      // heads the receipt names. A head is often an edit or a reaction rather
      // than a rendered message, so keying on it would silently emit nothing
      // exactly when a conversation is most active.
      const before = new Map(
        (await this.chat.view(frame.convId)).messages.map((m) => [toHex(m.id), m.readBy.length]),
      );
      await this.chat.setReadBy(frame.convId, sender, heads);
      for (const m of (await this.chat.view(frame.convId)).messages) {
        if (m.readBy.length !== (before.get(toHex(m.id)) ?? 0)) {
          this.emit('update', { convId: frame.convId, message: m });
        }
      }
      return;
    }

    if (frame.type === ChatFrameType.PAYMENT) {
      if (!(await this.isKnown(m.from))) return;
      try {
        this.emit('payment', { from: m.from, convId: frame.convId, payment: parsePaymentBody(frame.body) });
      } catch {
        // Malformed body from a newer or broken peer: ignore.
      }
      return;
    }

    if (frame.type === ChatFrameType.PROFILE) {
      if (!(await this.isKnown(m.from))) return;
      const profile = parseProfileBody(frame.body);
      await this.store.put(NS, `profile/${keyOf(m.from)}`, frame.body);
      this.emit('profile', { identity: m.from, profile });
      return;
    }

    if (!(await this.isKnown(m.from))) {
      // First contact from a stranger goes to the request queue, not the
      // inbox. PoW alone is a weak gate: cheap for a spammer with hardware,
      // expensive for a phone.
      await this.queueRequest(m.from, '');
      return;
    }

    await this.ingest(
      { id: chatMessageId(frame), sender, frame, receivedAt: this.now(), ...proof(m) },
      /*local=*/ false,
    );
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

  /**
   * A frame another device of this account sent, replayed to us over the
   * mirror. It is our own message: attributed to our identity, and not
   * counted as unread.
   *
   * Only content and membership are taken. A receipt, profile or contact
   * frame is about the sibling's side of the exchange — applying it here
   * would attribute the contact's read state, or their profile, to the wrong
   * person.
   */
  private async onMirrored(m: { to: string; topic: string; payload: Uint8Array }): Promise<void> {
    if (this.closed) return;
    if (!m.topic.startsWith(CHAT_TOPIC_PREFIX)) return;
    let frame: ChatFrame;
    try {
      frame = parseChatFrame(m.payload);
    } catch {
      return;
    }
    if (frame.type === ChatFrameType.MEMBERSHIP) {
      // The membership frame the sibling sent to a member carries the state
      // and the epoch secret, which is exactly what this device needs to be
      // in the group at all.
      await this.onMembershipFrame(this.client.identity, frame);
      return;
    }
    if (
      frame.type === ChatFrameType.RECEIPT ||
      frame.type === ChatFrameType.PROFILE ||
      frame.type === ChatFrameType.CONTACT ||
      frame.type === ChatFrameType.PAYMENT
    ) {
      return;
    }
    const group = await this.groupState(frame.convId);
    if (!group && toHex(frame.convId) !== toHex(this.conversationWith(m.to))) return;
    await this.ingest(
      { id: chatMessageId(frame), sender: decodeIdentity(this.client.identity), frame, receivedAt: this.now() },
      /*local=*/ true,
    );
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

  /**
   * Serve history to another device of this account over a direct channel.
   *
   * The caller owns the channel and decides who is on the other end: this is
   * for our own devices, and there is nothing in the protocol that makes it
   * safe to point at a contact. Close the returned server when the channel
   * goes away.
   */
  serveBackfill(channel: StreamChannel, opts: { maxLimit?: number } = {}): BackfillServer {
    return new BackfillServer(
      channel,
      {
        history: async (convId, fromLamport, limit) => {
          const stored = await this.chat.messages(convId);
          return stored
            .filter((m) => m.frame.lamport >= fromLamport)
            .slice(0, limit)
            .map((m) => {
              const e: SyncEntry = { frame: serializeChatFrame(m.frame), receivedAt: m.receivedAt };
              if (m.sender) e.sender = m.sender;
              if (m.signed && m.signedFor) {
                e.signed = m.signed;
                e.signedFor = m.signedFor;
              }
              return e;
            });
        },
      },
      opts,
    );
  }

  /**
   * Ask another device of this account for a conversation's history and fold
   * it into ours.
   *
   * Entries that came with a signature are verified here, not taken on trust,
   * and a bad one is dropped rather than stored. Entries with no signature —
   * our own sent messages, and anything stored before signatures were kept —
   * are accepted, and the count is returned so an application can say what it
   * took on trust.
   */
  async backfillFrom(
    channel: StreamChannel,
    convId: Uint8Array,
    opts: { fromLamport?: bigint; limit?: number; timeoutMs?: number } = {},
  ): Promise<{ added: number; verified: number; unverified: number; rejected: number }> {
    const client = new BackfillClient(channel, (id) => chatTopic(id));
    try {
      const res = await client.fetch(convId, opts);
      let added = 0;
      for (const e of [...res.verified, ...res.unverified]) {
        let frame: ChatFrame;
        try {
          frame = parseChatFrame(e.frame);
        } catch {
          continue;
        }
        // A frame claiming to belong to another conversation is not history
        // for this one, whatever it is signed with.
        if (toHex(frame.convId) !== toHex(convId)) continue;
        const before = await this.chat.messages(convId);
        const had = before.some((m) => toHex(m.id) === toHex(chatMessageId(frame)));
        await this.ingest(
          {
            id: chatMessageId(frame),
            ...(e.sender ? { sender: e.sender } : {}),
            frame,
            receivedAt: e.receivedAt,
            ...(e.signed && e.signedFor ? { signed: e.signed, signedFor: e.signedFor } : {}),
          },
          // Backfill is history, not new traffic: it must not mark anything
          // unread on a device that is only catching up.
          /*local=*/ true,
        );
        if (!had) added++;
      }
      return {
        added,
        verified: res.verified.length,
        unverified: res.unverified.length,
        rejected: res.rejected,
      };
    } finally {
      client.close();
    }
  }

  /**
   * Serve the state around the messages — contacts, groups, read state — to
   * another device of this account. Like `serveBackfill`, the caller owns the
   * channel and decides who is on the other end.
   */
  serveStateSync(channel: StreamChannel): StateSyncServer {
    return new StateSyncServer(channel, {
      contacts: () =>
        Promise.resolve(
          this.client.contacts
            .all()
            .filter((c) => c.bundle !== undefined)
            .map((c) => serializeBundle(c.bundle!)),
        ),
      groups: async () => {
        const out: GroupSnapshot[] = [];
        for (const state of await this.groups()) {
          const prefix = `group/${toHex(state.groupId)}/epoch/`;
          const secrets: { epoch: number; secret: Uint8Array }[] = [];
          for (const e of await this.store.list(NS, prefix)) {
            secrets.push({ epoch: parseInt(e.key.slice(prefix.length), 16), secret: e.value });
          }
          out.push({ state: serializeGroupState(state), secrets });
        }
        return out;
      },
      read: async () => {
        const out: ReadSnapshot[] = [];
        for (const convId of await this.chat.conversations()) {
          const meta = await this.chat.meta(convId);
          if (meta.readHeads.length > 0) out.push({ convId, heads: meta.readHeads });
        }
        return out;
      },
    });
  }

  /**
   * Ask another device of this account for the state around the messages and
   * merge it in.
   *
   * Everything merged is checked here rather than taken on trust: a contact's
   * bundle carries its own signature, a group state is hash-chained and
   * validated against what we already hold, and read state is unioned, which
   * is the only direction it moves. The known list and the blocklist are not
   * carried at all — see `../stream/statesync.js` for why.
   */
  async stateSyncFrom(
    channel: StreamChannel,
    opts: { sections?: number; timeoutMs?: number } = {},
  ): Promise<{ contacts: number; groups: number; conversations: number; rejected: number }> {
    const client = new StateSyncClient(channel);
    try {
      const res = await client.fetch(opts);
      let contacts = 0;
      let groups = 0;
      let conversations = 0;
      let rejected = res.malformed;

      for (const raw of res.contacts) {
        try {
          // addContact verifies the bundle, and kicks off discovery for the
          // clue key, which is not in a basic bundle and is 1152 bytes.
          await this.client.addContact(encodeBundle(parseBundle(raw)));
          contacts++;
        } catch {
          rejected++;
        }
      }

      for (const snap of res.groups) {
        try {
          const state = parseGroupState(snap.state);
          const previous = await this.groupState(state.groupId);
          // Same gate an arriving membership frame passes: a state that does
          // not chain to the one we hold is a missed update or two histories,
          // and neither is something to merge.
          if (!validateGroupState(state, previous).ok) {
            rejected++;
            continue;
          }
          for (const e of snap.secrets) await this.storeEpochSecret(state.groupId, e.epoch, e.secret);
          const current = snap.secrets.find((e) => e.epoch === state.epoch);
          if (current) await this.adoptGroup(state, current.secret);
          groups++;
        } catch {
          rejected++;
        }
      }

      for (const snap of res.read) {
        const meta = await this.chat.meta(snap.convId);
        const merged = mergeHeads(meta.readHeads, snap.heads);
        if (merged.length === meta.readHeads.length) continue;
        await this.chat.setMeta({ ...meta, readHeads: merged, unread: 0 });
        conversations++;
      }

      return { contacts, groups, conversations, rejected };
    } finally {
      client.close();
    }
  }

  conversations(): Promise<Uint8Array[]> {
    return this.chat.conversations();
  }

  unreadCount(convId: Uint8Array): Promise<number> {
    return this.chat.meta(convId).then((m) => m.unread);
  }

  /**
   * Full-text search over stored messages. The last word is matched as a
   * prefix, so search-as-you-type works.
   *
   * The index is derived from plaintext and sits at rest beside the store — on
   * a stolen device it reveals which words appear in conversations even where
   * bodies are encrypted. See docs/security.md.
   */
  async search(query: string, opts: { convId?: Uint8Array; limit?: number } = {}): Promise<MessageView[]> {
    const ids = await this.chat.search(query, opts);
    if (ids.length === 0) return [];
    const wanted = new Set(ids.map((i) => toHex(i)));
    const convIds = opts.convId ? [opts.convId] : await this.chat.conversations();
    const out: MessageView[] = [];
    for (const convId of convIds) {
      for (const m of (await this.chat.view(convId)).messages) {
        if (wanted.has(toHex(m.id)) && !m.deleted) out.push(m);
      }
    }
    return out.sort((a, b) => b.receivedAt - a.receivedAt);
  }

  /** Our published profile, if we have set one. */
  async profile(): Promise<ProfileBody | undefined> {
    const raw = await this.store.get(NS, 'profile/self');
    return raw ? parseProfileBody(raw) : undefined;
  }

  /**
   * Set our profile and publish it to `to`. There is no directory and no
   * global namespace: a display name is something a contact chose to tell you,
   * so applications should show the identity alongside it where impersonation
   * matters.
   */
  async setProfile(profile: ProfileBody, to: string[] = []): Promise<void> {
    const body = serializeProfileBody(profile);
    await this.store.put(NS, 'profile/self', body);
    for (const contact of to) await this.sendFrame(contact, ChatFrameType.PROFILE, body);
  }

  /** The profile a contact last published. */
  async profileOf(identity: string): Promise<ProfileBody | undefined> {
    const raw = await this.store.get(NS, `profile/${keyOf(identity)}`);
    return raw ? parseProfileBody(raw) : undefined;
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
    // Introduce ourselves: a new contact otherwise sees only a navid1… string.
    const mine = await this.store.get(NS, 'profile/self');
    if (mine) await this.sendFrame(identity, ChatFrameType.PROFILE, mine);
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

  // -------------------------------------------------------------------------
  // Groups

  /**
   * Create a group. We become the owner; every other member is added in the
   * same operation and receives the state and the epoch secret 1:1.
   */
  async createGroup(name: string, members: string[] = []): Promise<Uint8Array> {
    const groupId = randomBytes(32);
    const me = decodeIdentity(this.client.identity);
    const state = signGroupState(
      {
        version: 1,
        groupId,
        epoch: 0,
        members: [
          { identity: me, role: GroupRole.OWNER, joinedAt: BigInt(Math.floor(this.now() / 1000)), joinedEpoch: 0 },
          ...members.map((m) => ({
            identity: decodeIdentity(m),
            role: GroupRole.MEMBER,
            joinedAt: BigInt(Math.floor(this.now() / 1000)),
            joinedEpoch: 0,
          })),
        ],
        name,
        topic: '',
        prevStateHash: new Uint8Array(32),
        author: me,
      },
      this.client.keyring.requireIdentitySecret().sk,
    );
    const secret = randomEpochSecret();
    await this.adoptGroup(state, secret);
    for (const m of members) await this.sendGroupKeys(m, state, secret);
    return groupId;
  }

  async groupState(groupId: Uint8Array): Promise<GroupState | undefined> {
    const raw = await this.store.get(NS, `group/${toHex(groupId)}/state`);
    return raw ? parseGroupState(raw) : undefined;
  }

  /** Groups we are a member of. */
  async groups(): Promise<GroupState[]> {
    const entries = await this.store.list(NS, 'group/');
    return entries.filter((e) => e.key.endsWith('/state')).map((e) => parseGroupState(e.value));
  }

  /** Apply a membership or metadata change and distribute the result. */
  async groupOp(groupId: Uint8Array, op: GroupOp): Promise<GroupState> {
    const state = await this.groupState(groupId);
    if (!state) throw new Error('unknown group');
    const { state: next, rekey } = applyGroupOp(state, op, {
      identity: decodeIdentity(this.client.identity),
      sk: this.client.keyring.requireIdentitySecret().sk,
    }, this.now);

    // A rekey mints a fresh secret; anything else keeps the current one, so a
    // rename does not cost every member a key distribution.
    const secret = rekey ? randomEpochSecret() : await this.epochSecret(groupId, state.epoch);
    if (!secret) throw new Error('missing epoch secret for this group');
    await this.adoptGroup(next, secret);

    const me = toHex(decodeIdentity(this.client.identity));
    for (const m of next.members) {
      if (toHex(m.identity) === me) continue;
      await this.sendGroupKeys(encodeIdentity(m.identity), next, secret);
    }
    return next;
  }

  /**
   * Attach a file to a message.
   *
   * The file is encrypted under its OWN key and the ciphertext is offered on
   * the direct channel; only a hash, a size, a mime type, that key and an
   * optional thumbnail ride the bus. The thumbnail is what lets a preview
   * render before the transfer starts.
   *
   * With no direct channel, files up to `MAX_BUS_ATTACHMENT_BYTES` can still
   * be carried inline as chunked bus messages — the honest ceiling of a
   * 3584-byte frame with a proof of work per envelope. Anything larger needs
   * the direct channel, and says so rather than failing obscurely.
   */
  async attach(
    file: Uint8Array,
    opts: { mime?: string; thumbnail?: Uint8Array; server?: FileServer } = {},
  ): Promise<AttachRef> {
    const { ciphertext, key, contentHash } = encryptFile(file);
    if (opts.server) {
      opts.server.offer(contentHash, ciphertext);
    } else if (ciphertext.length > MAX_BUS_ATTACHMENT_BYTES) {
      throw new Error(
        `attachment is ${ciphertext.length} bytes; without a direct channel the ceiling is ${MAX_BUS_ATTACHMENT_BYTES}`,
      );
    }
    const thumbnail = opts.thumbnail ?? new Uint8Array(0);
    if (thumbnail.length > MAX_THUMBNAIL_BYTES) throw new Error('thumbnail too large');
    return {
      contentHash,
      size: BigInt(ciphertext.length),
      mime: opts.mime ?? 'application/octet-stream',
      key,
      thumbnail,
    };
  }

  /**
   * Fetch and decrypt an attachment over a direct channel.
   *
   * The per-file key is what makes the ciphertext safe to move over any
   * carrier, so it comes from the message rather than from the transfer.
   */
  async fetchAttachment(ref: AttachRef, client: FileClient, opts: { timeoutMs?: number } = {}): Promise<Uint8Array> {
    const ciphertext = await client.fetch(ref.contentHash, opts);
    return decryptFile(ciphertext, ref.key);
  }

  /**
   * Rotate the keys of every group we administer.
   *
   * Revoking a device moves the ACCOUNT epoch, but a group has its own epoch
   * and its own secret — which the revoked device still holds. Until the group
   * rekeys, that device keeps reading it. Called automatically when the
   * account epoch moves.
   *
   * Groups we do not administer cannot be rotated by us. They are reported
   * through `groupsNeedRekey` so the user can ask an admin rather than assume
   * the revocation was complete.
   */
  async rekeyAdministeredGroups(): Promise<{ rekeyed: Uint8Array[]; needsAdmin: Uint8Array[] }> {
    const me = decodeIdentity(this.client.identity);
    const rekeyed: Uint8Array[] = [];
    const needsAdmin: Uint8Array[] = [];
    for (const state of await this.groups()) {
      const mine = memberOf(state, me);
      if (!mine) continue;
      if (mine.role === GroupRole.MEMBER) {
        needsAdmin.push(state.groupId);
        continue;
      }
      try {
        await this.groupOp(state.groupId, { kind: 'rekey' });
        rekeyed.push(state.groupId);
      } catch (e) {
        this.emit('error', e instanceof Error ? e : new Error(String(e)));
      }
    }
    if (needsAdmin.length > 0) this.emit('groupsNeedRekey', { groupIds: needsAdmin });
    return { rekeyed, needsAdmin };
  }

  /**
   * Hand ownership to another member, who must already be an admin.
   *
   * Separate from `promote` because it is the one change that cannot be
   * undone by the person making it: afterwards they are an admin like any
   * other, and only the new owner can transfer it again.
   */
  async transferOwnership(groupId: Uint8Array, to: string): Promise<GroupState> {
    return this.groupOp(groupId, { kind: 'transferOwnership', identity: decodeIdentity(to) });
  }

  /**
   * Admit someone who presented a request-to-join invite.
   *
   * That invite carries no secret, so it grants nothing on its own — which is
   * what makes it safe to post where it might be forwarded. An admin turning
   * it into membership is the whole point.
   */
  async admitToGroup(groupId: Uint8Array, identity: string): Promise<GroupState> {
    return this.groupOp(groupId, { kind: 'add', identity: decodeIdentity(identity) });
  }

  /** A request-to-join `navinv1…`: shareable, and useless without an admin. */
  async createJoinRequestInvite(groupId: Uint8Array, ttlSeconds = 24 * 3600): Promise<string> {
    const state = await this.groupState(groupId);
    if (!state) throw new Error('unknown group');
    return encodeInvite(
      signInvite(
        {
          version: 1,
          kind: InviteKind.REQUEST_TO_JOIN,
          groupId,
          epoch: state.epoch,
          token: randomBytes(16),
          expiresAt: BigInt(Math.floor(this.now() / 1000) + ttlSeconds),
          inviter: decodeIdentity(this.client.identity),
        },
        this.client.keyring.requireIdentitySecret().sk,
      ),
    );
  }

  /**
   * Catch up on group messages that arrived while we were offline.
   *
   * Queries once per group epoch we hold: a rekey changes the group's clue
   * key, so a single detection key would silently miss everything sent under
   * the others.
   */
  async syncGroupArchives(precision = 8): Promise<number> {
    const keys = await this.groupDetectionKeys(precision);
    let accepted = 0;
    for (const key of keys) accepted += await this.client.syncArchiveWith(key, precision);
    return accepted;
  }

  /** `navinv1…` carrying the current epoch secret. Whoever holds it can join. */
  async createInvite(groupId: Uint8Array, ttlSeconds = 24 * 3600): Promise<string> {
    const state = await this.groupState(groupId);
    if (!state) throw new Error('unknown group');
    const secret = await this.epochSecret(groupId, state.epoch);
    if (!secret) throw new Error('missing epoch secret for this group');
    return encodeInvite(
      signInvite(
        {
          version: 1,
          kind: InviteKind.KEY_IN_LINK,
          groupId,
          epoch: state.epoch,
          epochSecret: secret,
          expiresAt: BigInt(Math.floor(this.now() / 1000) + ttlSeconds),
          inviter: decodeIdentity(this.client.identity),
        },
        this.client.keyring.requireIdentitySecret().sk,
      ),
    );
  }

  /**
   * Join from a key-in-link invite. The invite's signature and expiry are
   * checked, but whether to trust the INVITER is the application's call — the
   * link is a secret, and anyone who saw it holds the same one.
   */
  async joinWithInvite(text: string): Promise<GroupInvite> {
    const invite = decodeInvite(text);
    const check = checkInvite(invite, Math.floor(this.now() / 1000));
    if (!check.ok) throw new Error(check.reason ?? 'invalid invite');
    if (invite.kind !== InviteKind.KEY_IN_LINK || !invite.epochSecret) {
      throw new Error('this invite carries no key; ask an admin to admit you');
    }
    // Register the key so we can read traffic immediately; the signed state
    // arrives from an admin and replaces this placeholder knowledge.
    await this.storeEpochSecret(invite.groupId, invite.epoch, invite.epochSecret);
    this.registerGroupKeys(deriveGroupEpoch(invite.epochSecret, invite.epoch));
    return invite;
  }

  /** Send a message to a group. One envelope, one proof of work, all members. */
  async sendGroupText(groupId: Uint8Array, text: string, opts: SendTextOptions = {}): Promise<Uint8Array> {
    const body = serializeTextBody({
      text,
      mentions: opts.mentions ?? [],
      attachments: opts.attachments ?? [],
      ...(opts.replyTo ? { replyTo: opts.replyTo } : {}),
    });
    return this.sendGroupFrame(groupId, ChatFrameType.TEXT, body);
  }

  private async sendGroupFrame(groupId: Uint8Array, type: number, body: Uint8Array): Promise<Uint8Array> {
    const state = await this.groupState(groupId);
    if (!state) throw new Error('unknown group');
    const keys = await this.epochKeys(groupId, state.epoch);
    if (!keys) throw new Error('missing epoch secret for this group');

    const dag = await this.dagFor(groupId);
    const frame: ChatFrame = {
      version: 1,
      type,
      convId: groupId,
      timestamp: BigInt(Math.floor(this.now() / 1000)),
      lamport: dag.nextLamport(),
      parents: dag.heads(),
      body,
    };
    const id = chatMessageId(frame);
    await this.ingest(
      { id, sender: decodeIdentity(this.client.identity), frame, receivedAt: this.now() },
      /*local=*/ true,
    );

    const topic = chatTopic(groupId);
    // Signed by our identity so members can attribute it; addressed to the
    // group key so only members can open it.
    // Signed with whatever key this device may use — identity on a primary,
    // device key on a secondary — and addressed to the group key so only
    // members can open it.
    const inner = this.client.signInnerFrame(
      { msgId: randomBytes(16), timestamp: BigInt(Math.floor(this.now() / 1000)), payload: serializeChatFrame(frame) },
      topic,
      keys.eciesPub,
    );
    const outer = serializeUserMsgFrame({ topic, body: inner });
    // Flagged to the GROUP clue key, so any member can retrieve it from an
    // archive after being offline.
    await this.client.bus.send(USER_DATA_KIND, keys.eciesPub, outer, {
      stem: true,
      flag: fmdFlag(parseClueKey(keys.clueKey)),
    });
    return id;
  }

  private async onMembershipFrame(from: string, frame: ChatFrame): Promise<void> {
    let parsed: { state: GroupState; epochSecret: Uint8Array };
    try {
      parsed = parseMembershipBody(frame.body);
    } catch {
      return;
    }
    const { state, epochSecret } = parsed;
    const previous = await this.groupState(state.groupId);
    const check = validateGroupState(state, previous);
    if (!check.ok) {
      // Includes the case that matters most: a state that does not chain to
      // the one we hold, which means either a missed update or an admin
      // showing two different histories. Surface it; do not merge it.
      this.emit('error', new Error(`group state from ${from} rejected: ${check.reason}`));
      return;
    }
    // Only accept membership from someone the previous state says may send it.
    if (previous && !memberOf(state, decodeIdentity(this.client.identity))) {
      // We were removed. Keep the state so the UI can say so, but stop here.
      await this.store.put(NS, `group/${toHex(state.groupId)}/state`, serializeGroupState(state));
      this.emit('group', { groupId: state.groupId, state });
      return;
    }
    await this.adoptGroup(state, epochSecret);
  }

  private async adoptGroup(state: GroupState, epochSecret: Uint8Array): Promise<void> {
    await this.store.put(NS, `group/${toHex(state.groupId)}/state`, serializeGroupState(state));
    await this.storeEpochSecret(state.groupId, state.epoch, epochSecret);
    this.registerGroupKeys(deriveGroupEpoch(epochSecret, state.epoch));
    this.emit('group', { groupId: state.groupId, state });
  }

  private async sendGroupKeys(to: string, state: GroupState, epochSecret: Uint8Array): Promise<void> {
    // Distributed 1:1 over the ratchet, which is what makes a rekey O(n) small
    // messages rather than something the group key could carry.
    await this.sendFrame(to, ChatFrameType.MEMBERSHIP, serializeMembershipBody(state, epochSecret));
  }

  private async storeEpochSecret(groupId: Uint8Array, epoch: number, secret: Uint8Array): Promise<void> {
    await this.store.put(NS, `group/${toHex(groupId)}/epoch/${epoch.toString(16).padStart(8, '0')}`, secret);
  }

  private async epochSecret(groupId: Uint8Array, epoch: number): Promise<Uint8Array | undefined> {
    return this.store.get(NS, `group/${toHex(groupId)}/epoch/${epoch.toString(16).padStart(8, '0')}`);
  }

  /**
   * Detection keys for every group epoch we hold, at `precision`.
   *
   * A rekey changes the group's clue key, so catching up across one means
   * querying with the detection key of each epoch involved — a single key
   * would silently miss everything sent under the others.
   */
  async groupDetectionKeys(precision = 8): Promise<Uint8Array[]> {
    const out: Uint8Array[] = [];
    for (const state of await this.groups()) {
      const prefix = `group/${toHex(state.groupId)}/epoch/`;
      for (const e of await this.store.list(NS, prefix)) {
        const epoch = parseInt(e.key.slice(prefix.length), 16);
        try {
          out.push(extractDetectionKey(deriveGroupEpoch(e.value, epoch).fmd, precision));
        } catch {
          // Unreadable epoch record: skip it rather than fail the sync.
        }
      }
    }
    return out;
  }

  private async epochKeys(groupId: Uint8Array, epoch: number): Promise<GroupEpochKeys | undefined> {
    const secret = await this.epochSecret(groupId, epoch);
    return secret ? deriveGroupEpoch(secret, epoch) : undefined;
  }

  private registerGroupKeys(keys: GroupEpochKeys): void {
    // The bus already trial-decrypts session keys, so a group key needs no new
    // machinery below this layer — only a note that it is SHARED, so inbound
    // frames are authenticated against the group key rather than our identity
    // and are not individually acked.
    this.client.registerSharedKey(keys.eciesSk, keys.eciesPub);
  }

  /**
   * Re-register every group's keys. Called at construction so a restart does
   * not silently stop decrypting group traffic.
   */
  private async loadGroups(): Promise<void> {
    for (const state of await this.groups()) {
      const keys = await this.epochKeys(state.groupId, state.epoch);
      if (keys) this.registerGroupKeys(keys);
    }
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

// ---------------------------------------------------------------------------
// Groups
//
// A group message is ECIES'd to a MEMBER-ONLY key, not published on a
// broadcast topic. Broadcast scope encrypts to the generator, so anyone on the
// bus could read the topic field and watch the group's activity timeline even
// without the content. Encrypting the envelope to the group key keeps the
// topic itself secret, and still costs one envelope and one proof of work
// regardless of how many members there are.

/** Body of a MEMBERSHIP frame: the new state, and the epoch secret it needs. */
function serializeMembershipBody(state: GroupState, epochSecret: Uint8Array): Uint8Array {
  return new Writer().u8(1).varBytes(serializeGroupState(state)).bytes(epochSecret).finish();
}

function parseMembershipBody(bytes: Uint8Array): { state: GroupState; epochSecret: Uint8Array } {
  const r = new Reader(bytes);
  if (r.u8() !== 1) throw new Error('unknown membership body version');
  const state = parseGroupState(r.varBytes());
  const epochSecret = r.bytes(32).slice();
  r.assertDone();
  return { state, epochSecret };
}

/**
 * The proof of authorship an inbound message carries, if any, in the shape
 * `StoredMessage` keeps it. A message that was unsigned or chunked has none,
 * and history without it is still history — it just cannot prove itself to
 * another device.
 */
function proof(m: IncomingMessage): { signed?: Uint8Array; signedFor?: Uint8Array } {
  return m.signed && m.signedFor ? { signed: m.signed, signedFor: m.signedFor } : {};
}
