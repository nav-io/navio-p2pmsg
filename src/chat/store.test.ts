import { describe, expect, it } from 'vitest';
import { randomBytes, toHex } from '../common/bytes.js';
import { MemoryStore } from '../stores/memory-store.js';
import {
  type ChatFrame,
  ChatFrameType,
  chatMessageId,
  serializeDeleteBody,
  serializeEditBody,
  serializeReactionBody,
  serializeTextBody,
} from './frame.js';
import { ChatStore, type StoredMessage } from './store.js';

const CONV = new Uint8Array(32).fill(7);
const ALICE = new Uint8Array(48).fill(1);
const BOB = new Uint8Array(48).fill(2);

let clock = 1000;

function msg(
  type: number,
  body: Uint8Array,
  lamport: number,
  sender: Uint8Array | undefined,
  parents: Uint8Array[] = [],
): StoredMessage {
  const frame: ChatFrame = {
    version: 1,
    type,
    convId: CONV,
    timestamp: BigInt(1700000000 + lamport),
    lamport: BigInt(lamport),
    parents,
    body,
  };
  const out: StoredMessage = { id: chatMessageId(frame), frame, receivedAt: clock++ };
  if (sender) out.sender = sender;
  return out;
}

function text(t: string, lamport: number, sender = ALICE, parents: Uint8Array[] = []): StoredMessage {
  return msg(ChatFrameType.TEXT, serializeTextBody({ text: t, mentions: [], attachments: [] }), lamport, sender, parents);
}

const mk = (): ChatStore => new ChatStore(new MemoryStore());

describe('ChatStore', () => {
  it('stores and reads back a message', async () => {
    const s = mk();
    const m = text('hello', 1);
    expect(await s.putMessage(m)).toBe(true);
    const got = await s.getMessage(m.id);
    expect(got?.frame.body).toEqual(m.frame.body);
    expect(got?.sender).toEqual(ALICE);
  });

  it('treats a duplicate as a no-op', async () => {
    // The same message can arrive live, from the archive and from a device
    // mirror; content addressing makes dedupe free.
    const s = mk();
    const m = text('hello', 1);
    expect(await s.putMessage(m)).toBe(true);
    expect(await s.putMessage(m)).toBe(false);
    expect(await s.messages(CONV)).toHaveLength(1);
  });

  it('orders stored messages by lamport, not insertion order', async () => {
    const s = mk();
    await s.putMessage(text('third', 3));
    await s.putMessage(text('first', 1));
    await s.putMessage(text('second', 2));
    const view = await s.view(CONV);
    expect(view.messages.map((m) => m.text)).toEqual(['first', 'second', 'third']);
  });

  it('keeps lamport order past a power of ten', async () => {
    // Lamport keys are zero-padded hex; unpadded, "10" would sort before "9".
    const s = mk();
    for (const n of [9, 10, 11, 255, 256]) await s.putMessage(text(`m${n}`, n));
    const view = await s.view(CONV);
    expect(view.messages.map((m) => m.text)).toEqual(['m9', 'm10', 'm11', 'm255', 'm256']);
  });

  it('applies an edit from the original author', async () => {
    const s = mk();
    const original = text('typo', 1);
    await s.putMessage(original);
    await s.putMessage(msg(ChatFrameType.EDIT, serializeEditBody({ target: original.id, text: 'fixed' }), 2, ALICE, [original.id]));
    const view = await s.view(CONV);
    expect(view.messages).toHaveLength(1);
    expect(view.messages[0]!.text).toBe('fixed');
    expect(view.messages[0]!.edited).toBe(true);
  });

  it('ignores an edit from anyone but the author', async () => {
    // Otherwise anyone who can reach the conversation could rewrite someone
    // else's words.
    const s = mk();
    const original = text('mine', 1, ALICE);
    await s.putMessage(original);
    await s.putMessage(msg(ChatFrameType.EDIT, serializeEditBody({ target: original.id, text: 'forged' }), 2, BOB, [original.id]));
    const view = await s.view(CONV);
    expect(view.messages[0]!.text).toBe('mine');
    expect(view.messages[0]!.edited).toBe(false);
  });

  it('resolves competing edits by causal order, not arrival order', async () => {
    const s = mk();
    const original = text('v0', 1);
    await s.putMessage(original);
    const later = msg(ChatFrameType.EDIT, serializeEditBody({ target: original.id, text: 'v2' }), 5, ALICE, [original.id]);
    const earlier = msg(ChatFrameType.EDIT, serializeEditBody({ target: original.id, text: 'v1' }), 3, ALICE, [original.id]);
    // Deliver the later edit first.
    await s.putMessage(later);
    await s.putMessage(earlier);
    expect((await s.view(CONV)).messages[0]!.text).toBe('v2');
  });

  it('tombstones a delete from the author and drops its content', async () => {
    const s = mk();
    const original = text('secret', 1);
    await s.putMessage(original);
    await s.putMessage(msg(ChatFrameType.DELETE, serializeDeleteBody({ target: original.id }), 2, ALICE, [original.id]));
    const view = await s.view(CONV);
    expect(view.messages[0]!.deleted).toBe(true);
    expect(view.messages[0]!.text).toBe('');
  });

  it('ignores a delete from anyone but the author', async () => {
    const s = mk();
    const original = text('mine', 1, ALICE);
    await s.putMessage(original);
    await s.putMessage(msg(ChatFrameType.DELETE, serializeDeleteBody({ target: original.id }), 2, BOB, [original.id]));
    expect((await s.view(CONV)).messages[0]!.deleted).toBe(false);
  });

  it('adds and removes reactions, last write per reactor wins', async () => {
    const s = mk();
    const target = text('nice', 1);
    await s.putMessage(target);
    await s.putMessage(msg(ChatFrameType.REACTION, serializeReactionBody({ target: target.id, emoji: '👍', add: true }), 2, BOB, [target.id]));
    await s.putMessage(msg(ChatFrameType.REACTION, serializeReactionBody({ target: target.id, emoji: '👍', add: true }), 3, ALICE, [target.id]));
    let view = await s.view(CONV);
    expect(view.messages[0]!.reactions.get('👍')).toHaveLength(2);

    await s.putMessage(msg(ChatFrameType.REACTION, serializeReactionBody({ target: target.id, emoji: '👍', add: false }), 4, BOB, [target.id]));
    view = await s.view(CONV);
    expect(view.messages[0]!.reactions.get('👍')).toEqual([toHex(ALICE)]);
  });

  it('drops an emoji entirely once the last reactor removes it', async () => {
    const s = mk();
    const target = text('nice', 1);
    await s.putMessage(target);
    await s.putMessage(msg(ChatFrameType.REACTION, serializeReactionBody({ target: target.id, emoji: '🎉', add: true }), 2, BOB, [target.id]));
    await s.putMessage(msg(ChatFrameType.REACTION, serializeReactionBody({ target: target.id, emoji: '🎉', add: false }), 3, BOB, [target.id]));
    expect((await s.view(CONV)).messages[0]!.reactions.has('🎉')).toBe(false);
  });

  it('tolerates a mutation whose target never arrives', async () => {
    const s = mk();
    await s.putMessage(msg(ChatFrameType.EDIT, serializeEditBody({ target: randomBytes(32), text: 'x' }), 1, ALICE));
    const view = await s.view(CONV);
    expect(view.messages).toHaveLength(0); // nothing to render, and no throw
  });

  it('surfaces a gap for a cited parent it does not hold', async () => {
    const s = mk();
    const missing = randomBytes(32);
    await s.putMessage(text('after', 5, ALICE, [missing]));
    const view = await s.view(CONV);
    expect(view.gaps).toHaveLength(1);
    expect(toHex(view.gaps[0]!.id)).toBe(toHex(missing));
  });

  it('persists and clears recorded gaps', async () => {
    const s = mk();
    const missing = randomBytes(32);
    await s.recordGap(CONV, missing);
    expect((await s.gaps(CONV)).map(toHex)).toEqual([toHex(missing)]);
    // Storing the message itself resolves it.
    const m = text('the missing one', 4);
    await s.recordGap(CONV, m.id);
    await s.putMessage(m);
    expect((await s.gaps(CONV)).map(toHex)).toEqual([toHex(missing)]);
  });

  it('round trips conversation metadata', async () => {
    const s = mk();
    const empty = await s.meta(CONV);
    expect(empty.unread).toBe(0);
    expect(empty.readHeads).toEqual([]);

    const head = randomBytes(32);
    await s.setMeta({ convId: CONV, lastActivityAt: 12345, readHeads: [head], unread: 3 });
    const got = await s.meta(CONV);
    expect(got.unread).toBe(3);
    expect(got.lastActivityAt).toBe(12345);
    expect(got.readHeads.map(toHex)).toEqual([toHex(head)]);
    expect((await s.conversations()).map(toHex)).toEqual([toHex(CONV)]);
  });

  it('rebuilds a DAG whose heads are ready to parent the next send', async () => {
    const s = mk();
    const a = text('a', 1);
    await s.putMessage(a);
    await s.putMessage(text('b', 2, ALICE, [a.id]));
    const dag = await s.dag(CONV);
    expect(dag.size).toBe(2);
    expect(dag.nextLamport()).toBe(3n);
    expect(dag.heads()).toHaveLength(1);
  });
});
