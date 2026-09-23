import { describe, expect, it } from 'vitest';
import { randomBytes, toHex, utf8 } from '../common/bytes.js';
import { loopbackPair } from './transport.js';
import {
  BackfillClient,
  BackfillServer,
  parseSyncMessage,
  serializeSyncMessage,
  SyncOp,
  SYNC_BATCH_SIZE,
  type SyncEntry,
  type SyncMessage,
  verifyEntry,
} from './backfill.js';
import { ChatFrameType, chatMessageId, serializeChatFrame, serializeTextBody, type ChatFrame } from '../chat/frame.js';
import { deriveIdentity } from '../usermsg/keyring.js';
import { signAuthFrame } from '../usermsg/auth.js';
import { MSG_ID_BYTES } from '../usermsg/frame.js';

const alice = deriveIdentity(new Uint8Array(32).fill(3));
const mallory = deriveIdentity(new Uint8Array(32).fill(4));
const convId = new Uint8Array(32).fill(9);
const topic = 'chat/test';
const recipient = deriveIdentity(new Uint8Array(32).fill(5)).pub;

function frameOf(text: string, lamport: bigint): ChatFrame {
  return {
    version: 1,
    type: ChatFrameType.TEXT,
    convId,
    timestamp: 100n,
    lamport,
    parents: [],
    body: serializeTextBody({ text, mentions: [], attachments: [] }),
  };
}

/** A history entry as it would have been stored from a real inbound message. */
function signedEntry(text: string, lamport: bigint, signer = alice): SyncEntry {
  const frame = serializeChatFrame(frameOf(text, lamport));
  const signed = signAuthFrame(
    { msgId: randomBytes(MSG_ID_BYTES), timestamp: 100n, payload: frame },
    signer,
    topic,
    recipient,
  );
  return { frame, sender: signer.pub, receivedAt: 1000, signed, signedFor: recipient };
}

function pair(entries: SyncEntry[]) {
  const [a, b] = loopbackPair();
  const server = new BackfillServer(a.channel('control'), {
    history: (_id, fromLamport, limit) =>
      Promise.resolve(entries.filter((_e, i) => BigInt(i + 1) >= fromLamport).slice(0, limit)),
  });
  const client = new BackfillClient(b.channel('control'), () => topic);
  return { server, client };
}

describe('history backfill', () => {
  it('carries history a device can verify for itself', async () => {
    const { client } = pair([signedEntry('first', 1n), signedEntry('second', 2n)]);
    const res = await client.fetch(convId, { timeoutMs: 10000 });
    expect(res.verified).toHaveLength(2);
    expect(res.unverified).toHaveLength(0);
    expect(res.rejected).toBe(0);
  });

  it('drops an entry whose frame was swapped under a real signature', async () => {
    const good = signedEntry('what alice said', 1n);
    // Same signature, different content: the classic forgery a device relaying
    // somebody else's history would attempt.
    const tampered: SyncEntry = { ...good, frame: serializeChatFrame(frameOf('what alice did not say', 1n)) };
    const { client } = pair([tampered]);
    const res = await client.fetch(convId, { timeoutMs: 10000 });
    expect(res.verified).toHaveLength(0);
    expect(res.rejected).toBe(1);
  });

  it('drops an entry signed by somebody other than the sender it claims', async () => {
    const forged: SyncEntry = { ...signedEntry('trust me', 1n, mallory), sender: alice.pub };
    const { client } = pair([forged]);
    const res = await client.fetch(convId, { timeoutMs: 10000 });
    expect(res.rejected).toBe(1);
  });

  it('accepts an entry with no proof, and says so', async () => {
    // Our own sent messages, and anything stored before signatures were kept.
    const bare: SyncEntry = { frame: serializeChatFrame(frameOf('ours', 1n)), receivedAt: 1 };
    const { client } = pair([bare]);
    const res = await client.fetch(convId, { timeoutMs: 10000 });
    expect(res.verified).toHaveLength(0);
    expect(res.unverified).toHaveLength(1);
  });

  it('batches a long history and still completes', async () => {
    // Entries with no proof: batching is about how the frames are cut into
    // messages, not about what is in them, and a signature check per entry
    // would make this test hundreds of BLS verifications long for nothing.
    // Verification has its own cases above.
    const many = Array.from({ length: SYNC_BATCH_SIZE * 2 + 5 }, (_, i) => ({
      frame: serializeChatFrame(frameOf(`m${i}`, BigInt(i + 1))),
      receivedAt: 1000 + i,
    }));
    const { client } = pair(many);
    const res = await client.fetch(convId, { timeoutMs: 20000, limit: many.length });
    expect(res.unverified).toHaveLength(many.length);
    // The order the server sent them in survives the batching.
    expect(res.unverified.map((e) => e.receivedAt)).toEqual(many.map((e) => e.receivedAt));
  });

  it('refuses two fetches at once and times out with no server', async () => {
    const [, b] = loopbackPair();
    const client = new BackfillClient(b.channel('control'), () => topic);
    const first = client.fetch(convId, { timeoutMs: 500 });
    await expect(client.fetch(convId, { timeoutMs: 500 })).rejects.toThrow(/already in flight/);
    await expect(first).rejects.toThrow(/timed out/);
  });

  it('surfaces a denial as an error', async () => {
    const [a, b] = loopbackPair();
    new BackfillServer(a.channel('control'), {
      history: () => Promise.reject(new Error('no such conversation')),
    });
    const client = new BackfillClient(b.channel('control'), () => topic);
    await expect(client.fetch(convId, { timeoutMs: 10000 })).rejects.toThrow(/no such conversation/);
  });

  it('round trips every sync message', () => {
    const msgs: SyncMessage[] = [
      { op: SyncOp.REQUEST, convId, fromLamport: 7n, limit: 40 },
      { op: SyncOp.BATCH, convId, entries: [signedEntry('x', 1n), { frame: utf8('raw'), receivedAt: 5 }] },
      { op: SyncOp.DONE, convId },
      { op: SyncOp.DENY, convId, reason: 'nope' },
    ];
    for (const m of msgs) {
      expect(parseSyncMessage(serializeSyncMessage(m))).toEqual(m);
    }
    expect(() => parseSyncMessage(new Uint8Array([99, ...new Uint8Array(32)]))).toThrow(/unknown sync op/);
  });

  it('verifyEntry refuses a frame bound to a different topic', () => {
    const e = signedEntry('hello', 1n);
    expect(verifyEntry(e, topic)).toBe(true);
    expect(verifyEntry(e, 'chat/other')).toBe(false);
    expect(verifyEntry({ ...e, signedFor: alice.pub }, topic)).toBe(false);
  });

  it('message ids survive the trip, so a backfilled frame dedups against a live one', () => {
    const f = frameOf('same', 1n);
    const e = signedEntry('same', 1n);
    expect(toHex(chatMessageId(f))).toBe(toHex(chatMessageId(frameOf('same', 1n))));
    expect(e.frame).toEqual(serializeChatFrame(f));
  });
});
