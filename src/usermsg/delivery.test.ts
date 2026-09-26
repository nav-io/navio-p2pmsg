import { describe, expect, it } from 'vitest';
import { ACK_WHOLE, parseAcks, serializeAcks, TOPIC_PREKEY_REQUEST } from './topics.js';
import { PayloadTooLargeError, Reassembler, chunkCapacity, splitChunks } from './chunker.js';
import { Outbox } from './outbox.js';
import { MemoryStore } from '../stores/memory-store.js';
import { MAX_TOPIC_BYTES, serializeAuthFrame, serializeUserMsgFrame } from './frame.js';

describe('topics', () => {
  it('the prekey request topic is fixed, and names nobody', () => {
    // It used to be `_p2pmsg/prekey/<hash of the identity>` on a broadcast,
    // which anyone holding the address could precompute and watch for. A fixed
    // topic inside an envelope addressed to the identity key names no one.
    expect(TOPIC_PREKEY_REQUEST).toBe('_p2pmsg/prekeyreq');
    expect(new TextEncoder().encode(TOPIC_PREKEY_REQUEST).length).toBeLessThanOrEqual(MAX_TOPIC_BYTES);
  });
  it('ack codec round trips', () => {
    const acks = [
      { msgId: new Uint8Array(16).fill(1), chunkIdx: ACK_WHOLE },
      { msgId: new Uint8Array(16).fill(2), chunkIdx: 3 },
    ];
    expect(parseAcks(serializeAcks(acks))).toEqual(acks);
  });
});

describe('chunker', () => {
  it('capacity really fits a max-overhead frame in a USER_DATA frame', () => {
    const topic = 'x'.repeat(64);
    const cap = chunkCapacity(topic);
    const inner = serializeAuthFrame({
      msgId: new Uint8Array(16),
      timestamp: 0n,
      sender: new Uint8Array(48),
      sig: new Uint8Array(96),
      replyPub: new Uint8Array(48),
      chunk: { idx: 0, total: 2 },
      payload: new Uint8Array(cap),
    });
    expect(() => serializeUserMsgFrame({ topic, body: inner })).not.toThrow();
    expect(serializeUserMsgFrame({ topic, body: inner }).length).toBeLessThanOrEqual(3584);
  });
  it('splits and reassembles', () => {
    const cap = chunkCapacity('t');
    const payload = new Uint8Array(cap * 2 + 5).map((_, i) => i & 0xff);
    const chunks = splitChunks(payload, 't', 16);
    expect(chunks.length).toBe(3);
    const r = new Reassembler();
    const id = new Uint8Array(16).fill(9);
    expect(r.add(id, undefined, 2, 3, chunks[2]!)).toBeUndefined();
    expect(r.add(id, undefined, 0, 3, chunks[0]!)).toBeUndefined();
    expect(r.add(id, undefined, 0, 3, chunks[0]!)).toBeUndefined(); // dup
    expect(r.add(id, undefined, 1, 3, chunks[1]!)).toEqual(payload);
    expect(() => splitChunks(new Uint8Array(cap * 17), 't', 16)).toThrow(PayloadTooLargeError);
  });
  it('reassembler expires stale partials', () => {
    let t = 0;
    const r = new Reassembler({ ttlMs: 100, now: () => t });
    const id = new Uint8Array(16);
    r.add(id, undefined, 0, 2, new Uint8Array([1]));
    t = 200;
    // sweep happens on next add; the old partial is gone so total 2 restarts
    expect(r.add(id, undefined, 1, 2, new Uint8Array([2]))).toBeUndefined();
    expect(r.add(id, undefined, 0, 2, new Uint8Array([1]))).toEqual(new Uint8Array([1, 2]));
  });
});

describe('outbox', () => {
  it('schedules retries, acks chunks, expires, persists', async () => {
    let now = 1_000_000;
    const store = new MemoryStore();
    const ob = new Outbox(store, { now: () => now, ttlMs: 10_000, backoffBaseMs: 100, backoffCapMs: 1000 });
    const id = new Uint8Array(16).fill(3);
    await ob.add({ msgId: id, recipient: new Uint8Array(48), topic: 'msg', chunks: [new Uint8Array([1]), new Uint8Array([2])] });
    let d = await ob.due();
    expect(d.due.length).toBe(1);
    await ob.markSent(id);
    d = await ob.due();
    expect(d.due.length).toBe(0);
    now += 130; // within jitter of 100ms base
    d = await ob.due();
    expect(d.due.length).toBe(1);
    expect(await ob.ack(id, 0)).toBeUndefined();
    expect(ob.pendingChunks(ob.get(id)!)).toEqual([1]);
    // reload from store
    const ob2 = new Outbox(store, { now: () => now });
    await ob2.load();
    expect(ob2.get(id)?.acked).toEqual([true, false]);
    expect(ob2.get(id)?.attempts).toBe(1);
    const done = await ob2.ack(id, 1);
    expect(done?.msgId).toEqual(id);
    expect(ob2.size).toBe(0);
    expect(await store.list('outbox')).toEqual([]);
    // expiry
    await ob.add({ msgId: new Uint8Array(16).fill(4), recipient: new Uint8Array(48), topic: 'msg', chunks: [new Uint8Array(1)] });
    now += 20_000;
    d = await ob.due();
    // id=4 expired, and the id=3 entry still cached in `ob` (ob2 removed it from the store) expired too
    expect(d.expired.length).toBe(2);
    expect(d.due.length).toBe(0);
  });
});
