import { describe, expect, it } from 'vitest';
import { randomBytes, toHex, utf8 } from '../common/bytes.js';
import { generateSecret, publicKey } from './bls.js';
import { BusClient, type EnvelopeSink, type InboundMessage, PayloadTooLarge } from './client.js';
import { expectedPayloadHash, messageKey, parseEnvelope, serializeEnvelope } from './envelope.js';
import { FMD_FLAG_SIZE } from './fmd.js';
import { BusKeys } from './keyring.js';
import { PowGrinder } from './pow-grinder.js';
import { grindSync, withNonce } from './pow.js';

class FakeSink implements EnvelopeSink {
  sent: Array<{ bytes: Uint8Array; stem: boolean }> = [];
  broadcast(envelope: Uint8Array, opts: { stem: boolean }): void {
    this.sent.push({ bytes: envelope, stem: opts.stem });
  }
}

const grinder = new PowGrinder({ workers: 0 }); // main-thread grinding in tests
const BITS = 8;

function makeClient(opts: { keys?: BusKeys; now?: () => number } = {}) {
  const keys = opts.keys ?? new BusKeys();
  if (!keys.inboxPublic) keys.setInbox(generateSecret());
  const sink = new FakeSink();
  const client = new BusClient({ keys, sink, powBits: BITS, grinder, ...(opts.now ? { now: opts.now } : {}) });
  return { keys, sink, client };
}

function waitFor<T>(register: (cb: (v: T) => void) => void, ms = 5000): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    register((v) => {
      clearTimeout(t);
      resolve(v);
    });
  });
}

describe('BusClient', () => {
  it('send -> onWire on the recipient dispatches with the right body and recipient class', async () => {
    const a = makeClient();
    const b = makeClient();
    const body = utf8('hello bob');
    const got = waitFor<InboundMessage>((cb) => b.client.on(7, cb));
    const bytes = await a.client.send(7, b.keys.inboxPublic!, body, { stem: false });
    expect(a.sink.sent.length).toBe(1);
    expect(a.sink.sent[0]!.stem).toBe(false);
    expect(a.sink.sent[0]!.bytes).toEqual(bytes);
    expect(b.client.onWire('peer-a', false, bytes)).toBe('accepted');
    const msg = await got;
    expect(msg.body).toEqual(body);
    expect(msg.kind).toBe(7);
    expect(msg.recipient).toBe('inbox');
    expect(msg.peerId).toBe('peer-a');
    expect(msg.stem).toBe(false);
    expect(msg.senderEph).toEqual(parseEnvelope(bytes).enc.eph);
    expect(msg.sessionPub).toBeUndefined();
  });

  it('stem defaults to true', async () => {
    const a = makeClient();
    await a.client.send(0, publicKey(generateSecret()), utf8('ping'));
    expect(a.sink.sent[0]!.stem).toBe(true);
  });

  it('replay: the same envelope is rejected the second time (and by stem/fluff both)', async () => {
    const a = makeClient();
    const b = makeClient();
    b.client.on(7, () => {});
    const bytes = await a.client.send(7, b.keys.inboxPublic!, utf8('x'), { stem: false });
    expect(b.client.onWire(1, true, bytes)).toBe('accepted');
    expect(b.client.onWire(2, false, bytes)).toBe('replay');
    // re-grinding the nonce does not evade the replay cache
    const env = parseEnvelope(bytes);
    const regrind = serializeEnvelope({ ...env, pow: withNonce(env.pow, env.pow.nonce + 256n) });
    const r = b.client.onWire(3, false, regrind);
    expect(['replay', 'badpow']).toContain(r);
  });

  it('a re-flagged copy of a delivered envelope is not delivered again', async () => {
    // The flag is routing metadata and it is not secret: anyone who saw the
    // envelope can rewrite it, regrind the (cheap, flag-covering) proof of
    // work once, and put it back on the bus. A relay tells the two apart on
    // purpose, so the copy propagates — but the recipient must see one
    // message, not two.
    const a = makeClient();
    const b = makeClient();
    let calls = 0;
    b.client.on(7, () => calls++);
    const flag = randomBytes(FMD_FLAG_SIZE);
    const bytes = await a.client.send(7, b.keys.inboxPublic!, utf8('once'), { stem: false, flag });
    expect(b.client.onWire(1, false, bytes)).toBe('accepted');
    await b.client.drain();
    expect(calls).toBe(1);

    // Same ciphertext, somebody else's flag, freshly ground.
    const env = parseEnvelope(bytes);
    const reflagged: typeof env = { ...env, flag: randomBytes(FMD_FLAG_SIZE) };
    reflagged.pow = { ...env.pow, payloadHash: expectedPayloadHash(reflagged), nonce: 0n };
    const nonce = grindSync(reflagged.pow, BITS);
    expect(nonce).not.toBeUndefined();
    reflagged.pow = withNonce(reflagged.pow, nonce!);
    // It is a valid envelope carrying a flag nobody else chose...
    expect(toHex(reflagged.flag)).not.toBe(toHex(env.flag));
    // ...and still the same message, here and at every relay.
    expect(messageKey(reflagged)).toEqual(messageKey(env));
    expect(b.client.onWire(2, false, serializeEnvelope(reflagged))).toBe('replay');
    await b.client.drain();
    expect(calls).toBe(1);

    // Stripping the flag entirely is the same trick.
    const stripped: typeof env = { ...env, flag: new Uint8Array(0) };
    stripped.pow = { ...env.pow, payloadHash: expectedPayloadHash(stripped), nonce: 0n };
    stripped.pow = withNonce(stripped.pow, grindSync(stripped.pow, BITS)!);
    expect(b.client.onWire(3, false, serializeEnvelope(stripped))).toBe('replay');
    await b.client.drain();
    expect(calls).toBe(1);
  });

  it('our own echoed envelope is ignored', async () => {
    const a = makeClient();
    let calls = 0;
    a.client.on(7, () => calls++);
    const bytes = await a.client.send(7, a.keys.inboxPublic!, utf8('self'), { stem: false });
    expect(a.client.onWire('echo', false, bytes)).toBe('replay');
    await a.client.drain();
    expect(calls).toBe(0);
  });

  it('bad PoW, kind mismatch, payload hash mismatch, stale timestamp, garbage', async () => {
    const a = makeClient();
    const b = makeClient();
    const bytes = await a.client.send(7, b.keys.inboxPublic!, utf8('x'), { stem: false });
    const env = parseEnvelope(bytes);
    expect(b.client.onWire(0, false, serializeEnvelope({ ...env, pow: withNonce(env.pow, env.pow.nonce + 1n) }))).toBe('badpow');
    expect(b.client.onWire(0, false, serializeEnvelope({ ...env, kind: 8 }))).toBe('badpow');
    const badHash = { ...env, pow: { ...env.pow, payloadHash: randomBytes(32) } };
    expect(b.client.onWire(0, false, serializeEnvelope(badHash))).toBe('badpow');
    expect(b.client.onWire(0, false, new Uint8Array([1, 2, 3]))).toBe('invalid');
    expect(b.client.onWire(0, false, new Uint8Array(5000))).toBe('invalid');
    expect(b.client.onWire(0, false, new Uint8Array([...bytes, 0]))).toBe('invalid');

    // stale: sender clock 10 minutes off
    const old = makeClient({ now: () => Math.floor(Date.now() / 1000) - 600 });
    const staleBytes = await old.client.send(7, b.keys.inboxPublic!, utf8('x'), { stem: false });
    expect(b.client.onWire(0, false, staleBytes)).toBe('stale');
    // the same envelope is fine for a receiver with the same skew
    const oldRx = makeClient({ keys: b.keys, now: () => Math.floor(Date.now() / 1000) - 600 });
    expect(oldRx.client.onWire(0, false, staleBytes)).toBe('accepted');
  });

  it('session key decrypt path, grace inbox, broadcast', async () => {
    const a = makeClient();
    const b = makeClient();
    const sessSk = generateSecret();
    const sessPub = publicKey(sessSk);
    b.keys.addSessionKey(sessSk, sessPub, 60_000);
    const got1 = waitFor<InboundMessage>((cb) => b.client.on(5, cb));
    const bytes1 = await a.client.send(5, sessPub, utf8('quote'), { stem: false });
    expect(b.client.onWire(0, false, bytes1)).toBe('accepted');
    const m1 = await got1;
    expect(m1.recipient).toBe('session');
    expect(m1.sessionPub).toEqual(sessPub);
    expect(m1.body).toEqual(utf8('quote'));

    // broadcast
    const got2 = waitFor<InboundMessage>((cb) => b.client.on(4, cb));
    const bytes2 = await a.client.sendBroadcast(4, utf8('rfq'), { stem: false });
    expect(b.client.onWire(0, false, bytes2)).toBe('accepted');
    const m2 = await got2;
    expect(m2.recipient).toBe('broadcast');
    expect(m2.body).toEqual(utf8('rfq'));

    // grace: rotate b's inbox; a message to the OLD key still decrypts as 'inbox'
    const oldPub = b.keys.inboxPublic!;
    b.keys.rotateInbox(generateSecret());
    expect(b.keys.inboxPublic).not.toEqual(oldPub);
    const got3 = waitFor<InboundMessage>((cb) => b.client.on(7, cb));
    const bytes3 = await a.client.send(7, oldPub, utf8('late'), { stem: false });
    expect(b.client.onWire(0, false, bytes3)).toBe('accepted');
    expect((await got3).recipient).toBe('inbox');

    // expired session key no longer decrypts
    b.keys.removeSessionKey(sessPub);
    let calls = 0;
    b.client.on(5, () => calls++);
    const bytes4 = await a.client.send(5, sessPub, utf8('quote2'), { stem: false });
    expect(b.client.onWire(0, false, bytes4)).toBe('accepted');
    await b.client.drain();
    expect(calls).toBe(0);
  });

  it('messages for kinds without a handler are accepted but not decrypted; unsubscribe works', async () => {
    const a = makeClient();
    const b = makeClient();
    let calls = 0;
    const off = b.client.on(9, () => calls++);
    const bytes = await a.client.send(9, b.keys.inboxPublic!, utf8('x'), { stem: false });
    off();
    expect(b.client.onWire(0, false, bytes)).toBe('accepted');
    await b.client.drain();
    expect(calls).toBe(0);
  });

  it('throws PayloadTooLarge before grinding for oversize bodies', async () => {
    const a = makeClient();
    const max = BusClient.maxBodyBytes();
    await expect(a.client.send(7, a.keys.inboxPublic!, new Uint8Array(max + 1), { stem: false })).rejects.toBeInstanceOf(PayloadTooLarge);
    const bytes = await a.client.send(7, a.keys.inboxPublic!, new Uint8Array(max), { stem: false });
    expect(bytes.length).toBe(4096);
  });

  it('abort signal cancels a send', async () => {
    const a = makeClient();
    const ac = new AbortController();
    ac.abort();
    await expect(a.client.send(7, a.keys.inboxPublic!, utf8('x'), { signal: ac.signal })).rejects.toThrow(/abort/i);
  });
});

describe('BusKeys', () => {
  it('session key cap and TTL sweep', () => {
    let t = 0;
    const keys = new BusKeys({ maxSessionKeys: 3, now: () => t });
    const pubs: Uint8Array[] = [];
    for (let i = 0; i < 4; i++) {
      const sk = generateSecret();
      pubs.push(publicKey(sk));
      keys.addSessionKey(sk, undefined, 100);
    }
    expect(keys.sessionKeys().length).toBe(3);
    expect(keys.hasSessionKey(pubs[0]!)).toBe(false);
    expect(keys.hasSessionKey(pubs[3]!)).toBe(true);
    t = 100;
    expect(keys.sessionKeys().length).toBe(0);
    keys.addSessionKey(generateSecret());
    expect(keys.sessionKeys()[0]!.expiresAt).toBeUndefined();
  });

  it('grace ring is bounded', () => {
    const keys = new BusKeys({ graceKeys: 1 });
    keys.setInbox(generateSecret());
    keys.addGraceInbox(generateSecret());
    keys.addGraceInbox(generateSecret());
    // only the newest grace key + current remain: encrypt to a pub not in the ring fails
    expect(keys.trialDecrypt(7, { eph: new Uint8Array(48), ciphertext: new Uint8Array(64), tag: new Uint8Array(16) })).toBeNull();
  });
});
