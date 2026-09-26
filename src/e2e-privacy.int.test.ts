/**
 * End-to-end: what a node can and cannot learn.
 *
 * Everything else in this repo tests that messages arrive. This tests the
 * claims that make arriving worth anything — that the bus carries no
 * addressing, that two messages to one person do not look related, that an
 * archiving node holding a detection key still cannot say which envelopes are
 * yours, and that a relay sees ciphertext and nothing else.
 *
 * Observations are made from the wire, by a third client that reads every
 * envelope the node floods to it. That is exactly the vantage point a curious
 * peer has, which is the point.
 *
 * Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from './usermsg/client.js';
import { MemoryStore } from './stores/memory-store.js';
import { type Store } from './stores/store.js';
import { equal, fromHex, toHex, utf8 } from './common/bytes.js';
import { ServiceFlags } from './net/messages.js';
import { type Envelope, parseEnvelope } from './bus/envelope.js';
import { FMD_GAMMA, fmdTest } from './bus/fmd.js';
import { sha256 } from '@noble/hashes/sha256';
import { BROADCAST_SECRET } from './bus/bls.js';
import { decrypt } from './bus/ecies.js';
import { parseUserMsgFrame } from './usermsg/frame.js';
import { decodeIdentity } from './usermsg/bundle.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<K extends keyof MessagingEvents>(
  client: MessagingClient,
  ev: K,
  pred: (v: MessagingEvents[K]) => boolean = () => true,
  ms = 90000,
): Promise<MessagingEvents[K]> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      off();
      reject(new Error(`timeout waiting for ${String(ev)}`));
    }, ms);
    const off = client.on(ev, (v) => {
      if (pred(v)) {
        clearTimeout(t);
        off();
        resolve(v);
      }
    });
  });
}

async function waitUntil(pred: () => Promise<boolean> | boolean, ms = 60000): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** Does `haystack` contain `needle` anywhere, at any offset? */
function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

describe.skipIf(!haveBinary)('end to end: what a node can and cannot learn', () => {
  let node: RegtestNode;
  const open: Array<{ close(): void }> = [];

  async function account(seedByte: number, store: Store = new MemoryStore()) {
    const client = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(seedByte),
      store,
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      ackDelayMs: 100,
      retryTickMs: 1000,
      discoveryTimeoutMs: 45000,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    client.on('error', () => {});
    open.push(client);
    const up = waitFor(client, 'peer');
    await client.connect();
    await up;
    return client;
  }

  /**
   * A client that also keeps every envelope the node hands it. It decrypts
   * nothing it is not entitled to — the point is what is visible WITHOUT
   * decrypting.
   */
  async function observer(seedByte: number) {
    const client = await account(seedByte);
    const seen: Array<{ env: Envelope; bytes: Uint8Array }> = [];
    // The pool's raw message event is the wire, before the bus has looked at
    // it. Nothing here is privileged: every flooding peer sees exactly this.
    (client as unknown as { pool: { on(ev: 'message', cb: (m: { payload: Uint8Array }) => void): void } }).pool.on(
      'message',
      (m) => {
        try {
          seen.push({ env: parseEnvelope(m.payload), bytes: m.payload.slice() });
        } catch {
          // Not an envelope we can parse; a real observer sees these too.
        }
      },
    );
    return { client, seen };
  }

  beforeAll(async () => {
    node = await startRegtestNode({
      extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8', '-p2pmsgarchive=1'],
    });
  }, 300000);

  afterAll(async () => {
    for (const c of open.splice(0)) c.close();
    await node?.stop();
  });

  it('puts nothing on the wire that names the recipient', async () => {
    const alice = await account(120);
    const bob = await account(121);
    const eve = await observer(122);
    await alice.addContact(bob.bundle());
    await waitUntil(() => alice.contacts.get(decodeIdentity(bob.identity))?.clueKey !== undefined, 60000);

    const arrived = waitFor(bob, 'message');
    eve.seen.length = 0;
    // Fluffed, so every peer sees it — which is the worst case for the sender
    // and the right case to test.
    await alice.send(bob.identity, utf8('for bob only'), { stem: false });
    await arrived;
    await waitUntil(() => eve.seen.length > 0, 60000);

    const observed = eve.seen.find((e) => e.env.flag.length > 0)!;
    expect(observed).toBeDefined();
    const envelope = observed.env;
    // The serialised bytes exactly as they crossed the wire, not a
    // reconstruction from the fields this test happens to know about: a
    // recipient hint added to the framing would slip past the latter.
    const raw = observed.bytes;
    // Nothing identifying either party appears anywhere in it.
    for (const [who, key] of [
      ['bob prekey', bob.keyring.prekey.pub],
      ['bob identity', bob.keyring.identity.pub],
      ['bob clue key', bob.keyring.fmdClueKey()],
      ['alice identity', alice.keyring.identity.pub],
      ['alice prekey', alice.keyring.prekey.pub],
    ] as const) {
      expect(contains(raw, key), `${who} appears on the wire`).toBe(false);
    }
    // The sender's identity is inside the ciphertext, signed — but only the
    // recipient can get at it. An observer holding the envelope cannot.
    expect(contains(envelope.enc.ciphertext, alice.keyring.identity.pub)).toBe(false);
  }, 600000);

  it('does not announce who is being looked up', async () => {
    // Discovery used to ride a BROADCAST on a topic derived from the target's
    // identity. Broadcast envelopes are encrypted to a published key — that is
    // what makes them public — and an identity is a public address, so anyone
    // holding an address could precompute its topic and watch the bus: a live
    // social-graph oracle saying "somebody is about to contact this account",
    // with the reply following moments later to confirm the account is online.
    const alice = await account(134);
    const bob = await account(135);
    const eve = await observer(136);
    await alice.addContact(bob.bundle());

    eve.seen.length = 0;
    await alice.discover(bob.identity);
    await waitUntil(() => eve.seen.length > 0, 60000);

    // Eve reads every broadcast on the bus, because everyone can.
    let readable = 0;
    let mentionsBob = 0;
    for (const { env } of eve.seen) {
      const body = decrypt(BROADCAST_SECRET, env.enc, new Uint8Array([env.kind]));
      if (!body) continue;
      readable++;
      try {
        const { topic } = parseUserMsgFrame(body);
        if (topic.includes(toHex(sha256(decodeIdentity(bob.identity))).slice(0, 48))) mentionsBob++;
      } catch {
        // Not a library frame; a real observer sees these too.
      }
    }
    // Whatever else is on the bus, no readable frame names Bob.
    expect(mentionsBob).toBe(0);
    // And the request itself was not readable at all: it is an envelope to
    // Bob's identity key, so the topic is inside the ciphertext.
    const flagged = eve.seen.filter(({ env }) => env.flag.length === 0);
    expect(flagged.length).toBeGreaterThan(0);
    expect(readable).toBe(0);
  }, 600000);

  it('makes two messages to one person look unrelated', async () => {
    const alice = await account(123);
    const bob = await account(124);
    const eve = await observer(125);
    await alice.addContact(bob.bundle());
    await waitUntil(() => alice.contacts.get(decodeIdentity(bob.identity))?.clueKey !== undefined, 60000);

    eve.seen.length = 0;
    const one = waitFor(bob, 'message', (m) => m.payload.length === 11);
    await alice.send(bob.identity, utf8('first one!!'), { stem: false });
    await one;
    const two = waitFor(bob, 'message', (m) => m.payload.length === 12);
    await alice.send(bob.identity, utf8('second one!!'), { stem: false });
    await two;
    await waitUntil(() => eve.seen.filter((e) => e.env.flag.length > 0).length >= 2, 60000);

    const flagged = eve.seen.filter((e) => e.env.flag.length > 0).map((e) => e.env);
    const a = flagged[0]!;
    const b = flagged[flagged.length - 1]!;
    // Same recipient, same sender, nothing in common on the wire: a fresh
    // flag, a fresh ephemeral key, a fresh ciphertext. Linking them is the
    // whole game for an observer, and there is nothing to link them by.
    expect(toHex(a.flag)).not.toBe(toHex(b.flag));
    expect(toHex(a.enc.eph)).not.toBe(toHex(b.enc.eph));
    expect(toHex(a.pow.sessionEph)).not.toBe(toHex(b.pow.sessionEph));
    expect(toHex(a.pow.payloadHash)).not.toBe(toHex(b.pow.payloadHash));
    // Both are nevertheless Bob's, which only Bob's detection key can say.
    expect(fmdTest(bob.detectionKey(FMD_GAMMA), a.flag)).toBe(true);
    expect(fmdTest(bob.detectionKey(FMD_GAMMA), b.flag)).toBe(true);
  }, 600000);

  it('hands an archiving node a query it cannot pin on one account', async () => {
    // The detection key is the one thing a retrieving client must reveal, and
    // the precision it picks is exactly the trade: at a low precision the key
    // matches a large share of everyone else's traffic too, so the set the
    // node returns is bigger than the set that was wanted and it cannot tell
    // which is which.
    const alice = await account(126);
    const bob = await account(127);
    const carol = await account(128);
    for (const who of [bob, carol]) {
      await alice.addContact(who.bundle());
      await waitUntil(() => alice.contacts.get(decodeIdentity(who.identity))?.clueKey !== undefined, 60000);
    }

    const eve = await observer(130);
    eve.seen.length = 0;

    // One message for Bob, and a dozen for Carol that have nothing to do with
    // him. Twelve because the coarse key below misses each of them half the
    // time, and a test that is allowed to see none of them proves nothing.
    const mine = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('actually for bob'), { stem: false });
    await mine;
    // Twelve because the coarse key below misses each of them half the time,
    // and a test that is allowed to see none of them proves nothing. Sent one
    // at a time — the proof of work runs on this thread — and waited for on
    // the wire rather than at Carol, since what is on the wire is the whole
    // question here.
    const DECOYS = 12;
    for (let i = 0; i < DECOYS; i++) {
      await alice.send(carol.identity, utf8(`carol ${String(i).padStart(2, '0')}`), { stem: false });
    }
    await waitUntil(() => eve.seen.filter((e) => e.env.flag.length > 0).length >= DECOYS + 1, 120000);

    const flags = eve.seen.filter((e) => e.env.flag.length > 0).map((e) => e.env.flag);
    const exact = bob.detectionKey(FMD_GAMMA);
    const coarse = bob.detectionKey(1);
    const carolExact = carol.detectionKey(FMD_GAMMA);

    const bobs = flags.filter((f) => fmdTest(exact, f));
    const carols = flags.filter((f) => fmdTest(carolExact, f));
    expect(bobs.length).toBeGreaterThan(0);
    expect(carols.length).toBeGreaterThanOrEqual(DECOYS);
    // At full precision the two sets are disjoint: a detection key identifies
    // its owner's traffic exactly, which is why it is a secret.
    expect(bobs.some((f) => fmdTest(carolExact, f))).toBe(false);

    // At precision 1 Bob's key still finds everything of his — it has to, or
    // retrieval would lose messages — and also a large share of Carol's. What
    // the node serves is that union, and nothing in it says which half was
    // wanted.
    for (const f of bobs) expect(fmdTest(coarse, f)).toBe(true);
    const decoysMatched = carols.filter((f) => fmdTest(coarse, f)).length;
    expect(decoysMatched).toBeGreaterThan(0);
    const returned = flags.filter((f) => fmdTest(coarse, f)).length;
    expect(returned).toBeGreaterThan(bobs.length);
  }, 900000);

  it('lets the relaying node see nothing but ciphertext it cannot place', async () => {
    const alice = await account(131);
    const bob = await account(132);
    const eve = await observer(133);
    await alice.addContact(bob.bundle());
    await waitUntil(() => alice.contacts.get(decodeIdentity(bob.identity))?.clueKey !== undefined, 60000);

    eve.seen.length = 0;
    const arrived = waitFor(bob, 'message', (m) => m.payload.length === 8);
    await alice.send(bob.identity, utf8('relay me'), { stem: false });
    await arrived;
    await waitUntil(() => eve.seen.filter((e) => e.env.flag.length > 0).length > 0, 60000);

    // The node relayed it and — being an archive — kept it. Its own inbox is
    // a different thing entirely, and nothing addressed to Bob belongs there.
    const inbox = await node.rpc<unknown[]>('listp2pmsgs', []);
    expect(inbox).toHaveLength(0);
    const info = await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo', []);
    expect(info.archive.entries).toBeGreaterThan(0);

    // And running the archive buys no access. The node can derive a detection
    // key for its OWN inbox at any precision it likes; at full precision it
    // matches none of the traffic it is storing for other people. The only
    // key that finds Bob's messages is Bob's.
    const { detection_key: nodeKey } = await node.rpc<{ detection_key: string }>('getp2pmsgdetectionkey', [
      FMD_GAMMA,
    ]);
    const nodeDetection = fromHex(nodeKey);
    const flags = eve.seen.filter((e) => e.env.flag.length > 0).map((e) => e.env.flag);
    const bobs = flags.filter((f) => fmdTest(bob.detectionKey(FMD_GAMMA), f));
    expect(bobs.length).toBeGreaterThan(0);
    for (const f of bobs) expect(fmdTest(nodeDetection, f)).toBe(false);
    expect(equal(bob.keyring.fmdClueKey(), alice.keyring.fmdClueKey())).toBe(false);
  }, 600000);
});
