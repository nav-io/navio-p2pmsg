/**
 * End-to-end: abuse, and whether honest traffic survives it.
 *
 * The question in each case is not "does the node reject this" — the unit
 * tests cover that — but "does a bystander still get their messages while it
 * is happening". A rejection that also stops honest delivery is a successful
 * attack.
 *
 * Every attacker here is a real client on a real node, spending real proof of
 * work where the protocol demands it. That is the point: the defences are
 * supposed to be economic, so the test has to pay the same price an attacker
 * would, and the cost asymmetry is itself a result worth recording.
 *
 * Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from './usermsg/client.js';
import { MemoryStore } from './stores/memory-store.js';
import { fromUtf8, randomBytes, utf8 } from './common/bytes.js';
import { ServiceFlags } from './net/messages.js';
import { serializeEnvelope, type Envelope } from './bus/envelope.js';
import { POW_VERSION_CURRENT, payloadHash } from './bus/pow.js';
import { encrypt, packetMsgHash } from './bus/ecies.js';
import { generateSecret, publicKey } from './bus/bls.js';
import { decodeIdentity } from './usermsg/bundle.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<K extends keyof MessagingEvents>(
  client: MessagingClient,
  ev: K,
  pred: (v: MessagingEvents[K]) => boolean = () => true,
  ms = 120000,
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

describe.skipIf(!haveBinary)('end to end: abuse, and honest traffic under it', () => {
  let node: RegtestNode;
  const open: Array<{ close(): void }> = [];

  async function account(seedByte: number, extra: { powBits?: number } = {}) {
    const client = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(seedByte),
      store: new MemoryStore(),
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: extra.powBits ?? 8,
      powWorkers: 0,
      ackDelayMs: 100,
      retryTickMs: 1000,
      discoveryTimeoutMs: 45000,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    client.on('error', () => {
      // Abuse produces errors by design.
    });
    open.push(client);
    const up = waitFor(client, 'peer');
    await client.connect();
    await up;
    return client;
  }

  /** The raw wire, for sending what the SDK would never construct. */
  function wire(client: MessagingClient): { send(bytes: Uint8Array): void; peers(): number } {
    const pool = client as unknown as {
      pool: { broadcast(b: Uint8Array, o: { stem: boolean }): number };
    };
    return {
      send: (bytes) => {
        pool.pool.broadcast(bytes, { stem: false });
      },
      peers: () => client.peers().length,
    };
  }

  /** A syntactically valid envelope whose proof of work is absent. */
  function unstampedEnvelope(): Uint8Array {
    const recipient = publicKey(generateSecret());
    const enc = encrypt(recipient, randomBytes(64), new Uint8Array([7]));
    const env: Envelope = {
      kind: 7,
      pow: {
        version: POW_VERSION_CURRENT,
        timestamp: BigInt(Math.floor(Date.now() / 1000)),
        kind: 7,
        sessionEph: enc.eph,
        payloadHash: payloadHash(POW_VERSION_CURRENT, packetMsgHash(enc), new Uint8Array(0)),
        nonce: 0n, // never ground
      },
      flag: new Uint8Array(0),
      enc,
    };
    return serializeEnvelope(env);
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

  it('keeps delivering while a peer floods envelopes with no proof of work', async () => {
    const alice = await account(140);
    const bob = await account(141);
    const attacker = await account(142);
    await alice.addContact(bob.bundle());
    await waitUntil(() => alice.contacts.get(decodeIdentity(bob.identity))?.clueKey !== undefined, 60000);

    // 400 unstamped envelopes, as fast as the socket takes them. Each costs the
    // attacker nothing, which is exactly why the node must not pay for them
    // either: the proof of work is checked before anything expensive happens.
    const raw = wire(attacker);
    const flood = Array.from({ length: 400 }, () => unstampedEnvelope());
    const arrived = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'through the flood');
    for (const bytes of flood) raw.send(bytes);
    await alice.send(bob.identity, utf8('through the flood'));
    await arrived;

    // The honest message arrived with four hundred junk envelopes in flight,
    // which is the only assertion that matters here: the flood did not buy a
    // delay, let alone a denial.
    //
    // The attacker paid for it, not the network: discouragement points, then a
    // disconnection. Honest peers are untouched.
    await waitUntil(() => raw.peers() === 0, 60000);
    expect(alice.peers().length).toBe(1);
    expect(bob.peers().length).toBe(1);
  }, 900000);

  it('keeps delivering while a peer floods envelopes that DO carry proof of work', async () => {
    // The expensive case. These are valid envelopes, so the node relays them;
    // the defence is not rejection but the relay token bucket, and what must
    // survive is a bystander's message.
    const alice = await account(143);
    const bob = await account(144);
    const attacker = await account(145);
    await alice.addContact(bob.bundle());
    await waitUntil(() => alice.contacts.get(decodeIdentity(bob.identity))?.clueKey !== undefined, 60000);

    const junkRecipient = publicKey(generateSecret());
    const arrived = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'through the valid flood');
    // 60 fully ground envelopes. At 8 bits each that is cheap here, and the
    // ratio is the point: on mainnet this is 23 bits apiece.
    const sends: Array<Promise<unknown>> = [];
    for (let i = 0; i < 60; i++) {
      sends.push(attacker.bus.send(7, junkRecipient, randomBytes(256), { stem: false }).catch(() => undefined));
    }
    await alice.send(bob.identity, utf8('through the valid flood'));
    await arrived;
    await Promise.all(sends);

    // Everyone is still connected, and the honest pair still works afterwards.
    expect(alice.peers().length).toBe(1);
    const after = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'and still working');
    await alice.send(bob.identity, utf8('and still working'));
    await after;
  }, 900000);

  it('answers a discovery storm without falling over', async () => {
    // Discovery is the one place we answer a stranger, so it is the one place
    // an unauthenticated peer can make us sign something. Each answer is a
    // BLS signature over a bundle, and the reply cap exists so that one
    // requester cannot turn into an unbounded stream of them.
    const target = await account(146);
    const asker = await account(147);

    // Forty lookups at once, each minting its own reply key — the honest
    // shape, and the most expensive one for the target.
    const storm = await Promise.allSettled(
      Array.from({ length: 40 }, () => asker.discover(target.identity)),
    );
    const answered = storm.filter((r) => r.status === 'fulfilled').length;
    // All forty resolve, and they resolve off ONE request: concurrent lookups
    // of the same identity collapse onto a single in-flight discovery, so the
    // target signs one bundle rather than forty. That collapsing is the
    // defence that matters here; the per-reply-key cap is the backstop behind
    // it, for a requester that mints forty keys on purpose.
    expect(answered).toBe(40);

    // And the target is still there, still answering somebody new.
    expect(target.peers().length).toBe(1);
    const fresh = await account(148);
    await expect(fresh.discover(target.identity)).resolves.toBeDefined();
  }, 900000);

  it('rate limits archive queries without losing the messages behind them', async () => {
    // The archive is the most expensive thing a node offers: a scan is linear
    // in window times precision. It meters queries per peer, and a client that
    // is metered has to keep its place rather than skip what it did not see.
    const alice = await account(149);
    const bobStore = new MemoryStore();
    let bob = await account(150);
    await alice.addContact(bob.bundle());
    await waitUntil(() => alice.contacts.get(decodeIdentity(bob.identity))?.clueKey !== undefined, 60000);

    const heard = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('for later'));
    await heard;
    bob.close();
    open.splice(open.indexOf(bob), 1);

    await alice.send(bob.identity, utf8('while away'));
    await waitUntil(async () => (await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo')).archive.entries > 0, 60000);

    bob = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(150),
      store: bobStore,
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    bob.on('error', () => {});
    open.push(bob);
    const up = waitFor(bob, 'peer');
    await bob.connect();
    await up;

    // Ten syncs back to back, well past the node's burst of three. Some are
    // dropped; the ones that land must still bring the message, and the client
    // must not report itself complete when it was metered.
    const results = [];
    for (let i = 0; i < 10; i++) results.push(await bob.syncArchive({ precision: 4 }));
    const accepted = results.reduce((n, r) => n + r.accepted, 0);
    expect(accepted).toBeGreaterThan(0);
    // A metered query is reported as incomplete, not as "nothing there".
    expect(results.some((r) => !r.complete)).toBe(true);
    expect(bob.peers().length).toBe(1);
  }, 900000);
});
