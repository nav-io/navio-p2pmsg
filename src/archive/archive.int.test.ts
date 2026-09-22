/**
 * Integration: offline retrieval through a real archiving naviod.
 *
 * This is the scenario the whole mechanism exists for. Bob goes offline, Alice
 * sends him a message, the node relays it (and cannot read it), Bob comes back
 * and retrieves it from the archive using a detection key that tells the node
 * only a fuzzy set. Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from '../usermsg/client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { fromUtf8, utf8 } from '../common/bytes.js';
import { ServiceFlags } from '../net/messages.js';
import type { Store } from '../stores/store.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<K extends keyof MessagingEvents>(
  c: MessagingClient,
  ev: K,
  pred: (v: MessagingEvents[K]) => boolean = () => true,
  ms = 30000,
): Promise<MessagingEvents[K]> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      off();
      reject(new Error(`timeout waiting for ${String(ev)}`));
    }, ms);
    const off = c.on(ev, (v) => {
      if (pred(v)) {
        clearTimeout(t);
        off();
        resolve(v);
      }
    });
  });
}

describe.skipIf(!haveBinary)('archive retrieval <-> naviod regtest', () => {
  let node: RegtestNode;
  let archiveSupported = false;
  const clients: MessagingClient[] = [];

  async function mk(seedByte: number, store: Store = new MemoryStore()) {
    const c = await MessagingClient.create({
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
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    c.on('error', (e) => console.error('[client]', e.message));
    clients.push(c);
    // Wait for the handshake, not just the dial: without a peer a send goes
    // nowhere and the outbox does not retry for 30 s.
    const connected = waitFor(c, 'peer');
    await c.connect();
    await connected;
    return c;
  }

  beforeAll(async () => {
    node = await startRegtestNode({
      extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8', '-p2pmsgarchive=1', '-debug=net'],
    });
    const info = await node.rpc<Record<string, unknown>>('getp2pmsginfo', []);
    archiveSupported = 'archive' in info;
  }, 120000);

  afterAll(async () => {
    for (const c of clients.splice(0)) c.close();
    await node?.stop();
  });

  it('retrieves a message that arrived while the recipient was offline', async () => {
    expect(archiveSupported, 'naviod must be built with the archive change').toBe(true);

    const alice = await mk(40);
    const bobStore = new MemoryStore();
    let bob = await mk(41, bobStore);

    // Alice learns Bob's clue key over ordinary prekey discovery — it is the
    // only place the clue key is published, and without it she cannot flag.
    const learned = waitFor(alice, 'contact', (c) => c.identity === bob.identity);
    const online = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('while online'));
    await learned;
    expect(fromUtf8((await online).payload)).toBe('while online');

    // Bob goes away entirely.
    bob.close();
    clients.splice(clients.indexOf(bob), 1);
    await new Promise((r) => setTimeout(r, 500));

    const before = (await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo', [])).archive.entries;
    await alice.send(bob.identity, utf8('while offline'), { sign: true });

    // The node archives it even though it cannot read it.
    await waitUntil(async () => {
      const info = await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo', []);
      return info.archive.entries > before;
    }, 30000);

    // Bob comes back on the SAME store, so his keys (and therefore his clue
    // key) are unchanged, and retrieves what he missed.
    bob = await mk(41, bobStore);
    const recovered = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'while offline');
    const res = await bob.syncArchive({ precision: 4 });
    expect(res.peers).toBe(1);
    expect(res.received).toBeGreaterThan(0);
    expect(res.accepted).toBeGreaterThan(0);
    expect(res.complete).toBe(true);
    const got = await recovered;
    expect(fromUtf8(got.payload)).toBe('while offline');
    expect(got.from).toBe(alice.identity);

    // Syncing again is a no-op: the cursor advanced past what was scanned, and
    // the replay cache rejects anything that did come back twice.
    const second = await bob.syncArchive({ precision: 4 });
    expect(second.accepted).toBe(0);
  }, 180000);

  it('returns nothing useful to a stranger at full precision', async () => {
    expect(archiveSupported).toBe(true);
    // A client with unrelated keys queries the same archive. It gets decoys at
    // worst and can decrypt none of them.
    const stranger = await mk(42);
    const res = await stranger.syncArchive({ precision: 24 });
    expect(res.peers).toBe(1);
    expect(res.accepted).toBe(0);
  }, 120000);
});

async function waitUntil(pred: () => Promise<boolean>, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 200));
  }
}
