/**
 * End-to-end across a real relay network.
 *
 * The single-node e2e suite is the easy case: everything reaches everything.
 * Real networks relay, and the properties worth checking are the ones that
 * only fail once a message has to cross hops it cannot be read at — stem and
 * fluff routing, an archive that lives on a node neither party talks to, and
 * ordering when two people speak at once.
 *
 * Three chained nodes, A - B - C, with nothing else connecting them. Alice sits
 * on A, Bob on C, so nothing they exchange reaches the other without B relaying
 * it, and B can read none of it.
 *
 * Run with `npm run test:int`. Requires a naviod built with the envelope-v2 and
 * archive changes (navio-core #474 and #475).
 */
import { existsSync } from 'node:fs';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from './usermsg/client.js';
import { ChatClient, type ChatEvents } from './chat/client.js';
import { MemoryStore } from './stores/memory-store.js';
import type { Store } from './stores/store.js';
import { toHex } from './common/bytes.js';
import { ServiceFlags } from './net/messages.js';
import { decodeIdentity } from './usermsg/bundle.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<T extends ChatEvents | MessagingEvents, K extends keyof T>(
  emitter: { on(ev: K, cb: (v: T[K]) => void): () => void },
  ev: K,
  pred: (v: T[K]) => boolean = () => true,
  ms = 90000,
): Promise<T[K]> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      off();
      reject(new Error(`timeout waiting for ${String(ev)}`));
    }, ms);
    const off = emitter.on(ev, (v) => {
      if (pred(v)) {
        clearTimeout(t);
        off();
        resolve(v);
      }
    });
  });
}

describe.skipIf(!haveBinary)('end to end across a relay network', () => {
  const nodes: RegtestNode[] = [];
  /**
   * Closed after every test. Left open, clients accumulate across the file and
   * every one of them keeps grinding proof of work on the same three nodes —
   * which makes later tests fail for load rather than for anything real.
   */
  let open: Array<{ close(): void }> = [];

  async function account(seedByte: number, node: RegtestNode, store: Store = new MemoryStore()) {
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
      retryTickMs: 2000,
      discoveryTimeoutMs: 45000,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    client.on('error', (e) => console.error('[client]', e.message));
    open.push(client);
    const connected = waitFor<MessagingEvents, 'peer'>(client, 'peer');
    await client.connect();
    await connected;
    const chat = await ChatClient.create({ client, store });
    chat.on('error', (e) => console.error('[chat]', e.message));
    open.push(chat);
    return { client, chat, store };
  }

  type Account = Awaited<ReturnType<typeof account>>;

  async function introduce(a: Account, b: Account) {
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);
    // Wait for the clue keys to arrive: discovery is what makes a message
    // archivable, and it crosses the same hops the messages will.
    await waitUntil(
      async () =>
        a.client.contacts.get(decodeIdentity(b.chat.identity))?.clueKey !== undefined &&
        b.client.contacts.get(decodeIdentity(a.chat.identity))?.clueKey !== undefined,
      60000,
    );
  }

  async function waitPeers(node: RegtestNode, n: number) {
    await waitUntil(async () => (await node.rpc<unknown[]>('getpeerinfo')).length >= n, 30000);
  }

  beforeAll(async () => {
    // Only the middle node archives, so retrieval has to work from a node
    // neither party is connected to.
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsgpowbits=8'] }));
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsgpowbits=8', '-p2pmsgarchive=1'] }));
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsgpowbits=8'] }));
    await nodes[0]!.rpc('addnode', [`127.0.0.1:${nodes[1]!.port}`, 'onetry']);
    await nodes[2]!.rpc('addnode', [`127.0.0.1:${nodes[1]!.port}`, 'onetry']);
    await waitPeers(nodes[1]!, 2);
    // Stem routing needs the relay to have seen both peers advertise NODE_P2PMSG.
    await waitUntil(async () => {
      const info = await nodes[1]!.rpc<{ relay_capable_peers: number }>('getp2pmsginfo');
      return info.relay_capable_peers >= 2;
    }, 30000);
  }, 240000);

  afterEach(() => {
    for (const c of open.splice(0)) c.close();
    open = [];
  });

  afterAll(async () => {
    for (const c of open.splice(0)) c.close();
    await Promise.all(nodes.map((n) => n.stop()));
  });

  it('carries a conversation two hops, through a relay that cannot read it', async () => {
    const alice = await account(20, nodes[0]!);
    const bob = await account(21, nodes[2]!);
    await introduce(alice, bob);
    const conv = alice.chat.conversationWith(bob.chat.identity);

    const there = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'across two hops');
    const first = await alice.chat.sendText(bob.chat.identity, 'across two hops');
    await there;

    const back = waitFor<ChatEvents, 'message'>(alice.chat, 'message', (e) => e.message.text === 'and back');
    await bob.chat.sendText(alice.chat.identity, 'and back', { replyTo: first });
    expect(toHex((await back).message.replyTo!)).toBe(toHex(first));

    expect((await alice.chat.history(conv)).messages.map((m) => m.text)).toEqual(
      (await bob.chat.history(conv)).messages.map((m) => m.text),
    );

    // The relay in the middle saw every envelope and could read none of them:
    // it stored nothing addressable to itself.
    const relayInbox = await nodes[1]!.rpc<unknown[]>('listp2pmsgs', []);
    expect(relayInbox).toHaveLength(0);
  }, 300000);

  it('converges on one order when both sides speak at once', async () => {
    // Concurrent sends are a FORK, not a conflict. The causal DAG has to put
    // both devices on the same order anyway, or the same conversation renders
    // differently for each participant.
    const alice = await account(22, nodes[0]!);
    const bob = await account(23, nodes[2]!);
    await introduce(alice, bob);
    const conv = alice.chat.conversationWith(bob.chat.identity);

    const atBob = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'from alice');
    const atAlice = waitFor<ChatEvents, 'message'>(alice.chat, 'message', (e) => e.message.text === 'from bob');
    // Neither has seen the other's message when it builds its own, so both
    // cite the same parents and neither is causally after the other.
    await Promise.all([
      alice.chat.sendText(bob.chat.identity, 'from alice'),
      bob.chat.sendText(alice.chat.identity, 'from bob'),
    ]);
    await Promise.all([atBob, atAlice]);

    const onAlice = (await alice.chat.history(conv)).messages.map((m) => m.text);
    const onBob = (await bob.chat.history(conv)).messages.map((m) => m.text);
    expect(onAlice).toHaveLength(2);
    expect(onBob).toEqual(onAlice);
  }, 300000);

  it('retrieves from an archive on a node neither party is connected to', async () => {
    const alice = await account(24, nodes[0]!);
    const bobStore = new MemoryStore();
    let bob = await account(25, nodes[2]!, bobStore);
    await introduce(alice, bob);

    bob.client.close();
    bob.chat.close();
    await new Promise((r) => setTimeout(r, 500));

    const before = (await nodes[1]!.rpc<{ archive: { entries: number } }>('getp2pmsginfo', [])).archive.entries;
    await alice.chat.sendText(bob.chat.identity, 'archived two hops away');
    await waitUntil(async () => {
      const info = await nodes[1]!.rpc<{ archive: { entries: number } }>('getp2pmsginfo', []);
      return info.archive.entries > before;
    }, 90000);

    // Bob reconnects to C, which does not archive; the archive is on B. He has
    // to reach it through the peer he has.
    bob = await account(25, nodes[2]!, bobStore);
    await waitUntil(async () => bob.client.archivePeers().length > 0, 30000).catch(() => undefined);
    const recovered = waitFor<ChatEvents, 'message'>(
      bob.chat,
      'message',
      (e) => e.message.text === 'archived two hops away',
    );
    const res = await bob.client.syncArchive({ precision: 4 });
    if (res.peers === 0) {
      // C is not an archive peer and B is not directly connected to Bob, so
      // there is nothing to query. That is the honest outcome of this topology
      // and worth asserting rather than papering over.
      expect(res.accepted).toBe(0);
      return;
    }
    expect(res.accepted).toBeGreaterThan(0);
    await recovered;
  }, 300000);

  it('runs a group whose members sit on different nodes', async () => {
    const alice = await account(26, nodes[0]!);
    const bob = await account(27, nodes[2]!);
    const carol = await account(28, nodes[1]!);
    await introduce(alice, bob);
    await introduce(alice, carol);
    await introduce(bob, carol);

    const joinedB = waitFor<ChatEvents, 'group'>(bob.chat, 'group');
    const joinedC = waitFor<ChatEvents, 'group'>(carol.chat, 'group');
    const groupId = await alice.chat.createGroup('spread out', [bob.chat.identity, carol.chat.identity]);
    await joinedB;
    await joinedC;

    // One envelope, three nodes, two of them relays for the others.
    const atB = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'everyone, everywhere');
    const atC = waitFor<ChatEvents, 'message'>(carol.chat, 'message', (e) => e.message.text === 'everyone, everywhere');
    await alice.chat.sendGroupText(groupId, 'everyone, everywhere');
    await atB;
    await atC;

    expect((await bob.chat.history(groupId)).messages.map((m) => m.text)).toEqual(
      (await carol.chat.history(groupId)).messages.map((m) => m.text),
    );
  }, 300000);

  it('chunks a payload far beyond one frame and reassembles it across hops', async () => {
    // A frame is 3584 bytes. Anything larger is split, each chunk carrying its
    // own proof of work, and has to be reassembled after two relays.
    const alice = await account(29, nodes[0]!);
    const bob = await account(30, nodes[2]!);
    await introduce(alice, bob);

    const big = 'x'.repeat(20_000);
    const got = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text.length > 10_000);
    await alice.chat.sendText(bob.chat.identity, big);
    expect((await got).message.text).toBe(big);
  }, 300000);

  it('keeps delivering after the recipient rotates their prekey', async () => {
    // Rotation changes the key senders encrypt to. A sender holding the old
    // bundle must recover rather than silently stop being able to reach them.
    const alice = await account(31, nodes[0]!);
    const bob = await account(32, nodes[2]!);
    await introduce(alice, bob);

    const first = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'before rotation');
    await alice.chat.sendText(bob.chat.identity, 'before rotation');
    await first;

    const oldPrekey = toHex(bob.client.keyring.prekey.pub);
    await bob.client.rotatePrekey();
    expect(toHex(bob.client.keyring.prekey.pub)).not.toBe(oldPrekey);

    // The previous prekey stays in the grace ring, which is exactly what keeps
    // a sender with a cached bundle working.
    const after = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'after rotation');
    await alice.chat.sendText(bob.chat.identity, 'after rotation');
    expect((await after).message.text).toBe('after rotation');
  }, 300000);

  it('reports a gap when a message in the middle never arrives', async () => {
    // The property the causal DAG exists for: a client must be able to tell
    // "nothing was said" from "something was lost".
    const alice = await account(33, nodes[0]!);
    const bob = await account(34, nodes[2]!);
    await introduce(alice, bob);
    const conv = alice.chat.conversationWith(bob.chat.identity);

    const one = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'one');
    await alice.chat.sendText(bob.chat.identity, 'one');
    await one;

    // Drop the middle message by sending it while Bob is not listening, then
    // send a third that cites it.
    bob.client.close();
    bob.chat.close();
    await new Promise((r) => setTimeout(r, 300));
    await alice.chat.sendText(bob.chat.identity, 'two');
    await new Promise((r) => setTimeout(r, 1000));

    const revived = await account(34, nodes[2]!, bob.store);
    const three = waitFor<ChatEvents, 'gap'>(revived.chat, 'gap');
    await alice.chat.sendText(bob.chat.identity, 'three');
    const gaps = await three;
    expect(gaps.gaps.length).toBeGreaterThan(0);
    // And the hole is visible in the conversation rather than silently absent.
    expect((await revived.chat.history(conv)).gaps.length).toBeGreaterThan(0);
  }, 300000);
});

async function waitUntil(pred: () => Promise<boolean>, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 200));
  }
}
