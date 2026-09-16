/**
 * Integration: three chained regtest nodes A - B - C. Alice is a leaf on A,
 * Bob a leaf on C. Messages must traverse two relay hops (stem and fluff).
 * Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from './client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { fromUtf8, utf8 } from '../common/bytes.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<K extends keyof MessagingEvents>(c: MessagingClient, ev: K, pred: (v: MessagingEvents[K]) => boolean = () => true, ms = 60000): Promise<MessagingEvents[K]> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => { off(); reject(new Error(`timeout waiting for ${String(ev)}`)); }, ms);
    const off = c.on(ev, (v) => { if (pred(v)) { clearTimeout(t); off(); resolve(v); } });
  });
}

describe.skipIf(!haveBinary)('MessagingClient across three chained naviod nodes', () => {
  const nodes: RegtestNode[] = [];
  const clients: MessagingClient[] = [];

  async function mk(seedByte: number, node: RegtestNode) {
    const c = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(seedByte),
      store: new MemoryStore(),
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      ackDelayMs: 100,
      retryTickMs: 2000,
    });
    c.on('error', (e) => console.error('[client]', e.message));
    clients.push(c);
    const connected = waitFor(c, 'peer');
    await c.connect();
    await connected;
    return c;
  }

  async function waitPeers(node: RegtestNode, n: number) {
    for (let i = 0; i < 100; i++) {
      const peers = await node.rpc<unknown[]>('getpeerinfo');
      if (peers.length >= n) return;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error('nodes did not connect');
  }

  beforeAll(async () => {
    for (let i = 0; i < 3; i++) nodes.push(await startRegtestNode());
    // Chain: A <-> B <-> C, nothing else.
    await nodes[0]!.rpc('addnode', [`127.0.0.1:${nodes[1]!.port}`, 'onetry']);
    await nodes[2]!.rpc('addnode', [`127.0.0.1:${nodes[1]!.port}`, 'onetry']);
    await waitPeers(nodes[1]!, 2);
    // Wait for the version handshakes to expose NODE_P2PMSG so stem routes exist.
    for (let i = 0; i < 50; i++) {
      const info = await nodes[1]!.rpc<{ relay_capable_peers: number }>('getp2pmsginfo');
      if (info.relay_capable_peers >= 2) break;
      await new Promise((r) => setTimeout(r, 200));
    }
  }, 120000);

  afterAll(async () => {
    for (const c of clients) c.close();
    await Promise.all(nodes.map((n) => n.stop()));
  });

  it('A-leaf and C-leaf exchange acked messages over two hops (stem)', async () => {
    const alice = await mk(41, nodes[0]!);
    const bob = await mk(42, nodes[2]!);
    await alice.addContact(bob.bundle());
    const got = waitFor(bob, 'message');
    const acked = waitFor(alice, 'ack');
    await alice.send(bob.identity, utf8('across the chain'), { stem: true });
    expect(fromUtf8((await got).payload)).toBe('across the chain');
    await acked;
    const back = waitFor(alice, 'message');
    await bob.send(alice.identity, utf8('and back'), { stem: true });
    expect(fromUtf8((await back).payload)).toBe('and back');
    const infoB = await nodes[1]!.rpc<{ leaf_peers: number; relay_capable_peers: number }>('getp2pmsginfo');
    expect(infoB.leaf_peers).toBe(0); // leaves attach to A and C, not B
  }, 180000);

  it('discovery + fluff work over two hops', async () => {
    const carol = await mk(43, nodes[0]!);
    const dave = await mk(44, nodes[2]!);
    const got = waitFor(dave, 'message');
    await carol.send(dave.identity, utf8('found across hops'), { stem: false });
    expect(fromUtf8((await got).payload)).toBe('found across hops');
    const infoA = await nodes[0]!.rpc<{ leaf_peers: number }>('getp2pmsginfo');
    expect(infoA.leaf_peers).toBe(2);
  }, 180000);
});
