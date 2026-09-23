/**
 * End-to-end: what happens when the network misbehaves.
 *
 * The other end-to-end suites assume the peers stay up and the clocks agree.
 * This one takes those away: a node disappears under a connected client, a
 * message is sent by somebody with no identity to ack it, a sender's clock is
 * wrong, and traffic goes to a public topic where the interesting property is
 * who does NOT receive it.
 *
 * Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../test/regtest-node.js';
import { type IncomingMessage, MessagingClient, type MessagingEvents } from './usermsg/client.js';
import { MemoryStore } from './stores/memory-store.js';
import { type Store } from './stores/store.js';
import { fromUtf8, utf8 } from './common/bytes.js';
import { ServiceFlags } from './net/messages.js';

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
    await new Promise((r) => setTimeout(r, 250));
  }
}

function nothingWithin<K extends keyof MessagingEvents>(
  client: MessagingClient,
  ev: K,
  pred: (v: MessagingEvents[K]) => boolean,
  ms: number,
): Promise<boolean> {
  return new Promise((resolve) => {
    const off = client.on(ev, (v) => {
      if (!pred(v)) return;
      clearTimeout(t);
      off();
      resolve(false);
    });
    const t = setTimeout(() => {
      off();
      resolve(true);
    }, ms);
  });
}

describe.skipIf(!haveBinary)('end to end: when the network misbehaves', () => {
  const nodes: RegtestNode[] = [];
  const open: Array<{ close(): void }> = [];

  /** A client seeded with every node, so it can survive losing one. */
  async function client(
    seedByte: number,
    peers: string[],
    extra: { now?: () => number; store?: Store } = {},
  ) {
    const c = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(seedByte),
      store: extra.store ?? new MemoryStore(),
      peers,
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      ackDelayMs: 100,
      retryTickMs: 1000,
      discoveryTimeoutMs: 45000,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
      ...(extra.now ? { now: extra.now } : {}),
    });
    c.on('error', () => {
      // A node going away mid-test is the point of this suite; the pool
      // reports it and redials. Nothing to assert here.
    });
    open.push(c);
    const up = waitFor(c, 'peer');
    await c.connect();
    await up;
    return c;
  }

  const addr = (n: RegtestNode) => `127.0.0.1:${n.port}`;

  beforeAll(async () => {
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8'] }));
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8'] }));
    await nodes[0]!.rpc('addnode', [addr(nodes[1]!), 'onetry']);
    await waitUntil(
      async () => (await nodes[0]!.rpc<{ relay_capable_peers: number }>('getp2pmsginfo')).relay_capable_peers >= 1,
      60000,
    );
  }, 300000);

  afterAll(async () => {
    for (const c of open.splice(0)) c.close();
    await Promise.all(nodes.splice(0).map((n) => n.stop()));
  });

  it('keeps delivering after the node a client is talking through goes away', async () => {
    // Both clients know both nodes, which is what makes losing one survivable.
    const seeds = [addr(nodes[0]!), addr(nodes[1]!)];
    const alice = await client(90, seeds);
    const bob = await client(91, seeds);
    await alice.addContact(bob.bundle());
    await bob.addContact(alice.bundle());

    const first = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'while everything is up');
    await alice.send(bob.identity, utf8('while everything is up'));
    await first;

    // Take down whichever node Alice is on. She has to notice, redial, and
    // her outbox has to carry the message that was in flight.
    const alicePeer = alice.peers()[0]!.address;
    const doomed = nodes.find((n) => addr(n) === alicePeer)!;
    const survivor = nodes.find((n) => n !== doomed)!;
    const arrived = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'sent into the gap');

    // Sent first, so the send and the outage race — exactly as they would.
    void alice.send(bob.identity, utf8('sent into the gap')).catch(() => undefined);
    await doomed.stop();
    nodes.splice(nodes.indexOf(doomed), 1);

    // Bob may have been on the doomed node too; both of them redial the
    // survivor, and the outbox retries until it is acked. Waiting for "a
    // peer" would be satisfied by the dead one, which the pool has not
    // noticed yet — wait for the survivor by name.
    const onSurvivor = (c: MessagingClient) => c.peers().some((p) => p.address === addr(survivor));
    await waitUntil(() => onSurvivor(alice) && onSurvivor(bob), 120000);
    await arrived;

    // And the link is healthy afterwards, not merely once.
    const after = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'after the dust settled');
    await alice.send(bob.identity, utf8('after the dust settled'));
    await after;
  }, 600000);

  it('carries a public topic to its subscribers and to nobody else', async () => {
    const seeds = nodes.map(addr);
    const speaker = await client(92, seeds);
    const listener = await client(93, seeds);
    const bystander = await client(94, seeds);

    const heard: IncomingMessage[] = [];
    listener.subscribe('news/rates', (m) => heard.push(m));
    // The bystander subscribes to a DIFFERENT topic: a public message is
    // readable by anyone on the bus, so what is being checked is that the
    // client does not surface chatter nobody asked for.
    const other: IncomingMessage[] = [];
    bystander.subscribe('news/weather', (m) => other.push(m));

    await speaker.publish('news/rates', utf8('up two points'), { stem: false });
    await waitUntil(() => heard.length > 0, 60000);
    expect(fromUtf8(heard[0]!.payload)).toBe('up two points');
    expect(heard[0]!.scope).toBe('broadcast');
    expect(heard[0]!.from).toBe(speaker.identity);
    expect(other).toHaveLength(0);

    // Unsubscribing takes effect: the next one is not surfaced.
    listener.unsubscribe('news/rates');
    await speaker.publish('news/rates', utf8('down one'), { stem: false });
    await new Promise((r) => setTimeout(r, 5000));
    expect(heard).toHaveLength(1);
  }, 600000);

  it('delivers an unsigned message, which nobody can ack', async () => {
    const seeds = nodes.map(addr);
    const alice = await client(95, seeds);
    const bob = await client(96, seeds);
    await alice.addContact(bob.bundle());

    // No signature means no sender to attribute it to, so there is nobody to
    // ack — the SDK sends it once and forgets it. Worth pinning: an
    // application that expects delivery confirmation must not use this.
    const anon = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'no name on this');
    const noAck = nothingWithin(alice, 'ack', () => true, 15000);
    await alice.send(bob.identity, utf8('no name on this'), { sign: false });
    const got = await anon;
    expect(got.from).toBeUndefined();
    expect(got.scope).toBe('inbox');
    expect(await noAck).toBe(true);
  }, 600000);

  it('delivers from a device whose clock is an hour wrong', async () => {
    const seeds = nodes.map(addr);
    // Envelopes carry a timestamp and every node enforces a +/-120 s window on
    // it, so a device with a wrong system clock would be unable to say
    // anything to anyone. The bus stamps with its PEERS' time instead — the
    // wall clock plus the median offset measured at each handshake — so the
    // device is corrected by the network it is talking to.
    const skewed = await client(97, seeds, { now: () => Date.now() + 3600_000 });
    const bob = await client(98, seeds);
    await skewed.addContact(bob.bundle());
    await bob.addContact(skewed.bundle());

    const arrived = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'an hour fast, and fine');
    await skewed.send(bob.identity, utf8('an hour fast, and fine'));
    await arrived;

    // And in the other direction: the skewed device accepts what a
    // correctly-clocked peer sends, which it could not do if it checked
    // arriving stamps against its own idea of the time.
    const back = waitFor(skewed, 'message', (m) => fromUtf8(m.payload) === 'and back again');
    await bob.send(skewed.identity, utf8('and back again'));
    await back;
  }, 600000);
});
