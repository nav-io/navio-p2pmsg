/**
 * End-to-end: what delivery promises, and what it does not.
 *
 * The other suites check that a message arrives. These check the edges of
 * that: what happens when it never can, what happens when it arrives twice,
 * what happens when it is too big to be one envelope and the recipient is not
 * there to collect the pieces, and what one envelope costs when a group is
 * larger than two.
 *
 * Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from './usermsg/client.js';
import { ChatClient, type ChatEvents } from './chat/client.js';
import { MemoryStore } from './stores/memory-store.js';
import { type Store } from './stores/store.js';
import { fromUtf8, randomBytes, toHex, utf8 } from './common/bytes.js';
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

async function waitUntil(pred: () => Promise<boolean> | boolean, ms = 60000): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 250));
  }
}

describe.skipIf(!haveBinary)('end to end: the edges of delivery', () => {
  let node: RegtestNode;
  const open: Array<{ close(): void }> = [];

  async function account(seedByte: number, store: Store = new MemoryStore(), ackDelayMs = 100) {
    const client = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(seedByte),
      store,
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      ackDelayMs,
      retryTickMs: 1000,
      discoveryTimeoutMs: 45000,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    client.on('error', () => {
      // Peers come and go in this suite by design.
    });
    open.push(client);
    const up = waitFor<MessagingEvents, 'peer'>(client, 'peer');
    await client.connect();
    await up;
    const chat = await ChatClient.create({ client, store });
    chat.on('error', () => {});
    open.push(chat);
    return { client, chat, store };
  }

  type Account = Awaited<ReturnType<typeof account>>;

  async function introduce(a: Account, b: Account) {
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);
    await waitUntil(
      () =>
        a.client.contacts.get(decodeIdentity(b.chat.identity))?.clueKey !== undefined &&
        b.client.contacts.get(decodeIdentity(a.chat.identity))?.clueKey !== undefined,
      60000,
    );
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

  it('gives up on a message whose recipient never comes back, and says so', async () => {
    const alice = await account(100);
    const bob = await account(101);
    await introduce(alice, bob);

    // Bob leaves for good. Nothing in the protocol can deliver this, and the
    // honest outcome is the sender being told rather than retrying forever.
    bob.chat.close();
    bob.client.close();
    open.splice(open.indexOf(bob.chat), 1);
    open.splice(open.indexOf(bob.client), 1);

    const expired = waitFor<MessagingEvents, 'expired'>(alice.client, 'expired');
    const msgId = await alice.client.send(bob.client.identity, utf8('into the void'), { ttlMs: 8000 });
    const ev = await expired;
    expect(toHex(ev.msgId)).toBe(toHex(msgId));
    expect(ev.to).toBe(bob.client.identity);

    // Expiry is final: no ack can arrive afterwards for a message the outbox
    // has dropped, so an application may count it as failed.
    const late = await new Promise<boolean>((resolve) => {
      const off = alice.client.on('ack', (a) => {
        if (toHex(a.msgId) !== toHex(msgId)) return;
        off();
        resolve(false);
      });
      setTimeout(() => {
        off();
        resolve(true);
      }, 5000);
    });
    expect(late).toBe(true);
  }, 600000);

  it('re-acks a retransmission without delivering it twice, across a restart', async () => {
    const store = new MemoryStore();
    const alice = await account(102);
    // Bob batches his acks for a minute, so the one for the message below is
    // still pending when he goes away. That is the case worth testing: an ack
    // that never reached the sender, so the sender legitimately retransmits.
    let bob = await account(103, store, 60_000);
    await introduce(alice, bob);

    const first = waitFor<MessagingEvents, 'message'>(
      bob.client,
      'message',
      (m) => fromUtf8(m.payload) === 'exactly once',
    );
    const msgId = await alice.client.send(bob.client.identity, utf8('exactly once'));
    await first;

    bob.chat.close();
    bob.client.close();
    open.splice(open.indexOf(bob.chat), 1);
    open.splice(open.indexOf(bob.client), 1);

    // Alice never heard an ack, so the message is still in her outbox and she
    // is still retransmitting it.
    const acked = await new Promise<boolean>((resolve) => {
      const off = alice.client.on('ack', (a) => {
        if (toHex(a.msgId) !== toHex(msgId)) return;
        off();
        resolve(true);
      });
      setTimeout(() => {
        off();
        resolve(false);
      }, 3000);
    });
    expect(acked).toBe(false);

    // Bob comes back on the same store, acking promptly this time. The dedup
    // record has to have survived the restart: he must ack the retransmission
    // — otherwise Alice retries until the TTL — and must not show it again.
    bob = await account(103, store);
    let redelivered = 0;
    bob.client.on('message', (m) => {
      if (fromUtf8(m.payload) === 'exactly once') redelivered++;
    });
    await waitFor<MessagingEvents, 'ack'>(alice.client, 'ack', (a) => toHex(a.msgId) === toHex(msgId));
    expect(redelivered).toBe(0);
  }, 600000);

  it('retrieves a chunked message from the archive, every piece of it', async () => {
    const alice = await account(104);
    const bobStore = new MemoryStore();
    let bob = await account(105, bobStore);
    await introduce(alice, bob);

    bob.chat.close();
    bob.client.close();
    open.splice(open.indexOf(bob.chat), 1);
    open.splice(open.indexOf(bob.client), 1);

    // Well past one envelope, so it goes out as several — each with its own
    // proof of work and its own detection flag. Retrieval has to bring back
    // all of them or the reassembler has nothing to finish.
    const big = randomBytes(12 * 1024);
    const before = (await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo')).archive.entries;
    await alice.client.send(bob.client.identity, big);
    await waitUntil(
      async () => (await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo')).archive.entries >= before + 4,
      60000,
    );

    bob = await account(105, bobStore);
    const recovered = waitFor<MessagingEvents, 'message'>(
      bob.client,
      'message',
      (m) => m.payload.length === big.length,
    );
    const res = await bob.client.syncArchive({ precision: 4 });
    expect(res.accepted).toBeGreaterThan(0);
    const got = await recovered;
    expect(toHex(got.payload)).toBe(toHex(big));
    expect(got.from).toBe(alice.client.identity);
  }, 600000);

  it('costs one envelope to reach a group of five', async () => {
    const owner = await account(106);
    const members = [await account(107), await account(108), await account(109), await account(110)];
    for (const m of members) await introduce(owner, m);

    const joined = members.map((m) => waitFor<ChatEvents, 'group'>(m.chat, 'group'));
    const groupId = await owner.chat.createGroup('the five', members.map((m) => m.chat.identity));
    await Promise.all(joined);

    // One send, four recipients, ONE envelope. Group sends are flagged, so
    // the archiving node counts them: a per-member send would add four
    // entries here rather than one.
    const entries = async () =>
      (await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo')).archive.entries;
    const beforeSend = await entries();
    const heard = members.map((m) =>
      waitFor<ChatEvents, 'message'>(m.chat, 'message', (e) => e.message.text === 'all of you at once'),
    );
    await owner.chat.sendGroupText(groupId, 'all of you at once');
    await Promise.all(heard);
    expect(await entries()).toBe(beforeSend + 1);

    // A rekey is the opposite trade: the new epoch secret is handed out 1:1,
    // so removing one member costs a message per remaining member. That is
    // the price of the group key moving, and it is worth seeing it paid.
    const removed = members[3]!;
    const beforeRekey = await entries();
    const rekeyed = members.slice(0, 3).map((m) =>
      waitFor<ChatEvents, 'group'>(m.chat, 'group', (g) => g.state.members.length === 4),
    );
    await owner.chat.groupOp(groupId, { kind: 'remove', identity: decodeIdentity(removed.chat.identity) });
    await Promise.all(rekeyed);
    // Three remaining members, three 1:1 envelopes carrying the new secret.
    expect(await entries()).toBe(beforeRekey + 3);

    const still = members.slice(0, 3).map((m) =>
      waitFor<ChatEvents, 'message'>(m.chat, 'message', (e) => e.message.text === 'four of you now'),
    );
    await owner.chat.sendGroupText(groupId, 'four of you now');
    await Promise.all(still);
    const history = await removed.chat.history(groupId);
    expect(history.messages.some((msg) => msg.text === 'four of you now')).toBe(false);
  }, 900000);
});
