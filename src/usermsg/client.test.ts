import { afterEach, describe, expect, it } from 'vitest';
import { MessagingClient, type MessagingEvents, type PeerNetwork } from './client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { generateDevice, signDeviceCert } from '../devices/hierarchy.js';
import { DEVICE_LIST_VERSION, serializeDeviceList, signDeviceList } from '../devices/list.js';
import { decodeIdentity } from './bundle.js';
import { Emitter } from '../net/emitter.js';
import { utf8, fromUtf8 } from '../common/bytes.js';
import { parseEnvelope } from '../bus/envelope.js';
import { FMD_FLAG_SIZE, FMD_GAMMA, fmdTest } from '../bus/fmd.js';

type NetEvents = {
  message: { peerId: string; stem: boolean; payload: Uint8Array };
  peer: { id: string; address: string };
  peerclose: { id: string; address: string };
  error: Error;
};

/** In-memory "network": every broadcast is delivered to every other member, like a relaying node would. */
class Hub {
  members: FakeNetwork[] = [];
  relay(from: FakeNetwork, envelope: Uint8Array, stem: boolean): number {
    let n = 0;
    for (const m of this.members) {
      if (m === from || !m.up) continue;
      n++;
      setTimeout(() => m.emit('message', { peerId: 'hub', stem, payload: envelope }), 1);
    }
    return n;
  }
}

class FakeNetwork extends Emitter<NetEvents> implements PeerNetwork {
  up = false;
  /** Every envelope this member put on the wire, for inspection in tests. */
  sent: Uint8Array[] = [];
  constructor(private hub: Hub) {
    super();
    hub.members.push(this);
  }
  async start(): Promise<void> {
    this.up = true;
    this.emit('peer', { id: 'hub', address: 'hub' });
  }
  stop(): void {
    this.up = false;
  }
  broadcast(envelope: Uint8Array, opts: { stem: boolean }): number {
    this.sent.push(envelope);
    return this.hub.relay(this, envelope, opts.stem);
  }
  medianClockOffset(): number {
    return 0;
  }
  get connectedCount(): number {
    return this.up ? 1 : 0;
  }
}

const clients: MessagingClient[] = [];
afterEach(() => {
  for (const c of clients.splice(0)) c.close();
});

async function mk(hub: Hub, seedByte: number, extra: Partial<Parameters<typeof MessagingClient.create>[0]> = {}) {
  const c = await MessagingClient.create({
    network: 'regtest',
    seed: new Uint8Array(32).fill(seedByte),
    store: new MemoryStore(),
    pool: new FakeNetwork(hub),
    powBits: 4,
    powWorkers: 0,
    ackDelayMs: 50,
    retryTickMs: 200,
    discoveryTimeoutMs: 5000,
    ...extra,
  });
  clients.push(c);
  await c.connect();
  return c;
}

function waitFor<K extends keyof MessagingEvents>(
  client: MessagingClient,
  event: K,
  pred: (v: MessagingEvents[K]) => boolean = () => true,
  ms = 10000,
): Promise<MessagingEvents[K]> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      off();
      reject(new Error(`timeout waiting for ${String(event)}`));
    }, ms);
    const off = client.on(event, (v) => {
      if (pred(v)) {
        clearTimeout(t);
        off();
        resolve(v);
      }
    });
  });
}

describe('MessagingClient end to end (in-memory hub)', () => {
  it('sends with a known bundle, receives, acks, and ratchets reply keys', async () => {
    const hub = new Hub();
    const alice = await mk(hub, 1);
    const bob = await mk(hub, 2);
    await alice.addContact(bob.bundle());

    const retries: number[] = [];
    bob.on('sent', (s) => { if (s.attempt > 1) retries.push(s.attempt); });
    alice.on('sent', (s) => { if (s.attempt > 1) retries.push(s.attempt); });
    const gotBob = waitFor(bob, 'message');
    const acked = waitFor(alice, 'ack');
    const id = await alice.send(bob.identity, utf8('hello bob'));
    const m = await gotBob;
    expect(fromUtf8(m.payload)).toBe('hello bob');
    expect(m.from).toBe(alice.identity);
    expect(m.scope).toBe('inbox');
    expect(m.topic).toBe('msg');
    const a = await acked;
    expect(a.msgId).toEqual(id);
    expect(alice.outbox.size).toBe(0);

    // Bob learned alice's reply key from her frame; alice learned bob's from the ack.
    expect(bob.contacts.get(alice.identityBytes)?.nextKey).toBeDefined();
    expect(alice.contacts.get(bob.identityBytes)?.nextKey).toBeDefined();

    // Reply from bob rides alice's session key (scope 'session'), no bundle needed on bob's side
    // because alice's ack carried her reply key AND bob has no bundle for alice → discovery would
    // be needed only for the prekey fallback. Here nextKey exists so no discovery happens.
    const gotAlice = waitFor(alice, 'message');
    await bob.send(alice.identity, utf8('hi alice'));
    const r = await gotAlice;
    expect(fromUtf8(r.payload)).toBe('hi alice');
    expect(r.scope).toBe('session');
    await waitFor(bob, 'ack');
    // Acks must reach the sender on the first try: no retransmissions anywhere.
    expect(retries).toEqual([]);
  });

  it('discovers a prekey over the bus when only the identity is known', async () => {
    const hub = new Hub();
    const alice = await mk(hub, 3);
    const bob = await mk(hub, 4);
    const learned = waitFor(alice, 'contact', (c) => c.identity === bob.identity);
    const got = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('found you'));
    await learned;
    expect(fromUtf8((await got).payload)).toBe('found you');
  }, 20000);

  it('learns a clue key over discovery and flags later sends', async () => {
    // Discovery is the only place the clue key is published — it is 1152 bytes
    // and deliberately not part of the navmsg1… address string. Without it a
    // message is delivered normally but can never be retrieved after the fact.
    const hub = new Hub();
    const net = new FakeNetwork(hub);
    const alice = await mk(hub, 20, { pool: net });
    const bob = await mk(hub, 21);

    const learned = waitFor(alice, 'contact', (c) => c.identity === bob.identity);
    const first = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('before discovery'));
    await learned;
    expect(fromUtf8((await first).payload)).toBe('before discovery');

    // The first send could not be flagged — the clue key was not known yet.
    // A later one is, and it tests against Bob's own detection key.
    net.sent.length = 0;
    const second = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('after discovery'));
    expect(fromUtf8((await second).payload)).toBe('after discovery');

    const flags = net.sent.map((b) => parseEnvelope(b).flag).filter((f) => f.length > 0);
    expect(flags.length).toBeGreaterThan(0);
    for (const flag of flags) {
      expect(flag.length).toBe(FMD_FLAG_SIZE);
      expect(fmdTest(bob.detectionKey(FMD_GAMMA), flag)).toBe(true);
    }
    // A third party cannot tell the flag is Bob's.
    const stranger = await mk(hub, 22);
    expect(fmdTest(stranger.detectionKey(FMD_GAMMA), flags[0]!)).toBe(false);
  }, 30000);

  it('can send unflagged when offline retrieval does not matter', async () => {
    const hub = new Hub();
    const net = new FakeNetwork(hub);
    const alice = await mk(hub, 23, { pool: net });
    const bob = await mk(hub, 24);
    await alice.addContact(bob.bundle());
    // addContact only carries the v1 bundle, so there is no clue key yet and
    // nothing to flag with — the send still works.
    net.sent.length = 0;
    const got = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('hi'), { archivable: false });
    await got;
    for (const b of net.sent) expect(parseEnvelope(b).flag.length).toBe(0);
  }, 20000);

  it('chunks large payloads and retries until acked', async () => {
    const hub = new Hub();
    const alice = await mk(hub, 5);
    const bob = await mk(hub, 6);
    await alice.addContact(bob.bundle());
    const big = new Uint8Array(9000).map((_, i) => i % 251);
    const got = waitFor(bob, 'message');
    const acked = waitFor(alice, 'ack');
    await alice.send(bob.identity, big);
    expect((await got).payload).toEqual(big);
    await acked;
  }, 30000);

  it('retries when the recipient was offline and expires after ttl', async () => {
    const hub = new Hub();
    const alice = await mk(hub, 7);
    const bob = await mk(hub, 8);
    await alice.addContact(bob.bundle());
    bob.pool.stop(); // bob offline
    const id = await alice.send(bob.identity, utf8('are you there'), { ttlMs: 1500 });
    expect(alice.outbox.get(id)).toBeDefined();
    const expired = await waitFor(alice, 'expired', (e) => e.msgId.every((b, i) => b === id[i]), 10000);
    expect(expired.msgId).toEqual(id);
    expect(alice.outbox.size).toBe(0);
  }, 20000);

  it('public topics reach subscribers only', async () => {
    const hub = new Hub();
    const alice = await mk(hub, 9);
    const bob = await mk(hub, 10);
    const carol = await mk(hub, 11);
    const bobGot: string[] = [];
    bob.subscribe('news', (m) => bobGot.push(fromUtf8(m.payload)));
    let carolGot = 0;
    carol.on('message', () => carolGot++);
    await alice.publish('news', utf8('extra extra'));
    await new Promise((r) => setTimeout(r, 500));
    expect(bobGot).toEqual(['extra extra']);
    expect(carolGot).toBe(0);
  });

  it('rejects reserved topics and unsigned senders cannot be acked', async () => {
    const hub = new Hub();
    const alice = await mk(hub, 12);
    const bob = await mk(hub, 13);
    await alice.addContact(bob.bundle());
    await expect(alice.send(bob.identity, utf8('x'), { topic: '_p2pmsg/ack' })).rejects.toThrow(/reserved/);
    const got = waitFor(bob, 'message');
    await alice.send(bob.identity, utf8('anon'), { sign: false });
    const m = await got;
    expect(m.from).toBeUndefined();
    expect(alice.outbox.size).toBe(0);
  });
});

describe('MessagingClient device-signed frames', () => {
  it('accepts a listed device and rejects one that was revoked', async () => {
    // NOTE on the setup: the sending client is given the account seed as well
    // as a device key, because building a Keyring from a pairing grant alone
    // is still to come. What is under test is the RECEIVER's decision, which
    // is genuine: it sees a device-signed frame and consults the device list
    // it learned from the sender's bundle.
    const hub = new Hub();
    const net = new FakeNetwork(hub);
    const device = generateDevice();
    const alice = await mk(hub, 30, { pool: net });
    const bob = await mk(hub, 31);

    const identityPub = decodeIdentity(alice.identity);
    const createdAt = 1700000000n;
    const caps = 0;
    const entry = {
      deviceId: device.id,
      devicePub: device.pub,
      createdAt,
      caps,
      label: 'phone',
      cert: signDeviceCert(alice.keyring.identity.sk, { devicePub: device.pub, createdAt, caps }),
    };
    const list = signDeviceList(
      { version: DEVICE_LIST_VERSION, accountEpoch: 0, devices: [entry] },
      alice.keyring.identity.sk,
    );
    alice.keyring.deviceList = serializeDeviceList(list);

    // Bob learns the list through ordinary prekey discovery.
    const learned = waitFor(bob, 'contact', (c) => c.identity === alice.identity);
    await bob.addContact(alice.identity);
    await alice.addContact(bob.bundle());
    await bob.send(alice.identity, utf8('ping'));
    await learned;

    // Now Alice sends as the secondary device.
    const asDevice = await mk(hub, 30, {
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub },
    });
    await asDevice.addContact(bob.bundle());
    const got = waitFor(bob, 'message', (m) => fromUtf8(m.payload) === 'from my phone');
    await asDevice.send(bob.identity, utf8('from my phone'));
    const ev = await got;
    expect(ev.from).toBe(alice.identity);

    // Revoke the device: publish a list that no longer names it.
    const replacement = generateDevice();
    const goodRevoked = signDeviceList(
      {
        version: DEVICE_LIST_VERSION,
        accountEpoch: 1,
        devices: [
          {
            deviceId: replacement.id,
            devicePub: replacement.pub,
            createdAt,
            caps,
            label: 'laptop',
            cert: signDeviceCert(alice.keyring.identity.sk, { devicePub: replacement.pub, createdAt, caps }),
          },
        ],
      },
      alice.keyring.identity.sk,
    );
    await bob.contacts.setDeviceList(identityPub, serializeDeviceList(goodRevoked));

    let delivered = false;
    const off = bob.on('message', (m) => {
      if (fromUtf8(m.payload) === 'after revocation') delivered = true;
    });
    await asDevice.send(bob.identity, utf8('after revocation'));
    await new Promise((r) => setTimeout(r, 1500));
    off();
    // The device key still produces a valid signature; it is simply no longer
    // one of Alice's devices, which is the whole point of revocation.
    expect(delivered).toBe(false);
  }, 40000);
});
