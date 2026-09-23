import { afterEach, describe, expect, it } from 'vitest';
import { MessagingClient, type MessagingEvents, type PeerNetwork } from './client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { generateDevice, signDeviceCert } from '../devices/hierarchy.js';
import {
  DEVICE_LIST_VERSION,
  isListedDevice,
  parseDeviceList,
  serializeDeviceList,
  signDeviceList,
  verifyDeviceList,
} from '../devices/list.js';
import { decodeIdentity } from './bundle.js';
import { Emitter } from '../net/emitter.js';
import { utf8, fromUtf8, toHex } from '../common/bytes.js';
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
    // Generous: these suites run alongside native builds, and a discovery
    // that times out under load says nothing about correctness.
    discoveryTimeoutMs: 20000,
    ...extra,
  });
  clients.push(c);
  await c.connect();
  return c;
}

/** Poll until `pred` holds. For state no event announces. */
async function waitUntilTrue(pred: () => boolean, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 20));
  }
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
      cert: signDeviceCert(alice.keyring.requireIdentitySecret().sk, { devicePub: device.pub, createdAt, caps }),
    };
    const list = signDeviceList(
      { version: DEVICE_LIST_VERSION, accountEpoch: 0, devices: [entry] },
      alice.keyring.requireIdentitySecret().sk,
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
            cert: signDeviceCert(alice.keyring.requireIdentitySecret().sk, { devicePub: replacement.pub, createdAt, caps }),
          },
        ],
      },
      alice.keyring.requireIdentitySecret().sk,
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

describe('secondary device built from a pairing grant', () => {
  /** Everything a grant carries, produced the way a primary would. */
  function grantFrom(primary: MessagingClient) {
    const device = generateDevice();
    const createdAt = 1700000000n;
    const caps = 0;
    const identitySk = primary.keyring.requireIdentitySecret().sk;
    const entry = {
      deviceId: device.id,
      devicePub: device.pub,
      createdAt,
      caps,
      label: 'phone',
      cert: signDeviceCert(identitySk, { devicePub: device.pub, createdAt, caps }),
    };
    const list = signDeviceList({ version: DEVICE_LIST_VERSION, accountEpoch: 0, devices: [entry] }, identitySk);
    primary.keyring.deviceList = serializeDeviceList(list);
    return {
      device,
      grant: {
        accountSecret: primary.keyring.accountSecret(),
        identityPub: primary.keyring.identity.pub,
        epoch: primary.keyring.epoch,
      },
    };
  }

  it('shares the account address and inbox key with the primary', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 40);
    const { device, grant } = grantFrom(primary);
    const secondary = await mk(hub, 41, {
      seed: undefined,
      grant,
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });

    // Same account: same address, and the same key senders encrypt to — which
    // is why ONE envelope reaches both devices.
    expect(secondary.identity).toBe(primary.identity);
    expect(secondary.keyring.prekey.pub).toEqual(primary.keyring.prekey.pub);
    expect(secondary.keyring.isPrimary).toBe(false);
    expect(primary.keyring.isPrimary).toBe(true);
  }, 30000);

  it('cannot sign as the account, and says so plainly', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 42);
    const { device, grant } = grantFrom(primary);
    const secondary = await mk(hub, 43, {
      seed: undefined,
      grant,
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });

    // These are the operations that need the seed. A secondary failing them
    // loudly is the point: silently producing an unsigned or wrongly signed
    // bundle would be far worse.
    expect(() => secondary.keyring.requireIdentitySecret()).toThrow(/device key/);
    expect(() => secondary.bundle()).toThrow(/device key/);
    await expect(secondary.keyring.rotateAccountEpoch()).rejects.toThrow(/primary/);
    // And it holds only the epoch it was granted.
    expect(() => secondary.keyring.accountSecret(99)).toThrow(/current account epoch/);
  }, 30000);

  it('both devices receive the same message from one envelope', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 44);
    const { device, grant } = grantFrom(primary);
    const secondary = await mk(hub, 45, {
      seed: undefined,
      grant,
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });
    const sender = await mk(hub, 46);
    await sender.addContact(primary.bundle());

    const atPrimary = waitFor(primary, 'message');
    const atSecondary = waitFor(secondary, 'message');
    await sender.send(primary.identity, utf8('reaches both'));
    expect(fromUtf8((await atPrimary).payload)).toBe('reaches both');
    expect(fromUtf8((await atSecondary).payload)).toBe('reaches both');
  }, 30000);

  it('sends with its device key and the recipient accepts it', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 47);
    const { device, grant } = grantFrom(primary);
    const secondary = await mk(hub, 48, {
      seed: undefined,
      grant,
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });
    const peer = await mk(hub, 49);

    // The peer discovers the account from the PRIMARY, which is what publishes
    // the bundle carrying the device list.
    const learned = waitFor(peer, 'contact', (c) => c.identity === primary.identity);
    await peer.addContact(primary.identity);
    await primary.addContact(peer.bundle());
    await peer.send(primary.identity, utf8('hello'));
    await learned;

    await secondary.addContact(peer.bundle());
    const got = waitFor(peer, 'message', (m) => fromUtf8(m.payload) === 'sent from the phone');
    await secondary.send(peer.identity, utf8('sent from the phone'));
    const ev = await got;
    // Attributed to the ACCOUNT, not the device: which device sent it is not
    // the correspondent's concern.
    expect(ev.from).toBe(primary.identity);
  }, 40000);
});

describe('device pairing over the bus', () => {
  it('pairs a new device end to end and the grant works', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 50);
    // The joining device runs on a throwaway identity purely to reach the bus;
    // it publishes nothing under it and discards it once paired.
    const joining = await mk(hub, 51);

    const { offer, expiresAt } = primary.startPairing();
    expect(offer.startsWith('navpair1')).toBe(true);
    expect(expiresAt).toBeGreaterThan(Date.now());

    const asked = waitFor(primary, 'pairingRequest');
    const { sas: onDevice, device } = await joining.requestPairing(offer, "Alex's phone");
    const req = await asked;

    // The two strings must match; this is the only thing authenticating the
    // exchange, so a mismatch is what a user is meant to catch.
    expect(req.sas).toBe(onDevice);
    expect(req.label).toBe("Alex's phone");
    expect(toHex(req.devicePub)).toBe(toHex(device.pub));

    const granted = waitFor(joining, 'paired');
    await primary.confirmPairing(req.devicePub);
    const grant = await granted;

    expect(grant.accountEpoch).toBe(primary.keyring.epoch);
    expect(toHex(grant.identityPub)).toBe(toHex(primary.keyring.identity.pub));
    // The grant carries the account secret and never the seed.
    expect(grant.accountSecret).toHaveLength(32);

    // The device list the primary now publishes names the new device.
    const list = parseDeviceList(primary.keyring.deviceList);
    expect(verifyDeviceList(primary.keyring.identity.pub, list).ok).toBe(true);
    expect(isListedDevice(list, device.pub)).toBe(true);

    // And the grant actually builds a working secondary.
    const secondary = await mk(hub, 52, {
      seed: undefined,
      grant: { accountSecret: grant.accountSecret, identityPub: grant.identityPub, epoch: grant.accountEpoch },
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });
    expect(secondary.identity).toBe(primary.identity);
    expect(secondary.keyring.prekey.pub).toEqual(primary.keyring.prekey.pub);
  }, 40000);

  it('shows a different string to a device answering a substituted offer', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 53);
    const attacker = await mk(hub, 54);
    const joining = await mk(hub, 55);

    const real = primary.startPairing();
    // The attacker photographed the QR and makes its own offer instead.
    const fake = attacker.startPairing();
    const { sas: deviceSees } = await joining.requestPairing(fake.offer, 'victim');
    const asked = waitFor(primary, 'pairingRequest', () => true, 2000).catch(() => undefined);

    // The primary never hears about it — the device answered a different
    // topic — and even if it had, the strings would not match.
    expect(await asked).toBeUndefined();
    expect(deviceSees).toHaveLength(6);
    expect(real.offer).not.toBe(fake.offer);
  }, 30000);

  it('refuses to admit devices from a secondary', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 56);
    const device = generateDevice();
    const secondary = await mk(hub, 57, {
      seed: undefined,
      grant: {
        accountSecret: primary.keyring.accountSecret(),
        identityPub: primary.keyring.identity.pub,
        epoch: primary.keyring.epoch,
      },
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: primary.keyring.identity.pub },
    });
    // Admitting a device means signing a certificate, which needs the seed.
    expect(() => secondary.startPairing()).toThrow(/primary/);
  }, 30000);

  it('ignores a confirmation for a device that never asked', async () => {
    const hub = new Hub();
    const primary = await mk(hub, 58);
    primary.startPairing();
    await expect(primary.confirmPairing(generateDevice().pub)).rejects.toThrow(/no pairing request/);
  }, 30000);
});

describe('device revocation', () => {
  async function accountWithTwoDevices(hub: Hub, seedByte: number) {
    const primary = await mk(hub, seedByte);
    const joining = await mk(hub, seedByte + 1);
    const { offer } = primary.startPairing();
    const asked = waitFor(primary, 'pairingRequest');
    const { device } = await joining.requestPairing(offer, 'phone');
    const req = await asked;
    const granted = waitFor(joining, 'paired');
    await primary.confirmPairing(req.devicePub);
    const grant = await granted;
    const secondary = await mk(hub, seedByte + 2, {
      seed: undefined,
      grant: { accountSecret: grant.accountSecret, identityPub: grant.identityPub, epoch: grant.accountEpoch },
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });
    return { primary, secondary, device };
  }

  it('rotates the epoch, drops the device from the list, and moves every key', async () => {
    const hub = new Hub();
    const { primary, device } = await accountWithTwoDevices(hub, 60);
    const before = { epoch: primary.keyring.epoch, prekey: toHex(primary.keyring.prekey.pub) };

    const res = await primary.revokeDevice(device.pub);
    expect(res.epoch).toBe(before.epoch + 1);
    expect(toHex(primary.keyring.prekey.pub)).not.toBe(before.prekey);

    const list = parseDeviceList(res.deviceList);
    expect(isListedDevice(list, device.pub)).toBe(false);
    expect(list.accountEpoch).toBe(res.epoch);
    expect(verifyDeviceList(primary.keyring.identity.pub, list).ok).toBe(true);
  }, 40000);

  it('refuses a bundle from before an epoch it already knows about', async () => {
    // Discovery re-sends while it waits, so an answer to an earlier attempt
    // can arrive after a rotation. A signed bundle stays valid forever, so
    // taking it would put the sender back on keys the account has moved off —
    // and those are exactly the keys a revoked device still holds.
    const hub = new Hub();
    const { primary, device } = await accountWithTwoDevices(hub, 76);
    const peer = await mk(hub, 77);
    await peer.addContact(primary.bundle());
    await peer.discover(primary.identity);
    const stale = primary.keyring.extendedBundle();

    await primary.revokeDevice(device.pub);
    await peer.discover(primary.identity);
    const current = toHex(peer.contacts.get(decodeIdentity(primary.identity))!.bundle!.prekey);
    expect(current).toBe(toHex(primary.keyring.prekey.pub));

    // The stale answer, arriving late and perfectly well signed.
    // Reaching into the private handler: this is the path a late discovery
    // answer takes, and there is no way to time one deterministically.
    await (peer as unknown as { learnBundle(b: unknown): Promise<void> }).learnBundle(stale);
    expect(toHex(peer.contacts.get(decodeIdentity(primary.identity))!.bundle!.prekey)).toBe(current);
  }, 40000);

  it('moves the key the bus listens on, not just the one it publishes', async () => {
    // Rotating the keyring alone republishes a prekey nothing decrypts: every
    // sender that then discovers the new bundle addresses a key the bus was
    // never told about, and the account goes quietly deaf.
    const hub = new Hub();
    const { primary, device } = await accountWithTwoDevices(hub, 72);
    const peer = await mk(hub, 73);
    await peer.addContact(primary.bundle());
    await primary.revokeDevice(device.pub);
    await peer.discover(primary.identity);

    const got = waitFor(primary, 'message', (m) => fromUtf8(m.payload) === 'to the new key');
    await peer.send(primary.identity, utf8('to the new key'));
    expect(fromUtf8((await got).payload)).toBe('to the new key');
  }, 40000);

  it('tells contacts their cached key moved when asked to', async () => {
    const hub = new Hub();
    const { primary, device } = await accountWithTwoDevices(hub, 74);
    const peer = await mk(hub, 75);
    await peer.addContact(primary.bundle());
    const cached = toHex(peer.contacts.get(decodeIdentity(primary.identity))!.bundle!.prekey);

    // Nothing local can stop a revoked device reading what a contact still
    // addresses to the old key — it holds its own copy of the secret. The
    // senders are the only lever.
    await primary.revokeDevice(device.pub, { notifyContacts: true });
    await waitUntilTrue(
      () => toHex(peer.contacts.get(decodeIdentity(primary.identity))!.bundle!.prekey) !== cached,
      10000,
    );
    expect(toHex(peer.contacts.get(decodeIdentity(primary.identity))!.bundle!.prekey)).toBe(
      toHex(primary.keyring.prekey.pub),
    );
  }, 40000);

  it('hands the new epoch to the devices that remain', async () => {
    const hub = new Hub();
    const { primary } = await accountWithTwoDevices(hub, 64);
    // Pair a third device so there is a survivor to notify.
    const joining = await mk(hub, 70);
    const { offer } = primary.startPairing();
    const asked = waitFor(primary, 'pairingRequest');
    const { device: third } = await joining.requestPairing(offer, 'laptop');
    const req = await asked;
    const granted = waitFor(joining, 'paired');
    await primary.confirmPairing(req.devicePub);
    const grant = await granted;
    const survivor = await mk(hub, 71, {
      seed: undefined,
      grant: { accountSecret: grant.accountSecret, identityPub: grant.identityPub, epoch: grant.accountEpoch },
      device: { keypair: { sk: third.sk, pub: third.pub }, identityPub: grant.identityPub },
    });

    // Revoke the first secondary, keeping the third device.
    const victim = parseDeviceList(primary.keyring.deviceList).devices.find(
      (d) =>
        toHex(d.devicePub) !== toHex(third.pub) &&
        toHex(d.devicePub) !== toHex(primary.keyring.identity.pub),
    )!;
    const moved = waitFor(survivor, 'accountEpoch');
    const res = await primary.revokeDevice(victim.devicePub);
    const ev = await moved;

    expect(ev.epoch).toBe(res.epoch);
    // The survivor now derives the same inbox key as the primary again.
    expect(toHex(survivor.keyring.prekey.pub)).toBe(toHex(primary.keyring.prekey.pub));
    expect(survivor.keyring.epoch).toBe(res.epoch);
  }, 60000);

  it('refuses to revoke from a secondary, or to revoke a device that is not listed', async () => {
    const hub = new Hub();
    const { primary, secondary } = await accountWithTwoDevices(hub, 74);
    await expect(secondary.revokeDevice(generateDevice().pub)).rejects.toThrow(/primary/);
    await expect(primary.revokeDevice(generateDevice().pub)).rejects.toThrow(/not on the list/);
  }, 40000);

  it('never accepts a device list that goes backwards', async () => {
    // A signed list stays valid forever, so replaying the one from before a
    // revocation would re-admit the revoked device.
    const hub = new Hub();
    const { primary, device } = await accountWithTwoDevices(hub, 78);
    const peer = await mk(hub, 81);
    const identityPub = primary.keyring.identity.pub;
    const stale = primary.keyring.deviceList;
    expect(isListedDevice(parseDeviceList(stale), device.pub)).toBe(true);

    await primary.revokeDevice(device.pub);
    const fresh = primary.keyring.deviceList;

    await peer.contacts.setDeviceList(identityPub, fresh);
    // Feeding the old list back must not re-admit the device.
    const current = parseDeviceList(peer.contacts.get(identityPub)!.deviceList!);
    expect(current.accountEpoch).toBe(parseDeviceList(fresh).accountEpoch);
    expect(parseDeviceList(stale).accountEpoch).toBeLessThan(current.accountEpoch);
    expect(isListedDevice(current, device.pub)).toBe(false);
  }, 40000);
});

describe('sent-message mirroring', () => {
  it('shows a secondary what the primary sent', async () => {
    // An outgoing message is encrypted to the RECIPIENT, so our other devices
    // cannot read it. Without a mirror a paired phone shows half of every
    // conversation.
    const hub = new Hub();
    const primary = await mk(hub, 110);
    const joining = await mk(hub, 111);
    const { offer } = primary.startPairing();
    const asked = waitFor(primary, 'pairingRequest');
    const { device } = await joining.requestPairing(offer, 'phone');
    const req = await asked;
    const granted = waitFor(joining, 'paired');
    await primary.confirmPairing(req.devicePub);
    const grant = await granted;
    const secondary = await mk(hub, 112, {
      seed: undefined,
      grant: { accountSecret: grant.accountSecret, identityPub: grant.identityPub, epoch: grant.accountEpoch },
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
    });

    const peer = await mk(hub, 113);
    await primary.addContact(peer.bundle());

    const mirrored = waitFor(secondary, 'mirrored');
    await primary.send(peer.identity, utf8('sent from the desktop'));
    await primary.flushMirror();
    const ev = await mirrored;
    expect(fromUtf8(ev.payload)).toBe('sent from the desktop');
    expect(ev.to).toBe(peer.identity);
  }, 60000);

  it('sends no mirror at all when the account has one device', async () => {
    // The copy costs a whole envelope and a whole proof of work; with nobody
    // to read it that is pure waste.
    const hub = new Hub();
    const net = new FakeNetwork(hub);
    const solo = await mk(hub, 114, { pool: net });
    const peer = await mk(hub, 115);
    await solo.addContact(peer.bundle());

    await solo.send(peer.identity, utf8('no mirror needed'));
    await new Promise((r) => setTimeout(r, 300));
    // Count only what the flush itself emits: adding a contact also triggers
    // discovery, so counting every envelope would measure the wrong thing.
    net.sent.length = 0;
    await solo.flushMirror();
    await new Promise((r) => setTimeout(r, 300));
    expect(net.sent.length).toBe(0);
  }, 30000);
});

describe('MirrorBatcher', () => {
  const entry = (n: number, size = 10) => ({
    recipient: new Uint8Array(48).fill(n),
    topic: 'msg',
    timestamp: BigInt(n),
    payload: new Uint8Array(size).fill(n),
  });

  it('accumulates until the budget is reached', async () => {
    const { MirrorBatcher } = await import('./mirror.js');
    const b = new MirrorBatcher(10_000, 64);
    expect(b.add(entry(1))).toBeUndefined();
    expect(b.add(entry(2))).toBeUndefined();
    expect(b.size).toBe(2);
    expect(b.flush()).toHaveLength(2);
    expect(b.size).toBe(0);
  });

  it('flushes before an entry that would overflow, so a batch always fits', async () => {
    const { MirrorBatcher } = await import('./mirror.js');
    const b = new MirrorBatcher(200, 64);
    expect(b.add(entry(1, 100))).toBeUndefined();
    const batch = b.add(entry(2, 100));
    expect(batch).toHaveLength(1); // the first one went out on its own
    expect(b.size).toBe(1); // the new one is pending
  });

  it('respects the entry count cap', async () => {
    const { MirrorBatcher } = await import('./mirror.js');
    const b = new MirrorBatcher(1_000_000, 3);
    expect(b.add(entry(1))).toBeUndefined();
    expect(b.add(entry(2))).toBeUndefined();
    expect(b.add(entry(3))).toHaveLength(3);
  });

  it('round trips the wire form', async () => {
    const { parseMirror, serializeMirror } = await import('./mirror.js');
    const entries = [entry(1, 5), entry(2, 0)];
    expect(parseMirror(serializeMirror(entries))).toEqual(entries);
    expect(parseMirror(serializeMirror([]))).toEqual([]);
  });
});
