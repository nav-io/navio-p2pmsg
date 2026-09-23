/**
 * End-to-end: several devices on one account, across a relay.
 *
 * `e2e.int.test.ts` pairs a second device against a single node. This suite
 * puts the devices on DIFFERENT nodes, which is the realistic shape — a phone
 * and a desktop rarely share a peer — and covers what revocation is actually
 * for: the revoked device losing access, to the account and to the groups the
 * account administers. Payments ride along, since they are the other thing a
 * contact sends that is not text.
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
import { loopbackPair } from './stream/transport.js';
import { GroupRole, memberOf } from './chat/group/state.js';
import { decodeIdentity } from './usermsg/bundle.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<T extends ChatEvents | MessagingEvents, K extends keyof T>(
  emitter: { on(ev: K, cb: (v: T[K]) => void): () => void },
  ev: K,
  pred: (v: T[K]) => boolean = () => true,
  ms = 60000,
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

async function waitUntil(pred: () => Promise<boolean>, ms = 30000): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** Nothing matching arrives within `ms`. Asserting an absence needs time. */
function nothingWithin<T extends ChatEvents | MessagingEvents, K extends keyof T>(
  emitter: { on(ev: K, cb: (v: T[K]) => void): () => void },
  ev: K,
  pred: (v: T[K]) => boolean,
  ms: number,
): Promise<boolean> {
  return new Promise((resolve) => {
    const off = emitter.on(ev, (v) => {
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

describe.skipIf(!haveBinary)('end to end: devices across a relay', () => {
  const nodes: RegtestNode[] = [];
  const open: Array<{ close(): void }> = [];

  function clientOptions(node: RegtestNode, store: Store) {
    return {
      network: 'regtest' as const,
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
    };
  }

  async function connect(client: MessagingClient) {
    open.push(client);
    const up = waitFor<MessagingEvents, 'peer'>(client, 'peer');
    await client.connect();
    await up;
    return client;
  }

  async function account(seedByte: number, node: RegtestNode, store: Store = new MemoryStore()) {
    const client = await connect(
      await MessagingClient.create({ ...clientOptions(node, store), seed: new Uint8Array(32).fill(seedByte) }),
    );
    client.on('error', (e) => console.error('[client]', e.message));
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
    // Clue keys cross the same hops the messages will, and nothing is
    // archivable until they have.
    await waitUntil(
      async () =>
        a.client.contacts.get(decodeIdentity(b.chat.identity))?.clueKey !== undefined &&
        b.client.contacts.get(decodeIdentity(a.chat.identity))?.clueKey !== undefined,
      60000,
    );
  }

  /** Pair a fresh device onto `primary`'s account, on `node`. */
  async function pairDevice(primary: Account, node: RegtestNode) {
    const joining = await connect(
      await MessagingClient.create({
        ...clientOptions(node, new MemoryStore()),
        seed: randomBytes(32),
      }),
    );
    const { offer } = primary.client.startPairing();
    const asked = waitFor<MessagingEvents, 'pairingRequest'>(primary.client, 'pairingRequest');
    const { sas, device } = await joining.requestPairing(offer, 'phone');
    const req = await asked;
    // The short code is what a human compares; it must match on both sides or
    // the pairing is with somebody else.
    expect(req.sas).toBe(sas);

    const granted = waitFor<MessagingEvents, 'paired'>(joining, 'paired');
    await primary.client.confirmPairing(req.devicePub);
    const grant = await granted;

    const store = new MemoryStore();
    const secondary = await connect(
      await MessagingClient.create({
        ...clientOptions(node, store),
        grant: { accountSecret: grant.accountSecret, identityPub: grant.identityPub, epoch: grant.accountEpoch },
        device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
      }),
    );
    secondary.on('error', (e) => console.error('[secondary]', e.message));
    const chat = await ChatClient.create({ client: secondary, store });
    chat.on('error', (e) => console.error('[secondary chat]', e.message));
    open.push(chat);
    return { client: secondary, chat, store, devicePub: device.pub, grant };
  }

  beforeAll(async () => {
    // Two nodes, so a device and its account can sit on different peers.
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8'] }));
    nodes.push(await startRegtestNode({ extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8', '-p2pmsgarchive=1'] }));
    await nodes[0]!.rpc('addnode', [`127.0.0.1:${nodes[1]!.port}`, 'onetry']);
    await waitUntil(
      async () => (await nodes[0]!.rpc<{ relay_capable_peers: number }>('getp2pmsginfo')).relay_capable_peers >= 1,
      60000,
    );
  }, 300000);

  afterAll(async () => {
    for (const c of open.splice(0)) c.close();
    await Promise.all(nodes.splice(0).map((n) => n.stop()));
  });

  it('pairs a device on the other node, mirrors to it, and cuts it off on revoke', async () => {
    const primary = await account(60, nodes[0]!);
    const peer = await account(61, nodes[0]!);
    await introduce(primary, peer);
    const secondary = await pairDevice(primary, nodes[1]!);

    // Same account seen from two peers: one envelope, both devices.
    expect(secondary.client.identity).toBe(primary.client.identity);
    const atPrimary = waitFor<MessagingEvents, 'message'>(primary.client, 'message');
    const atSecondary = waitFor<MessagingEvents, 'message'>(secondary.client, 'message');
    await peer.client.send(primary.client.identity, utf8('for both devices'));
    expect(fromUtf8((await atPrimary).payload)).toBe('for both devices');
    expect(fromUtf8((await atSecondary).payload)).toBe('for both devices');

    // What the desktop sends is mirrored to the phone, so the phone shows the
    // whole conversation rather than half of it.
    const mirrored = waitFor<MessagingEvents, 'mirrored'>(secondary.client, 'mirrored');
    await primary.client.send(peer.client.identity, utf8('sent from the desktop'));
    await primary.client.flushMirror();
    expect(fromUtf8((await mirrored).payload)).toBe('sent from the desktop');

    // And it lands in the phone's history as ours, not just as a transport
    // event — otherwise the phone shows half a conversation.
    const chatted = waitFor<ChatEvents, 'message'>(
      secondary.chat,
      'message',
      (e) => e.message.text === 'typed on the desktop',
    );
    await primary.chat.sendText(peer.chat.identity, 'typed on the desktop');
    await primary.client.flushMirror();
    await chatted;
    const onPhone = await secondary.chat.history(secondary.chat.conversationWith(peer.chat.identity));
    expect(onPhone.messages.map((m) => m.text)).toContain('typed on the desktop');

    // Revoking rotates the account epoch and drops the device from the list.
    const beforePrekey = toHex(primary.client.keyring.prekey.pub);
    const revoked = await primary.client.revokeDevice(secondary.devicePub);
    expect(revoked.epoch).toBe(secondary.grant.accountEpoch + 1);
    expect(toHex(primary.client.keyring.prekey.pub)).not.toBe(beforePrekey);

    // Cut-off is not instant, and pretending otherwise would be the dangerous
    // reading. A sender still holding the old bundle sends to the old prekey,
    // which stays readable through the grace window — so the revoked device
    // still sees this one.
    const stillReadable = waitFor<MessagingEvents, 'message'>(
      secondary.client,
      'message',
      (m) => fromUtf8(m.payload) === 'during the grace window',
    );
    await peer.client.send(primary.client.identity, utf8('during the grace window'));
    await stillReadable;

    // Once the sender learns the new bundle, every later message goes to keys
    // the revoked device does not have.
    await peer.client.discover(primary.client.identity);
    const atPrimaryAgain = waitFor<MessagingEvents, 'message'>(
      primary.client,
      'message',
      (m) => fromUtf8(m.payload) === 'after the revoke',
    );
    const notAtSecondary = nothingWithin<MessagingEvents, 'message'>(
      secondary.client,
      'message',
      (m) => fromUtf8(m.payload) === 'after the revoke',
      15000,
    );
    await peer.client.send(primary.client.identity, utf8('after the revoke'));
    await atPrimaryAgain;
    expect(await notAtSecondary).toBe(true);
  }, 600000);

  it('rekeys the groups it administers when a device is revoked, and names the ones it cannot', async () => {
    const primary = await account(62, nodes[0]!);
    const friend = await account(63, nodes[1]!);
    await introduce(primary, friend);
    const secondary = await pairDevice(primary, nodes[1]!);

    // One group we own, one we are only a member of. Revocation can rotate the
    // first; the second needs its own admin, and the honest thing is to say so.
    const inFriend = waitFor<ChatEvents, 'group'>(friend.chat, 'group');
    const ours = await primary.chat.createGroup('ours', [friend.chat.identity]);
    await inFriend;
    const inPrimary = waitFor<ChatEvents, 'group'>(primary.chat, 'group');
    const theirs = await friend.chat.createGroup('theirs', [primary.chat.identity]);
    await inPrimary;
    // The membership frame went to the friend, not to our own devices; the
    // phone learns the group from the mirror of what the desktop sent.
    await primary.client.flushMirror();
    await waitUntil(async () => (await secondary.chat.groupState(ours)) !== undefined, 60000);

    // The secondary is a member of the account, so it reads group traffic.
    const seen = waitFor<ChatEvents, 'message'>(
      secondary.chat,
      'message',
      (e) => e.message.text === 'while the phone was ours',
    );
    await primary.chat.sendGroupText(ours, 'while the phone was ours');
    await seen;

    // Rotating the ACCOUNT epoch does not rotate a GROUP's keys: the revoked
    // device still holds the group secret it was given. Groups we administer
    // are rekeyed; the rest can only be rotated by their own admin, and the
    // honest thing is to name them. Subscribed before the revoke, because
    // revoking is what sets it off.
    const flagged = waitFor<ChatEvents, 'groupsNeedRekey'>(primary.chat, 'groupsNeedRekey');
    await primary.client.revokeDevice(secondary.devicePub);
    expect((await flagged).groupIds.map(toHex)).toEqual([toHex(theirs)]);

    // Calling it directly reports the same split.
    const { rekeyed, needsAdmin } = await primary.chat.rekeyAdministeredGroups();
    expect(rekeyed.map(toHex)).toContain(toHex(ours));
    expect(needsAdmin.map(toHex)).toEqual([toHex(theirs)]);
    expect(memberOf((await primary.chat.groupState(ours))!, decodeIdentity(primary.chat.identity))?.role).toBe(
      GroupRole.OWNER,
    );

    // After the rekey the revoked device is reading a key it no longer has.
    const notSeen = nothingWithin<ChatEvents, 'message'>(
      secondary.chat,
      'message',
      (e) => e.message.text === 'after the phone left',
      15000,
    );
    const atFriend = waitFor<ChatEvents, 'message'>(
      friend.chat,
      'message',
      (e) => e.message.text === 'after the phone left',
    );
    await primary.chat.sendGroupText(ours, 'after the phone left');
    await atFriend;
    expect(await notSeen).toBe(true);
  }, 600000);

  it('backfills a newly paired device with history it can verify', async () => {
    const primary = await account(66, nodes[0]!);
    const peer = await account(67, nodes[1]!);
    await introduce(primary, peer);

    // A conversation that happens BEFORE the second device exists. This is
    // the whole problem: the phone can decrypt everything from now on, and
    // nothing from before.
    const heard = waitFor<ChatEvents, 'message'>(primary.chat, 'message', (e) => e.message.text === 'from the peer');
    await peer.chat.sendText(primary.chat.identity, 'from the peer');
    await heard;
    await primary.chat.sendText(peer.chat.identity, 'and the reply');

    const secondary = await pairDevice(primary, nodes[1]!);
    const convId = primary.chat.conversationWith(peer.chat.identity);
    expect((await secondary.chat.history(convId)).messages).toHaveLength(0);

    // Backfill rides a direct channel, not the bus: history is megabytes and
    // the bus charges a proof of work per envelope. A loopback pair stands in
    // for the channel the stream layer will open.
    const [side, other] = loopbackPair();
    const server = primary.chat.serveBackfill(side.channel('control'));
    try {
      const res = await secondary.chat.backfillFrom(other.channel('control'), convId, { timeoutMs: 30000 });
      expect(res.added).toBe(2);
      // What the peer said came with the signed frame it arrived in, so the
      // phone checked it rather than trusting the desktop. What the desktop
      // itself sent has no such proof — it was never signed to us.
      expect(res.verified).toBe(1);
      expect(res.unverified).toBe(1);
      expect(res.rejected).toBe(0);
    } finally {
      server.close();
      side.close();
      other.close();
    }

    const onPhone = await secondary.chat.history(convId);
    expect(onPhone.messages.map((m) => m.text)).toEqual(['from the peer', 'and the reply']);
    // Catching up is not the same as being spoken to: none of it is unread.
    expect(await secondary.chat.unreadCount(convId)).toBe(0);
  }, 600000);

  it('carries a payment request and its receipt between nodes', async () => {
    const alice = await account(64, nodes[0]!);
    const bob = await account(65, nodes[1]!);
    await introduce(alice, bob);

    const asked = waitFor<ChatEvents, 'payment'>(bob.chat, 'payment', (p) => p.from === alice.chat.identity);
    await alice.chat.requestPayment(bob.chat.identity, 125_000_000n, { memo: 'for the tickets' });
    const request = await asked;
    expect(request.payment.amount).toBe(125_000_000n);
    expect(request.payment.memo).toBe('for the tickets');
    // The chain's native asset carries no token id.
    expect(request.payment.tokenId).toBe('');

    // navio-core's send returns an output hash rather than a txid, so that is
    // what the receipt carries and what Alice can actually look up.
    const outputHash = randomBytes(32);
    const receipted = waitFor<ChatEvents, 'payment'>(alice.chat, 'payment', (p) => p.from === bob.chat.identity);
    await bob.chat.notifyPaymentSent(alice.chat.identity, 125_000_000n, outputHash, { memo: 'sent' });
    const receipt = await receipted;
    expect(toHex(receipt.payment.reference)).toBe(toHex(outputHash));
    expect(receipt.payment.amount).toBe(125_000_000n);
    // Both sides of it land in the same conversation as the messages.
    expect(toHex(receipt.convId)).toBe(toHex(alice.chat.conversationWith(bob.chat.identity)));
  }, 300000);
});
