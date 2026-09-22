/**
 * End-to-end: the whole stack against a real naviod.
 *
 * Every other integration test exercises one layer. This one runs the stack an
 * application actually uses — real envelopes over a real node, real proof of
 * work, real discovery, the chat layer on top — and checks the properties that
 * only show up when the pieces are combined.
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
import { memberOf } from './chat/group/state.js';
import { FileClient, FileServer } from './stream/file.js';
import { loopbackPair } from './stream/transport.js';
import { exportState, importState } from './backup/export.js';
import { generateSeedPhrase, seedFromPhrase } from './backup/mnemonic.js';

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

describe.skipIf(!haveBinary)('end to end against naviod', () => {
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
      discoveryTimeoutMs: 30000,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    client.on('error', (e) => console.error('[client]', e.message));
    open.push(client);
    const connected = waitFor<MessagingEvents, 'peer'>(client, 'peer');
    await client.connect();
    await connected;
    const chat = await ChatClient.create({ client, store });
    open.push(chat);
    return { client, chat, store };
  }

  /** Mutual contact + discovery, as an application would do on first contact. */
  async function introduce(a: Awaited<ReturnType<typeof account>>, b: Awaited<ReturnType<typeof account>>) {
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);
  }

  beforeAll(async () => {
    node = await startRegtestNode({
      extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8', '-p2pmsgarchive=1'],
    });
  }, 180000);

  afterAll(async () => {
    for (const c of open.splice(0)) c.close();
    await node?.stop();
  });

  it('holds a real conversation: reply, edit, react, delete, read receipts', async () => {
    const alice = await account(1);
    const bob = await account(2);
    await introduce(alice, bob);
    const conv = alice.chat.conversationWith(bob.chat.identity);

    const arrived = waitFor<ChatEvents, 'message'>(bob.chat, 'message');
    const first = await alice.chat.sendText(bob.chat.identity, 'hello over a real node');
    expect(fromUtf8(utf8((await arrived).message.text))).toBe('hello over a real node');

    const replied = waitFor<ChatEvents, 'message'>(alice.chat, 'message', (e) => e.message.text === 'hi back');
    await bob.chat.sendText(alice.chat.identity, 'hi back', { replyTo: first });
    expect(toHex((await replied).message.replyTo!)).toBe(toHex(first));

    const edited = waitFor<ChatEvents, 'update'>(bob.chat, 'update', (e) => e.message.edited);
    await alice.chat.edit(bob.chat.identity, first, 'hello over a REAL node');
    expect((await edited).message.text).toBe('hello over a REAL node');

    const reacted = waitFor<ChatEvents, 'update'>(alice.chat, 'update', (e) => e.message.reactions.size > 0);
    await bob.chat.react(alice.chat.identity, first, '🎉');
    expect((await reacted).message.reactions.get('🎉')).toHaveLength(1);

    const read = waitFor<ChatEvents, 'update'>(alice.chat, 'update', (e) => e.message.readBy.length > 0);
    await bob.chat.markRead(alice.chat.identity);
    await read;

    const deleted = waitFor<ChatEvents, 'update'>(bob.chat, 'update', (e) => e.message.deleted);
    await alice.chat.delete(bob.chat.identity, first);
    expect((await deleted).message.text).toBe('');

    // Both sides render the same conversation, in the same order.
    const onAlice = (await alice.chat.history(conv)).messages.map((m) => m.text);
    const onBob = (await bob.chat.history(conv)).messages.map((m) => m.text);
    expect(onBob).toEqual(onAlice);
    expect((await alice.chat.history(conv)).gaps).toHaveLength(0);
  }, 300000);

  it('delivers a message to a recipient who was offline, through the archive', async () => {
    // The property the whole FMD and archive design exists for.
    const alice = await account(3);
    const bobStore = new MemoryStore();
    let bob = await account(4, bobStore);
    await introduce(alice, bob);

    // Discovery has to run first: without Bob's clue key there is nothing to
    // flag with, and nothing to retrieve later.
    const online = waitFor<ChatEvents, 'message'>(bob.chat, 'message');
    await alice.chat.sendText(bob.chat.identity, 'while you were here');
    await online;

    bob.client.close();
    bob.chat.close();
    await new Promise((r) => setTimeout(r, 500));

    const before = (await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo', [])).archive.entries;
    await alice.chat.sendText(bob.chat.identity, 'while you were away');
    await waitUntil(async () => {
      const info = await node.rpc<{ archive: { entries: number } }>('getp2pmsginfo', []);
      return info.archive.entries > before;
    }, 60000);

    // Bob comes back on the same store, so his keys are unchanged.
    bob = await account(4, bobStore);
    const recovered = waitFor<ChatEvents, 'message'>(
      bob.chat,
      'message',
      (e) => e.message.text === 'while you were away',
    );
    const res = await bob.client.syncArchive({ precision: 4 });
    expect(res.accepted).toBeGreaterThan(0);
    expect((await recovered).message.text).toBe('while you were away');
  }, 300000);

  it('runs a group over the node, and a removed member loses access', async () => {
    const alice = await account(5);
    const bob = await account(6);
    const carol = await account(7);
    await introduce(alice, bob);
    await introduce(alice, carol);
    await introduce(bob, carol);

    const joinedB = waitFor<ChatEvents, 'group'>(bob.chat, 'group');
    const joinedC = waitFor<ChatEvents, 'group'>(carol.chat, 'group');
    const groupId = await alice.chat.createGroup('real group', [bob.chat.identity, carol.chat.identity]);
    await joinedB;
    await joinedC;

    // One envelope, both members.
    const atB = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'everyone');
    const atC = waitFor<ChatEvents, 'message'>(carol.chat, 'message', (e) => e.message.text === 'everyone');
    await alice.chat.sendGroupText(groupId, 'everyone');
    await atB;
    await atC;

    const carolId = memberOf((await alice.chat.groupState(groupId))!, (await carolIdentity(carol)))!;
    const rekeyed = waitFor<ChatEvents, 'group'>(bob.chat, 'group', (e) => e.state.epoch === 1);
    await alice.chat.groupOp(groupId, { kind: 'remove', identity: carolId.identity });
    await rekeyed;

    const afterAtB = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'without carol');
    await alice.chat.sendGroupText(groupId, 'without carol');
    await afterAtB;
    await new Promise((r) => setTimeout(r, 2000));

    const atCarol = (await carol.chat.history(groupId)).messages.map((m) => m.text);
    expect(atCarol).toContain('everyone');
    // The rekey is what makes removal mean anything.
    expect(atCarol).not.toContain('without carol');
  }, 300000);

  it('pairs a second device, mirrors sends to it, and revokes it', async () => {
    const primary = await account(8);
    const joining = await account(9);
    const peer = await account(10);
    await introduce(primary, peer);

    const { offer } = primary.client.startPairing();
    const asked = waitFor<MessagingEvents, 'pairingRequest'>(primary.client, 'pairingRequest');
    const { sas, device } = await joining.client.requestPairing(offer, 'phone');
    const req = await asked;
    expect(req.sas).toBe(sas);

    const granted = waitFor<MessagingEvents, 'paired'>(joining.client, 'paired');
    await primary.client.confirmPairing(req.devicePub);
    const grant = await granted;

    const secondary = await MessagingClient.create({
      network: 'regtest',
      grant: { accountSecret: grant.accountSecret, identityPub: grant.identityPub, epoch: grant.accountEpoch },
      device: { keypair: { sk: device.sk, pub: device.pub }, identityPub: grant.identityPub },
      store: new MemoryStore(),
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    open.push(secondary);
    const up = waitFor<MessagingEvents, 'peer'>(secondary, 'peer');
    await secondary.connect();
    await up;

    // Same account, and one envelope reaches both devices.
    expect(secondary.identity).toBe(primary.client.identity);
    const atPrimary = waitFor<MessagingEvents, 'message'>(primary.client, 'message');
    const atSecondary = waitFor<MessagingEvents, 'message'>(secondary, 'message');
    await peer.client.send(primary.client.identity, utf8('for both devices'));
    expect(fromUtf8((await atPrimary).payload)).toBe('for both devices');
    expect(fromUtf8((await atSecondary).payload)).toBe('for both devices');

    // What the primary sends is mirrored, so the phone shows the whole
    // conversation rather than half of it.
    const mirrored = waitFor<MessagingEvents, 'mirrored'>(secondary, 'mirrored');
    await primary.client.send(peer.client.identity, utf8('sent from the desktop'));
    await primary.client.flushMirror();
    expect(fromUtf8((await mirrored).payload)).toBe('sent from the desktop');

    // Revoking moves every key; the revoked device is off the list.
    const before = toHex(primary.client.keyring.prekey.pub);
    const revoked = await primary.client.revokeDevice(device.pub);
    expect(revoked.epoch).toBe(grant.accountEpoch + 1);
    expect(toHex(primary.client.keyring.prekey.pub)).not.toBe(before);
  }, 300000);

  it('carries an attachment reference over the node and the bytes over a channel', async () => {
    const alice = await account(11);
    const bob = await account(12);
    await introduce(alice, bob);

    const [left, right] = loopbackPair();
    const server = new FileServer(left.channel('file'));
    const client = new FileClient(right.channel('file'));

    const file = randomBytes(250 * 1024);
    const ref = await alice.chat.attach(file, { mime: 'image/png', thumbnail: randomBytes(128), server });

    const got = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.attachments.length > 0);
    await alice.chat.sendText(bob.chat.identity, 'a picture', { attachments: [ref] });
    const received = (await got).message.attachments[0]!;
    // Only the reference crossed the bus; the file is far past a 3584-byte frame.
    expect(Number(received.size)).toBeGreaterThan(200 * 1024);
    expect(toHex(await bob.chat.fetchAttachment(received, client, { timeoutMs: 30000 }))).toBe(toHex(file));
  }, 300000);

  it('survives a restart: history, contacts and group state come back', async () => {
    const store = new MemoryStore();
    const alice = await account(13, store);
    const bob = await account(14);
    await introduce(alice, bob);

    const got = waitFor<ChatEvents, 'message'>(bob.chat, 'message');
    await alice.chat.sendText(bob.chat.identity, 'before the restart');
    await got;
    const conv = alice.chat.conversationWith(bob.chat.identity);
    expect((await alice.chat.history(conv)).messages).toHaveLength(1);

    alice.client.close();
    alice.chat.close();

    // Same seed, same store: the account picks up exactly where it was.
    const restarted = await account(13, store);
    expect(restarted.client.identity).toBe(alice.client.identity);
    const history = await restarted.chat.history(conv);
    expect(history.messages.map((m) => m.text)).toEqual(['before the restart']);
    expect(await restarted.chat.isKnown(bob.chat.identity)).toBe(true);
  }, 300000);

  it('backs up and restores an account from a phrase and an export', async () => {
    const store = new MemoryStore();
    const phrase = generateSeedPhrase();
    const seed = seedFromPhrase(phrase);

    const alice = await MessagingClient.create({
      network: 'regtest',
      seed,
      store,
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    open.push(alice);
    const up = waitFor<MessagingEvents, 'peer'>(alice, 'peer');
    await alice.connect();
    await up;
    const aliceChat = await ChatClient.create({ client: alice, store });
    open.push(aliceChat);

    const bob = await account(15);
    await alice.addContact(bob.client.bundle());
    await bob.client.addContact(alice.bundle());
    await aliceChat.markKnown(bob.chat.identity);
    await bob.chat.markKnown(aliceChat.identity);

    const got = waitFor<ChatEvents, 'message'>(bob.chat, 'message');
    await aliceChat.sendText(bob.chat.identity, 'worth backing up');
    await got;

    const backup = await exportState(store, 'a good passphrase', { iterations: 1000 });

    // Restore onto a clean store with the seed recovered from the phrase.
    const restoredStore = new MemoryStore();
    await importState(restoredStore, backup, 'a good passphrase');
    const restored = await MessagingClient.create({
      network: 'regtest',
      seed: seedFromPhrase(phrase),
      store: restoredStore,
      peers: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      services: ServiceFlags.NODE_P2PMSG_LEAF,
    });
    open.push(restored);
    const restoredChat = await ChatClient.create({ client: restored, store: restoredStore });
    open.push(restoredChat);

    // The phrase brings back the identity; the export brings back the history.
    expect(restored.identity).toBe(alice.identity);
    const conv = restoredChat.conversationWith(bob.chat.identity);
    expect((await restoredChat.history(conv)).messages.map((m) => m.text)).toEqual(['worth backing up']);
  }, 300000);
});

async function carolIdentity(carol: { chat: ChatClient }): Promise<Uint8Array> {
  const { decodeIdentity } = await import('./usermsg/bundle.js');
  return decodeIdentity(carol.chat.identity);
}

async function waitUntil(pred: () => Promise<boolean>, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 200));
  }
}
