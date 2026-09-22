/**
 * End-to-end: the social surface, against a real naviod.
 *
 * `e2e.int.test.ts` covers messaging between two people who already know each
 * other. This suite covers how that relationship starts and how it is
 * administered: meeting a stranger, publishing a profile, joining a group by
 * link, handing a group over, and catching up on a group that rekeyed while a
 * member was away. All of it over real envelopes and real proof of work.
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
import { toHex } from './common/bytes.js';
import { ServiceFlags } from './net/messages.js';
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

/** Resolves when `pred` holds, or throws. For state with no event to await. */
async function waitUntil(pred: () => Promise<boolean>, ms = 30000): Promise<void> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** Nothing arrives within `ms`. Used to assert an absence, which needs time. */
function nothingWithin<T extends ChatEvents, K extends keyof T>(
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

describe.skipIf(!haveBinary)('end to end: meeting people and running groups', () => {
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
    chat.on('error', (e) => console.error('[chat]', e.message));
    open.push(chat);
    return { client, chat, store };
  }

  type Account = Awaited<ReturnType<typeof account>>;

  /** Exchange keys only. Neither side has accepted the other as a contact. */
  async function exchangeKeys(a: Account, b: Account) {
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
  }

  /** Keys plus mutual acceptance, as an application does on first contact. */
  async function introduce(a: Account, b: Account) {
    await exchangeKeys(a, b);
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

  it('meets a stranger: request, accept, profile, then block', async () => {
    const alice = await account(40);
    const bob = await account(41);
    // Keys only: Bob can decrypt what Alice sends, but has never agreed to
    // hear from her. That is the situation a scanned address puts you in.
    await exchangeKeys(alice, bob);

    const queued = waitFor<ChatEvents, 'request'>(bob.chat, 'request', (r) => r.identity === alice.chat.identity);
    await alice.chat.sendContactRequest(bob.chat.identity, 'met at the conference');
    const req = await queued;
    expect(req.intro).toBe('met at the conference');
    expect(await bob.chat.requests()).toHaveLength(1);
    expect(await bob.chat.isKnown(alice.chat.identity)).toBe(false);

    // Accepting sends back an ACCEPT and our profile, so a new contact sees a
    // name rather than a navid1… string.
    await bob.chat.setProfile({ displayName: 'Bob', statusText: 'around' });
    const gotProfile = waitFor<ChatEvents, 'profile'>(alice.chat, 'profile', (p) => p.identity === bob.chat.identity);
    await bob.chat.acceptRequest(alice.chat.identity);
    expect((await gotProfile).profile.displayName).toBe('Bob');
    expect(await alice.chat.profileOf(bob.chat.identity)).toMatchObject({ displayName: 'Bob' });
    expect(await bob.chat.requests()).toHaveLength(0);
    expect(await bob.chat.isKnown(alice.chat.identity)).toBe(true);

    const hello = waitFor<ChatEvents, 'message'>(bob.chat, 'message', (e) => e.message.text === 'glad you said yes');
    await alice.chat.sendText(bob.chat.identity, 'glad you said yes');
    await hello;

    // Blocking is local and silent: Alice's send still succeeds, and Bob
    // simply never surfaces it.
    await bob.chat.block(alice.chat.identity);
    const silent = nothingWithin<ChatEvents, 'message'>(
      bob.chat,
      'message',
      (e) => e.message.text === 'still there?',
      8000,
    );
    await alice.chat.sendText(bob.chat.identity, 'still there?');
    expect(await silent).toBe(true);
  }, 300000);

  it('admits someone who arrived with a request-to-join link', async () => {
    const owner = await account(42);
    const member = await account(43);
    const stranger = await account(44);
    await introduce(owner, member);
    await introduce(owner, stranger);

    const joined = waitFor<ChatEvents, 'group'>(member.chat, 'group');
    const groupId = await owner.chat.createGroup('reading club', [member.chat.identity]);
    await joined;

    // A request-to-join link carries no key: holding it proves nothing and
    // reads nothing. It is safe to post where it may be forwarded.
    const link = await owner.chat.createJoinRequestInvite(groupId);
    await expect(stranger.chat.joinWithInvite(link)).rejects.toThrow(/no key/);

    // Said out loud: before admission the stranger cannot read group traffic.
    const beforeAdmission = nothingWithin<ChatEvents, 'message'>(
      stranger.chat,
      'message',
      (e) => e.message.text === 'members only',
      8000,
    );
    await owner.chat.sendGroupText(groupId, 'members only');
    expect(await beforeAdmission).toBe(true);

    // An admin turning the link into membership is the whole point.
    const admitted = waitFor<ChatEvents, 'group'>(stranger.chat, 'group', (g) => toHex(g.groupId) === toHex(groupId));
    await owner.chat.admitToGroup(groupId, stranger.chat.identity);
    const state = (await admitted).state;
    expect(memberOf(state, decodeIdentity(stranger.chat.identity))).toBeDefined();

    const welcome = waitFor<ChatEvents, 'message'>(stranger.chat, 'message', (e) => e.message.text === 'welcome in');
    await owner.chat.sendGroupText(groupId, 'welcome in');
    await welcome;

    // Admission does not hand over the past: the group rekeys on join, so the
    // message sent before it stays unreadable.
    const history = await stranger.chat.history(groupId);
    expect(history.messages.some((m) => m.text === 'members only')).toBe(false);
  }, 300000);

  it('hands a group over, and the old owner can no longer administer it', async () => {
    const owner = await account(45);
    const heir = await account(46);
    const newcomer = await account(47);
    await introduce(owner, heir);
    await introduce(owner, newcomer);
    await introduce(heir, newcomer);

    const joined = waitFor<ChatEvents, 'group'>(heir.chat, 'group');
    const groupId = await owner.chat.createGroup('handover', [heir.chat.identity]);
    await joined;

    // Ownership only transfers to an admin, so promote first.
    await owner.chat.groupOp(groupId, { kind: 'promote', identity: decodeIdentity(heir.chat.identity), role: GroupRole.ADMIN });
    await waitUntil(async () => {
      const s = await heir.chat.groupState(groupId);
      return memberOf(s!, decodeIdentity(heir.chat.identity))?.role === GroupRole.ADMIN;
    });

    const handed = waitFor<ChatEvents, 'group'>(
      heir.chat,
      'group',
      (g) => memberOf(g.state, decodeIdentity(heir.chat.identity))?.role === GroupRole.OWNER,
    );
    await owner.chat.transferOwnership(groupId, heir.chat.identity);
    await handed;

    // The heir administers it now.
    const admitted = waitFor<ChatEvents, 'group'>(newcomer.chat, 'group', (g) => toHex(g.groupId) === toHex(groupId));
    await heir.chat.admitToGroup(groupId, newcomer.chat.identity);
    await admitted;

    // And the former owner cannot hand it back to themselves.
    await expect(owner.chat.transferOwnership(groupId, owner.chat.identity)).rejects.toThrow();
  }, 300000);

  it('catches a group up across a rekey that happened while a member was away', async () => {
    const owner = await account(48);
    const leaver = await account(49);
    const store = new MemoryStore();
    let away = await account(50, store);
    await introduce(owner, away);
    await introduce(owner, leaver);
    await introduce(away, leaver);

    const inA = waitFor<ChatEvents, 'group'>(away.chat, 'group');
    const inL = waitFor<ChatEvents, 'group'>(leaver.chat, 'group');
    const groupId = await owner.chat.createGroup('epochs', [away.chat.identity, leaver.chat.identity]);
    await inA;
    await inL;

    const first = waitFor<ChatEvents, 'message'>(away.chat, 'message', (e) => e.message.text === 'before you left');
    await owner.chat.sendGroupText(groupId, 'before you left');
    await first;

    // Away goes offline. While it is gone the group rekeys (a removal rotates
    // the epoch) and traffic continues under the new keys.
    const awayIdentity = away.chat.identity;
    away.chat.close();
    away.client.close();

    await owner.chat.groupOp(groupId, { kind: 'remove', identity: decodeIdentity(leaver.chat.identity) });
    await owner.chat.sendGroupText(groupId, 'after the rekey');

    // It comes back on the same store, so it still holds the old epoch secret
    // and the group membership, but it missed both the new epoch secret and
    // the message sent under it.
    const epochBefore = (await owner.chat.groupState(groupId))!.epoch;
    away = await account(50, store);
    expect((await away.chat.groupState(groupId))!.epoch).toBeLessThan(epochBefore);

    // The new epoch secret comes back on its own: the owner's outbox keeps
    // retransmitting an unacked message, so reconnecting is enough. Until it
    // lands there is nothing to retrieve WITH — the group's clue key moved
    // with the epoch, so the message is not even detectable.
    await waitUntil(async () => (await away.chat.groupState(groupId))!.epoch === epochBefore, 60000);

    const caught = waitFor<ChatEvents, 'message'>(away.chat, 'message', (e) => e.message.text === 'after the rekey');
    // One query per epoch we hold: a single detection key would silently miss
    // everything sent under the others.
    // Two epochs, two detection keys, and the epoch-0 query must not move the
    // epoch-1 query past the message it is looking for.
    expect(await away.chat.groupDetectionKeys(4)).toHaveLength(2);
    await away.chat.syncGroupArchives(4);
    await caught;

    const history = await away.chat.history(groupId);
    expect(history.messages.map((m) => m.text)).toEqual(
      expect.arrayContaining(['before you left', 'after the rekey']),
    );
    expect(awayIdentity).toBe(away.chat.identity);
  }, 300000);

  it('finds an old message by text after the application restarts', async () => {
    const store = new MemoryStore();
    let alice = await account(51, store);
    const bob = await account(52);
    await introduce(alice, bob);

    const arrived = waitFor<ChatEvents, 'message'>(alice.chat, 'message', (e) => e.message.text?.includes('pangolin'));
    await bob.chat.sendText(alice.chat.identity, 'the pangolin has landed');
    await arrived;
    await alice.chat.sendText(bob.chat.identity, 'noted, filing under mammals');

    alice.chat.close();
    alice.client.close();
    alice = await account(51, store);

    const hits = await alice.chat.search('pangolin');
    expect(hits.map((m) => m.text)).toEqual(['the pangolin has landed']);
    // Search spans the whole store, not one side of it.
    expect((await alice.chat.search('mammals')).map((m) => m.text)).toEqual(['noted, filing under mammals']);
  }, 300000);
});
