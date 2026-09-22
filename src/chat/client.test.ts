import { afterEach, describe, expect, it } from 'vitest';
import { MessagingClient } from '../usermsg/client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { Emitter } from '../net/emitter.js';
import { toHex } from '../common/bytes.js';
import { ChatClient, type ChatEvents } from './client.js';
import { decodeInvite } from './group/invite.js';

type NetEvents = {
  message: { peerId: string; stem: boolean; payload: Uint8Array };
  peer: { id: string; address: string };
  peerclose: { id: string; address: string };
  error: Error;
};

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

class FakeNetwork extends Emitter<NetEvents> {
  up = false;
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
    return this.hub.relay(this, envelope, opts.stem);
  }
  medianClockOffset(): number {
    return 0;
  }
  get connectedCount(): number {
    return this.up ? 1 : 0;
  }
}

const open: Array<{ close(): void }> = [];
afterEach(() => {
  for (const c of open.splice(0)) c.close();
});

async function mk(hub: Hub, seedByte: number) {
  const store = new MemoryStore();
  const client = await MessagingClient.create({
    network: 'regtest',
    seed: new Uint8Array(32).fill(seedByte),
    store,
    pool: new FakeNetwork(hub) as never,
    powBits: 4,
    powWorkers: 0,
    ackDelayMs: 50,
    retryTickMs: 200,
    discoveryTimeoutMs: 5000,
  });
  open.push(client);
  await client.connect();
  const chat = await ChatClient.create({ client, store });
  open.push(chat);
  return { client, chat };
}

function waitFor<K extends keyof ChatEvents>(
  c: ChatClient,
  ev: K,
  pred: (v: ChatEvents[K]) => boolean = () => true,
  ms = 15000,
): Promise<ChatEvents[K]> {
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

describe('ChatClient', () => {
  it('holds a stranger in the request queue instead of the inbox', async () => {
    // PoW alone is a weak gate: cheap for a spammer with hardware, expensive
    // for a phone. First contact is a request, not a message.
    const hub = new Hub();
    const a = await mk(hub, 60);
    const b = await mk(hub, 61);
    await a.client.addContact(b.client.bundle());

    const req = waitFor(b.chat, 'request');
    await a.chat.sendContactRequest(b.chat.identity, 'hi, it is alex');
    const got = await req;
    expect(got.identity).toBe(a.chat.identity);
    expect(got.intro).toBe('hi, it is alex');
    expect((await b.chat.requests()).map((r) => r.identity)).toEqual([a.chat.identity]);
    // Nothing landed in the conversation.
    expect((await b.chat.history(b.chat.conversationWith(a.chat.identity))).messages).toHaveLength(0);
  }, 30000);

  it('delivers messages once the request is accepted', async () => {
    const hub = new Hub();
    const a = await mk(hub, 62);
    const b = await mk(hub, 63);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);

    const got = waitFor(b.chat, 'message');
    await a.chat.sendText(b.chat.identity, 'hello there');
    const ev = await got;
    expect(ev.message.text).toBe('hello there');
    expect(ev.message.sender && toHex(ev.message.sender)).toBeDefined();

    // Both sides derive the same conversation id with nothing negotiated.
    expect(toHex(ev.convId)).toBe(toHex(a.chat.conversationWith(b.chat.identity)));
    expect(await b.chat.unreadCount(ev.convId)).toBe(1);
  }, 30000);

  it('orders a two-way exchange identically on both sides', async () => {
    const hub = new Hub();
    const a = await mk(hub, 64);
    const b = await mk(hub, 65);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);

    const first = waitFor(b.chat, 'message');
    await a.chat.sendText(b.chat.identity, 'one');
    await first;
    const second = waitFor(a.chat, 'message');
    await b.chat.sendText(a.chat.identity, 'two');
    await second;
    const third = waitFor(b.chat, 'message', (e) => e.message.text === 'three');
    await a.chat.sendText(b.chat.identity, 'three');
    await third;

    const conv = a.chat.conversationWith(b.chat.identity);
    const onA = (await a.chat.history(conv)).messages.map((m) => m.text);
    const onB = (await b.chat.history(conv)).messages.map((m) => m.text);
    expect(onA).toEqual(['one', 'two', 'three']);
    // Same order on both devices: a conversation that renders differently for
    // each participant is a bug users notice immediately.
    expect(onB).toEqual(onA);
  }, 30000);

  it('applies a reply, an edit, a delete and a reaction end to end', async () => {
    const hub = new Hub();
    const a = await mk(hub, 66);
    const b = await mk(hub, 67);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);
    const conv = a.chat.conversationWith(b.chat.identity);

    const arrived = waitFor(b.chat, 'message');
    const originalId = await a.chat.sendText(b.chat.identity, 'orignal');
    await arrived;

    const replied = waitFor(b.chat, 'message', (e) => e.message.text === 'a reply');
    await b.chat.sendText(a.chat.identity, 'a reply', { replyTo: originalId });
    const reply = await replied;
    expect(reply.message.replyTo && toHex(reply.message.replyTo)).toBe(toHex(originalId));

    const edited = waitFor(b.chat, 'update', (e) => e.message.edited);
    await a.chat.edit(b.chat.identity, originalId, 'original');
    const afterEdit = await edited;
    expect(afterEdit.message.text).toBe('original');

    const reacted = waitFor(a.chat, 'update', (e) => e.message.reactions.size > 0);
    await b.chat.react(a.chat.identity, originalId, '👍');
    const afterReact = await reacted;
    expect(afterReact.message.reactions.get('👍')).toHaveLength(1);

    const deleted = waitFor(b.chat, 'update', (e) => e.message.deleted);
    await a.chat.delete(b.chat.identity, originalId);
    const afterDelete = await deleted;
    expect(afterDelete.message.text).toBe('');

    const onA = (await a.chat.history(conv)).messages;
    expect(onA.find((m) => toHex(m.id) === toHex(originalId))?.deleted).toBe(true);
  }, 40000);

  it('drops messages from a blocked identity without telling them', async () => {
    const hub = new Hub();
    const a = await mk(hub, 68);
    const b = await mk(hub, 69);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);

    await b.chat.block(a.chat.identity);
    expect(await b.chat.isBlocked(a.chat.identity)).toBe(true);
    await a.chat.sendText(b.chat.identity, 'let me in');
    await new Promise((r) => setTimeout(r, 500));
    const conv = b.chat.conversationWith(a.chat.identity);
    expect((await b.chat.history(conv)).messages).toHaveLength(0);
    // The sender sees nothing different: blocking is never published.
    expect((await a.chat.history(conv)).messages).toHaveLength(1);
  }, 30000);

  it('clears unread on markRead', async () => {
    const hub = new Hub();
    const a = await mk(hub, 70);
    const b = await mk(hub, 71);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);

    const got = waitFor(b.chat, 'message');
    await a.chat.sendText(b.chat.identity, 'unread me');
    const ev = await got;
    expect(await b.chat.unreadCount(ev.convId)).toBe(1);
    await b.chat.markRead(a.chat.identity);
    expect(await b.chat.unreadCount(ev.convId)).toBe(0);
  }, 30000);

  it('accepting a request lets the next message through', async () => {
    const hub = new Hub();
    const a = await mk(hub, 72);
    const b = await mk(hub, 73);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);

    const req = waitFor(b.chat, 'request');
    await a.chat.sendContactRequest(b.chat.identity, 'hello');
    await req;
    await b.chat.acceptRequest(a.chat.identity);
    expect(await b.chat.requests()).toHaveLength(0);
    expect(await b.chat.isKnown(a.chat.identity)).toBe(true);

    const msg = waitFor(b.chat, 'message');
    await a.chat.sendText(b.chat.identity, 'now it lands');
    expect((await msg).message.text).toBe('now it lands');
  }, 30000);
});

describe('ChatClient receipts, profiles and search', () => {
  async function pair(seedA: number, seedB: number) {
    const hub = new Hub();
    const a = await mk(hub, seedA);
    const b = await mk(hub, seedB);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.markKnown(a.chat.identity);
    return { a, b };
  }

  it('surfaces read receipts as readBy on the sender side', async () => {
    const { a, b } = await pair(80, 81);
    const conv = a.chat.conversationWith(b.chat.identity);

    const delivered = waitFor(b.chat, 'message');
    await a.chat.sendText(b.chat.identity, 'did you see this');
    await delivered;

    // Before the receipt, the sender knows nothing about whether it was read.
    expect((await a.chat.history(conv)).messages[0]!.readBy).toEqual([]);

    const seen = waitFor(a.chat, 'update', (e) => e.message.readBy.length > 0);
    await b.chat.markRead(a.chat.identity);
    const ev = await seen;
    expect(ev.message.readBy).toHaveLength(1);
  }, 30000);

  it('exchanges profiles and emits them', async () => {
    const { a, b } = await pair(82, 83);
    const got = waitFor(b.chat, 'profile');
    await a.chat.setProfile({ displayName: 'alex', statusText: 'building' }, [b.chat.identity]);
    const ev = await got;
    expect(ev.identity).toBe(a.chat.identity);
    expect(ev.profile.displayName).toBe('alex');
    expect((await b.chat.profileOf(a.chat.identity))?.displayName).toBe('alex');
    expect((await a.chat.profile())?.displayName).toBe('alex');
  }, 30000);

  it('shares our profile automatically when accepting a request', async () => {
    // A new contact otherwise sees only a navid1… string.
    const hub = new Hub();
    const a = await mk(hub, 84);
    const b = await mk(hub, 85);
    await a.client.addContact(b.client.bundle());
    await b.client.addContact(a.client.bundle());
    await a.chat.markKnown(b.chat.identity);
    await b.chat.setProfile({ displayName: 'bea', statusText: '' });

    const req = waitFor(b.chat, 'request');
    await a.chat.sendContactRequest(b.chat.identity, 'hi');
    await req;
    const profile = waitFor(a.chat, 'profile');
    await b.chat.acceptRequest(a.chat.identity);
    expect((await profile).profile.displayName).toBe('bea');
  }, 30000);

  it('searches stored messages and skips deleted ones', async () => {
    const { a, b } = await pair(86, 87);
    const first = waitFor(b.chat, 'message');
    await a.chat.sendText(b.chat.identity, 'the pineapple is in the fridge');
    await first;
    const second = waitFor(b.chat, 'message', (e) => e.message.text.includes('banana'));
    await a.chat.sendText(b.chat.identity, 'the banana is not');
    await second;

    expect((await b.chat.search('pineapple')).map((m) => m.text)).toEqual(['the pineapple is in the fridge']);
    expect(await b.chat.search('the')).toHaveLength(2);
    expect(await b.chat.search('pineap')).toHaveLength(1); // prefix

    const gone = waitFor(b.chat, 'update', (e) => e.message.deleted);
    const ids = (await b.chat.history(a.chat.conversationWith(b.chat.identity))).messages;
    const target = ids.find((m) => m.text.includes('pineapple'))!;
    await a.chat.delete(b.chat.identity, target.id);
    await gone;
    expect(await b.chat.search('pineapple')).toHaveLength(0);
  }, 40000);
});

describe('ChatClient groups', () => {
  async function trio() {
    const hub = new Hub();
    const a = await mk(hub, 90);
    const b = await mk(hub, 91);
    const c = await mk(hub, 92);
    for (const [x, y] of [
      [a, b],
      [a, c],
      [b, c],
    ] as const) {
      await x.client.addContact(y.client.bundle());
      await y.client.addContact(x.client.bundle());
      await x.chat.markKnown(y.chat.identity);
      await y.chat.markKnown(x.chat.identity);
    }
    return { a, b, c };
  }

  it('creates a group, distributes keys, and delivers one envelope to everyone', async () => {
    const { a, b, c } = await trio();
    const bJoined = waitFor(b.chat, 'group');
    const cJoined = waitFor(c.chat, 'group');
    const groupId = await a.chat.createGroup('the group', [b.chat.identity, c.chat.identity]);
    await bJoined;
    await cJoined;

    expect((await b.chat.groupState(groupId))?.name).toBe('the group');
    expect((await c.chat.groupState(groupId))?.members).toHaveLength(3);

    const atB = waitFor(b.chat, 'message', (e) => toHex(e.convId) === toHex(groupId));
    const atC = waitFor(c.chat, 'message', (e) => toHex(e.convId) === toHex(groupId));
    await a.chat.sendGroupText(groupId, 'hello everyone');
    expect((await atB).message.text).toBe('hello everyone');
    expect((await atC).message.text).toBe('hello everyone');
  }, 60000);

  it('renders the same group history on every member', async () => {
    const { a, b, c } = await trio();
    const joined = [waitFor(b.chat, 'group'), waitFor(c.chat, 'group')];
    const groupId = await a.chat.createGroup('order test', [b.chat.identity, c.chat.identity]);
    await Promise.all(joined);

    const first = waitFor(c.chat, 'message', (e) => e.message.text === 'from a');
    await a.chat.sendGroupText(groupId, 'from a');
    await first;
    const second = waitFor(a.chat, 'message', (e) => e.message.text === 'from b');
    await b.chat.sendGroupText(groupId, 'from b');
    await second;

    const onA = (await a.chat.history(groupId)).messages.map((m) => m.text);
    const onB = (await b.chat.history(groupId)).messages.map((m) => m.text);
    expect(onA).toEqual(['from a', 'from b']);
    expect(onB).toEqual(onA);
  }, 60000);

  it('rekeys on removal so the removed member cannot read the next message', async () => {
    // Without the rekey, removal would mean nothing: the departing member
    // keeps the epoch secret and keeps reading.
    const { a, b, c } = await trio();
    const joined = [waitFor(b.chat, 'group'), waitFor(c.chat, 'group')];
    const groupId = await a.chat.createGroup('rekey test', [b.chat.identity, c.chat.identity]);
    await Promise.all(joined);

    const before = waitFor(c.chat, 'message', (e) => e.message.text === 'still here');
    await a.chat.sendGroupText(groupId, 'still here');
    await before;

    const rekeyed = waitFor(b.chat, 'group', (e) => e.state.epoch === 1);
    await a.chat.groupOp(groupId, { kind: 'remove', identity: (await c.chat.groupState(groupId))!.members[2]!.identity });
    await rekeyed;
    expect((await a.chat.groupState(groupId))!.epoch).toBe(1);
    expect((await a.chat.groupState(groupId))!.members).toHaveLength(2);

    const afterAtB = waitFor(b.chat, 'message', (e) => e.message.text === 'after removal');
    await a.chat.sendGroupText(groupId, 'after removal');
    await afterAtB;
    await new Promise((r) => setTimeout(r, 500));

    // C holds only the old epoch secret.
    const atC = (await c.chat.history(groupId)).messages.map((m) => m.text);
    expect(atC).toContain('still here');
    expect(atC).not.toContain('after removal');
  }, 60000);

  it('refuses a membership change from a non-admin', async () => {
    const { a, b, c } = await trio();
    const joined = [waitFor(b.chat, 'group'), waitFor(c.chat, 'group')];
    const groupId = await a.chat.createGroup('authority', [b.chat.identity, c.chat.identity]);
    await Promise.all(joined);
    const state = (await b.chat.groupState(groupId))!;
    await expect(b.chat.groupOp(groupId, { kind: 'remove', identity: state.members[2]!.identity })).rejects.toThrow(
      /admin/,
    );
  }, 60000);

  it('renames without rotating keys', async () => {
    const { a, b, c } = await trio();
    const joined = [waitFor(b.chat, 'group'), waitFor(c.chat, 'group')];
    const groupId = await a.chat.createGroup('old name', [b.chat.identity, c.chat.identity]);
    await Promise.all(joined);

    const renamed = waitFor(b.chat, 'group', (e) => e.state.name === 'new name');
    await a.chat.groupOp(groupId, { kind: 'rename', name: 'new name' });
    const ev = await renamed;
    // A rename costs nobody a key distribution.
    expect(ev.state.epoch).toBe(0);

    const got = waitFor(c.chat, 'message', (e) => e.message.text === 'still works');
    await a.chat.sendGroupText(groupId, 'still works');
    await got;
  }, 60000);

  it('issues an invite that carries the epoch key', async () => {
    const { a, b, c } = await trio();
    const joined = [waitFor(b.chat, 'group'), waitFor(c.chat, 'group')];
    const groupId = await a.chat.createGroup('invites', [b.chat.identity, c.chat.identity]);
    await Promise.all(joined);

    const text = await a.chat.createInvite(groupId, 3600);
    expect(text.startsWith('navinv1')).toBe(true);
    const invite = decodeInvite(text);
    expect(toHex(invite.groupId)).toBe(toHex(groupId));
    expect(invite.epochSecret).toHaveLength(32);
  }, 60000);
});
