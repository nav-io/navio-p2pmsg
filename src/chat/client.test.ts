import { afterEach, describe, expect, it } from 'vitest';
import { MessagingClient } from '../usermsg/client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { Emitter } from '../net/emitter.js';
import { toHex } from '../common/bytes.js';
import { ChatClient, type ChatEvents } from './client.js';

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
