/**
 * Integration: two MessagingClients through one real regtest naviod, plus
 * interop with the node's own usermsg RPCs (sendp2pmsg / listp2pmsgs).
 * Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, getFreePort, startRegtestNode, supportedFlags } from '../../test/regtest-node.js';
import { MessagingClient, type MessagingEvents } from './client.js';
import { MemoryStore } from '../stores/memory-store.js';
import { fromHex, fromUtf8, toHex, utf8 } from '../common/bytes.js';
import { ServiceFlags } from '../net/messages.js';
import { verifyBundle } from './keyring.js';
import { USER_DATA_KIND, serializeUserMsgFrame } from './frame.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

function waitFor<K extends keyof MessagingEvents>(c: MessagingClient, ev: K, pred: (v: MessagingEvents[K]) => boolean = () => true, ms = 30000): Promise<MessagingEvents[K]> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => { off(); reject(new Error(`timeout waiting for ${String(ev)}`)); }, ms);
    const off = c.on(ev, (v) => { if (pred(v)) { clearTimeout(t); off(); resolve(v); } });
  });
}

describe.skipIf(!haveBinary)('MessagingClient <-> naviod regtest', () => {
  let node: RegtestNode;
  let leafSupported = false;
  let wsPort = 0;
  const clients: MessagingClient[] = [];

  async function mk(seedByte: number, transport: 'tcp' | 'ws' = 'tcp') {
    const c = await MessagingClient.create({
      network: 'regtest',
      seed: new Uint8Array(32).fill(seedByte),
      store: new MemoryStore(),
      peers: [transport === 'ws' ? `ws://127.0.0.1:${wsPort}` : `127.0.0.1:${node.port}`],
      targetPeers: 1,
      dnsSeeds: [],
      powBits: 8,
      powWorkers: 0,
      ackDelayMs: 100,
      retryTickMs: 1000,
      // Until the node knows NODE_P2PMSG_LEAF it only fluffs to NODE_P2PMSG peers.
      services: leafSupported ? ServiceFlags.NODE_P2PMSG_LEAF : ServiceFlags.NODE_P2PMSG,
    });
    c.on('error', (e) => console.error('[client]', e.message));
    clients.push(c);
    const connected = waitFor(c, 'peer');
    await c.connect();
    await connected;
    return c;
  }

  beforeAll(async () => {
    const wsSupported = supportedFlags(DEFAULT_NAVIOD).has('-p2pwsbind');
    if (wsSupported) wsPort = await getFreePort();
    node = await startRegtestNode({
      extraArgs: ['-p2pmsg=1', '-p2pmsgpowbits=8', '-debug=net', ...(wsSupported ? [`-p2pwsbind=127.0.0.1:${wsPort}`] : [])],
    });
    const help = await node.rpc<string>('help', ['getp2pmsginfo']);
    leafSupported = /leaf_peers/.test(help);
  });
  afterAll(async () => {
    for (const c of clients) c.close();
    await node?.stop();
  });

  it('node prekey bundle verifies with our BLS scheme', async () => {
    const info = await node.rpc<{ identity_pubkey: string; inbox_pubkey: string; prekey_sig: string }>('getp2pmsginfo');
    expect(verifyBundle({ identity: fromHex(info.identity_pubkey), prekey: fromHex(info.inbox_pubkey), prekeySig: fromHex(info.prekey_sig) })).toBe(true);
  });

  it('two SDK clients exchange an acked message through the node', async () => {
    const alice = await mk(21);
    const bob = await mk(22);
    await alice.addContact(bob.bundle());
    const got = waitFor(bob, 'message');
    const acked = waitFor(alice, 'ack');
    const id = await alice.send(bob.identity, utf8('over the real bus'));
    const m = await got;
    expect(fromUtf8(m.payload)).toBe('over the real bus');
    expect(m.from).toBe(alice.identity);
    expect((await acked).msgId).toEqual(id);
    // reply rides the session key
    const back = waitFor(alice, 'message');
    await bob.send(alice.identity, utf8('ack received'));
    expect((await back).scope).toBe('session');
  }, 120000);

  it('discovery works over the real bus', async () => {
    const carol = await mk(23);
    const dave = await mk(24);
    const got = waitFor(dave, 'message');
    await carol.send(dave.identity, utf8('who are you'));
    expect(fromUtf8((await got).payload)).toBe('who are you');
  }, 120000);

  it('WebSocket client talks to a TCP client through the node', async ({ skip }) => {
    if (!wsPort) skip();
    const frank = await mk(26, 'ws');
    const grace = await mk(27, 'tcp');
    const peers = await node.rpc<Array<{ websocket?: boolean; subver: string }>>('getpeerinfo');
    expect(peers.filter((p) => p.websocket).length).toBe(1);
    await frank.addContact(grace.bundle());
    const got = waitFor(grace, 'message');
    const acked = waitFor(frank, 'ack');
    await frank.send(grace.identity, utf8('hello from the browser side'));
    expect(fromUtf8((await got).payload)).toBe('hello from the browser side');
    await acked;
    const back = waitFor(frank, 'message');
    await grace.send(frank.identity, utf8('hello ws'));
    expect(fromUtf8((await back).payload)).toBe('hello ws');
  }, 120000);

  it('SDK -> naviod inbox shows up in listp2pmsgs; naviod -> SDK arrives as raw', async () => {
    const erin = await mk(25);
    const info = await node.rpc<{ identity_pubkey: string; inbox_pubkey: string; prekey_sig: string }>('getp2pmsginfo');
    // Raw bus send of a USER_DATA frame to the node's inbox (node stores the opaque body).
    const body = serializeUserMsgFrame({ topic: 'hello-node', body: utf8('from sdk') });
    await erin.bus.send(USER_DATA_KIND, fromHex(info.inbox_pubkey), body, { stem: false });
    let stored: Array<{ topic: string; payload: string }> = [];
    for (let i = 0; i < 50 && stored.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 200));
      stored = await node.rpc('listp2pmsgs', [0, 0, 'hello-node']);
    }
    expect(stored.length).toBe(1);
    expect(stored[0]!.payload).toBe(toHex(utf8('from sdk')));

    // Node -> SDK: body is not an AuthFrame, so it surfaces as a `raw` event.
    const raw = waitFor(erin, 'raw');
    await node.rpc('sendp2pmsg', [toHex(erin.keyring.prekey.pub), 'from-node', toHex(utf8('hi sdk')), false]);
    const r = await raw;
    expect(r.topic).toBe('from-node');
    expect(fromUtf8(r.body)).toBe('hi sdk');
    expect(r.scope).toBe('inbox');
  }, 120000);
});
