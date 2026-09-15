/**
 * Integration: BusClient <-> real `naviod -regtest -p2pmsg=1 -p2pmsgpowbits=8`.
 * Proves BLS signature scheme, envelope/PoW/ECIES byte compatibility in both directions.
 * Run with `npm run test:int` (excluded from `npm test`).
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode } from '../../test/regtest-node.js';
import { fromHex, toHex, utf8 } from '../common/bytes.js';
import { ServiceFlags } from '../net/messages.js';
import { Peer } from '../net/peer.js';
import { TcpTransport } from '../net/tcp-transport.js';
import { generateSecret, isValidPublicKey, verifyAugmented } from './bls.js';
import { BusClient, type InboundMessage, PayloadKind } from './client.js';
import { parseEnvelope } from './envelope.js';
import { BusKeys } from './keyring.js';
import { PowGrinder } from './pow-grinder.js';
import { checkPoW } from './pow.js';

interface P2pMsgInfo {
  enabled: boolean;
  identity_pubkey: string;
  inbox_pubkey: string;
  prekey_sig: string;
  pings_received: number;
}

const haveBinary = existsSync(DEFAULT_NAVIOD);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe.skipIf(!haveBinary)('bus <-> naviod regtest interop', () => {
  let node: RegtestNode;
  let peer: Peer;
  let bus: BusClient;
  let keys: BusKeys;
  const grinder = new PowGrinder({ workers: 0 });
  const inbound: InboundMessage[] = [];
  const wireResults: string[] = [];

  function makePeer(services: bigint): Peer {
    return new Peer(new TcpTransport('127.0.0.1', node.port, { connectTimeoutMs: 5000 }), {
      network: 'regtest',
      services,
      handshakeTimeoutMs: 15_000,
      pingIntervalMs: 0,
    });
  }

  beforeAll(async () => {
    node = await startRegtestNode();
    // PR A (`feat/p2pmsg-leaf-bit`) makes a LEAF-only peer fluff-eligible and adds
    // `leaf_peers` to getp2pmsginfo. Builds without it only forward to peers
    // advertising NODE_P2PMSG, so fall back to advertising both bits there.
    const hasLeafSupport = 'leaf_peers' in (await node.rpc<Record<string, unknown>>('getp2pmsginfo'));
    if (!hasLeafSupport) process.stderr.write('[interop] naviod build lacks PR A (leaf bit); advertising NODE_P2PMSG too\n');
    peer = makePeer(hasLeafSupport ? ServiceFlags.NODE_P2PMSG_LEAF : ServiceFlags.NODE_P2PMSG_LEAF | ServiceFlags.NODE_P2PMSG);
    keys = new BusKeys();
    keys.setInbox(generateSecret());
    bus = new BusClient({
      network: 'regtest',
      keys,
      grinder,
      sink: { broadcast: (env, { stem }) => peer.sendP2pMsg(env, stem) },
      clockOffsetSeconds: () => peer.clockOffsetSeconds,
      onError: (e) => process.stderr.write(`[bus error] ${String(e)}\n`),
    });
    bus.on(PayloadKind.PING, (m) => inbound.push(m));
    peer.on('message', (m) => {
      wireResults.push(bus.onWire(peer.id, m.stem, m.payload));
    });
    await peer.connect();
  }, 120_000);

  afterAll(async () => {
    bus?.close();
    grinder.close();
    peer?.close();
    await node?.stop();
  });

  async function info(): Promise<P2pMsgInfo> {
    return node.rpc<P2pMsgInfo>('getp2pmsginfo');
  }

  async function waitFor(pred: () => boolean, what: string, ms = 30_000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!pred()) {
      if (Date.now() > deadline) throw new Error(`timeout waiting for ${what}; wire results: ${wireResults.join(',')}`);
      await sleep(50);
    }
  }

  it('node prekey bundle verifies under our BLS scheme (augmented, POP DST)', async () => {
    const i = await info();
    expect(i.enabled).toBe(true);
    const identity = fromHex(i.identity_pubkey);
    const inbox = fromHex(i.inbox_pubkey);
    const sig = fromHex(i.prekey_sig);
    expect(identity.length).toBe(48);
    expect(inbox.length).toBe(48);
    expect(sig.length).toBe(96);
    expect(isValidPublicKey(identity)).toBe(true);
    expect(isValidPublicKey(inbox)).toBe(true);
    expect(verifyAugmented(identity, inbox, sig)).toBe(true);
    // negative control: the same signature must not verify for a different message
    expect(verifyAugmented(identity, identity, sig)).toBe(false);
  });

  it('node -> SDK: sendp2pping to our inbox is decrypted with recipient=inbox', async () => {
    const ok = await node.rpc<boolean>('sendp2pping', [toHex(keys.inboxPublic!), false]);
    expect(ok).toBe(true);
    await waitFor(() => inbound.length >= 1, 'PING from node');
    const m = inbound[0]!;
    expect(Array.from(m.body)).toEqual([0x70, 0x69, 0x6e, 0x67]);
    expect(m.recipient).toBe('inbox');
    expect(m.kind).toBe(PayloadKind.PING);
    expect(m.stem).toBe(false);
    expect(wireResults).toContain('accepted');
    expect(wireResults).not.toContain('badpow');
    expect(wireResults).not.toContain('invalid');
  });

  it('node -> SDK: broadcast-scoped ping (generator key) decrypts with recipient=broadcast', async () => {
    const before = inbound.length;
    const { BROADCAST_PUBLIC } = await import('./bls.js');
    await node.rpc<boolean>('sendp2pping', [toHex(BROADCAST_PUBLIC), false]);
    await waitFor(() => inbound.length > before, 'broadcast PING from node');
    expect(inbound[before]!.recipient).toBe('broadcast');
  });

  it('SDK -> node (fluff): bus.send PING is accepted, decrypted and counted', async () => {
    const before = (await info()).pings_received;
    const nodeInbox = fromHex((await info()).inbox_pubkey);
    const env = await bus.send(PayloadKind.PING, nodeInbox, utf8('ping'), { stem: false });
    expect(env.length).toBeLessThanOrEqual(4096);
    let after = before;
    await waitFor(() => {
      void info().then((i) => (after = i.pings_received));
      return after > before;
    }, 'pings_received to increment (fluff)');
    expect(after).toBe(before + 1);
  });

  it('SDK -> node (stem): dp2pmsg is also decrypted and counted', async () => {
    const before = (await info()).pings_received;
    const nodeInbox = fromHex((await info()).inbox_pubkey);
    await bus.send(PayloadKind.PING, nodeInbox, utf8('ping'), { stem: true });
    let after = before;
    await waitFor(() => {
      void info().then((i) => (after = i.pings_received));
      return after > before;
    }, 'pings_received to increment (stem)');
    expect(after).toBe(before + 1);
  });

  it('SDK -> node: a message with insufficient PoW is NOT counted', async () => {
    const before = (await info()).pings_received;
    const nodeInbox = fromHex((await info()).inbox_pubkey);
    const weak = new BusClient({
      keys,
      powBits: 0,
      grinder,
      sink: { broadcast: (env, { stem }) => peer.sendP2pMsg(env, stem) },
      clockOffsetSeconds: () => peer.clockOffsetSeconds,
    });
    const env = parseEnvelope(await weak.send(PayloadKind.PING, nodeInbox, utf8('ping'), { stem: false }));
    await sleep(1500);
    // A bits=0 stamp meets bits=8 by chance 1/256 of the time; only assert when it genuinely fails.
    if (!checkPoW(env.pow, 8)) expect((await info()).pings_received).toBe(before);
    expect(peer.connected).toBe(true);
    weak.close();
  });
});
