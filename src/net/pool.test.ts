import { describe, expect, it } from 'vitest';
import { utf8 } from '../common/bytes.js';
import { MessageType, ServiceFlags, type NetAddress } from './messages.js';
import { MockNode, MockTransport, type MockNodeOptions } from './mock-transport.js';
import { PeerPool, normalizeAddress, type PeerPoolOptions } from './pool.js';
import { parsePeerAddress } from './transport.js';

const tick = () => new Promise((r) => setTimeout(r, 0));
async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 2));
  }
}

/** A "network" of mock nodes keyed by address; the factory hands out one end of a fresh pair per dial. */
function mockNetwork(nodeOpts: (address: string) => Partial<MockNodeOptions> | null = () => ({})) {
  const nodes = new Map<string, MockNode[]>();
  const dials: string[] = [];
  const factory = (address: string): MockTransport => {
    dials.push(address);
    const opts = nodeOpts(address);
    const [client, server] = MockTransport.pair(address, `node@${address}`, opts === null ? { failConnect: new Error('refused') } : {});
    if (opts !== null) {
      const node = new MockNode(server, { network: 'regtest', ...opts });
      const list = nodes.get(address) ?? [];
      list.push(node);
      nodes.set(address, list);
    }
    return client;
  };
  const live = () => [...nodes.values()].flat().filter((n) => !n.closed);
  return { factory, nodes, dials, live };
}

function makePool(extra: Partial<PeerPoolOptions> & { transportFactory: PeerPoolOptions['transportFactory'] }): PeerPool {
  return new PeerPool({
    network: 'regtest',
    allowDns: false,
    minBackoffMs: 5,
    maxBackoffMs: 50,
    maintainIntervalMs: 20,
    peerOptions: { pingIntervalMs: 0, handshakeTimeoutMs: 500 },
    ...extra,
  });
}

describe('PeerPool', () => {
  it('connects to targetPeers from seeds and reports them', async () => {
    const net = mockNetwork();
    const seeds = ['10.0.0.1:18444', '10.0.0.2', '[2001:db8::3]:18444', '10.0.0.4:18444'];
    const pool = makePool({ seeds, targetPeers: 3, transportFactory: net.factory });
    const events: string[] = [];
    pool.on('peer', (p) => events.push(p.address));
    await pool.start();
    await until(() => pool.peers().length === 3);
    await tick();
    expect(pool.connectedCount).toBe(3);
    expect(events).toHaveLength(3);
    expect(new Set(net.dials).size).toBe(3); // no duplicate concurrent dials
    for (const p of pool.peers()) {
      expect(p.services).toBe(ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG);
      expect(p.userAgent).toBe('/MockNode:0.0.1/');
      expect(p.id.startsWith(p.address + '#')).toBe(true);
    }
    // Address book keys are normalised.
    expect(normalizeAddress('10.0.0.2', 'regtest')).toBe('10.0.0.2:18444');
    pool.stop();
    await tick();
    expect(pool.peers()).toHaveLength(0);
    expect(net.live()).toHaveLength(0);
  });

  it('reconnects after a peer closes (with backoff) and emits peerclose', async () => {
    const net = mockNetwork();
    const pool = makePool({ seeds: ['1.1.1.1:1'], targetPeers: 1, transportFactory: net.factory });
    const closes: unknown[] = [];
    pool.on('peerclose', (e) => closes.push(e));
    await pool.start();
    await until(() => pool.connectedCount === 1);
    const first = pool.peers()[0]!.id;
    net.live()[0]!.close();
    await until(() => pool.connectedCount === 0);
    await until(() => pool.connectedCount === 1);
    expect(pool.peers()[0]!.id).not.toBe(first);
    expect(net.dials).toEqual(['1.1.1.1:1', '1.1.1.1:1']);
    expect(closes).toHaveLength(1);
    expect((closes[0] as { wasConnected: boolean }).wasConnected).toBe(true);
    pool.stop();
  });

  it('retries failed dials with backoff and moves on to other addresses', async () => {
    const attempts = new Map<string, number>();
    const net = mockNetwork((addr) => {
      attempts.set(addr, (attempts.get(addr) ?? 0) + 1);
      if (addr === '2.2.2.2:2') return attempts.get(addr)! < 3 ? null : {};
      return {};
    });
    const pool = makePool({ seeds: ['2.2.2.2:2', '3.3.3.3:3'], targetPeers: 2, transportFactory: net.factory });
    const errors: Error[] = [];
    pool.on('error', (e) => errors.push(e));
    await pool.start();
    await until(() => pool.connectedCount === 2, 5000);
    expect(attempts.get('2.2.2.2:2')).toBe(3);
    expect(errors.some((e) => /refused/.test(e.message))).toBe(true);
    pool.stop();
  });

  it('learns gossiped addresses that advertise NODE_P2PMSG and dials them', async () => {
    const gossip: NetAddress[] = [
      { host: '7.7.7.7', port: 18444, services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG, time: 1 },
      { host: '8.8.8.8', port: 18444, services: ServiceFlags.NODE_NETWORK, time: 1 }, // no p2pmsg → ignored
    ];
    const net = mockNetwork((addr) => (addr === '5.5.5.5:18444' ? { addrs: gossip } : {}));
    const pool = makePool({ seeds: ['5.5.5.5'], targetPeers: 2, transportFactory: net.factory });
    const learned: string[] = [];
    pool.on('addr', (a) => learned.push(a.address));
    await pool.start();
    await until(() => pool.connectedCount === 2);
    expect(learned).toEqual(['7.7.7.7:18444']);
    expect(pool.addresses().map((a) => a.address).sort()).toEqual(['5.5.5.5:18444', '7.7.7.7:18444']);
    expect(net.dials).toContain('7.7.7.7:18444');
    expect(net.dials).not.toContain('8.8.8.8:18444');
    pool.stop();
  });

  it('broadcast: stem → exactly one peer (dp2pmsg), fluff → all (p2pmsg)', async () => {
    const net = mockNetwork();
    const pool = makePool({ seeds: ['a:1', 'b:1', 'c:1'], targetPeers: 3, transportFactory: net.factory });
    await pool.start();
    await until(() => pool.connectedCount === 3);
    await tick();

    expect(pool.broadcast(utf8('stem'), { stem: true })).toBe(1);
    await until(() => net.live().some((n) => n.received.some((m) => m.command === MessageType.DP2PMSG)));
    await tick();
    const stemReceivers = net.live().filter((n) => n.received.some((m) => m.command === MessageType.DP2PMSG));
    expect(stemReceivers).toHaveLength(1);
    expect(net.live().some((n) => n.received.some((m) => m.command === MessageType.P2PMSG))).toBe(false);

    expect(pool.broadcast(utf8('fluff'), { stem: false })).toBe(3);
    await until(() => net.live().every((n) => n.received.some((m) => m.command === MessageType.P2PMSG)));
    pool.stop();
    expect(pool.broadcast(utf8('x'), { stem: false })).toBe(0);
  });

  it('delivers inbound p2pmsg with the peer id and computes the median clock offset', async () => {
    const skews: Record<string, number> = { 'a:1': 10, 'b:1': -30, 'c:1': 4 };
    const net = mockNetwork((addr) => ({ clockSkewSeconds: skews[addr] }));
    const pool = makePool({ seeds: Object.keys(skews), targetPeers: 3, transportFactory: net.factory });
    const got: { peerId: string; stem: boolean; payload: Uint8Array }[] = [];
    pool.on('message', (m) => got.push(m));
    await pool.start();
    await until(() => pool.connectedCount === 3);
    expect(pool.medianClockOffset()).toBe(4);

    const node = net.live()[0]!;
    node.sendP2pMsg(utf8('hi'), true);
    await until(() => got.length === 1);
    expect(got[0]!.stem).toBe(true);
    expect(pool.peers().map((p) => p.id)).toContain(got[0]!.peerId);
    pool.stop();
    expect(pool.medianClockOffset()).toBe(0);
  });

  it('addPeerAddress triggers a dial while running and rejects junk', async () => {
    const net = mockNetwork();
    const pool = makePool({ targetPeers: 1, transportFactory: net.factory });
    const errors: Error[] = [];
    pool.on('error', (e) => errors.push(e));
    await pool.start();
    await tick();
    expect(pool.connectedCount).toBe(0);
    expect(pool.addPeerAddress('ftp://nope')).toBe(false);
    expect(errors).toHaveLength(1);
    expect(pool.addPeerAddress('9.9.9.9:9')).toBe(true);
    expect(pool.addPeerAddress('9.9.9.9:9')).toBe(false); // duplicate
    await until(() => pool.connectedCount === 1);
    pool.stop();
  });
});

describe('parsePeerAddress', () => {
  it('parses all supported forms', () => {
    expect(parsePeerAddress('1.2.3.4:5', 9)).toEqual({ kind: 'tcp', host: '1.2.3.4', port: 5 });
    expect(parsePeerAddress('example.com', 9)).toEqual({ kind: 'tcp', host: 'example.com', port: 9 });
    expect(parsePeerAddress('[::1]:7', 9)).toEqual({ kind: 'tcp', host: '::1', port: 7 });
    expect(parsePeerAddress('[::1]', 9)).toEqual({ kind: 'tcp', host: '::1', port: 9 });
    expect(parsePeerAddress('2001:db8::1', 9)).toEqual({ kind: 'tcp', host: '2001:db8::1', port: 9 });
    expect(parsePeerAddress('ws://h:1/p', 9)).toEqual({ kind: 'ws', host: 'h', port: 1, url: 'ws://h:1/p' });
    expect(parsePeerAddress('wss://h', 9)).toEqual({ kind: 'ws', host: 'h', port: 443, url: 'wss://h/' });
    expect(() => parsePeerAddress('h:99999', 9)).toThrow();
    expect(() => parsePeerAddress('http://h', 9)).toThrow();
    expect(() => parsePeerAddress('', 9)).toThrow();
  });
});

describe('IPv6 deprioritisation', () => {
  it('dials IPv4 first after an IPv6 no-route failure', async () => {
    const dials: string[] = [];
    const factory = (address: string): MockTransport => {
      dials.push(address);
      const v6 = address.startsWith('[');
      const err = Object.assign(new Error(`connect EHOSTUNREACH ${address}`), { code: 'EHOSTUNREACH' });
      const [client, server] = MockTransport.pair(address, `node@${address}`, v6 ? { failConnect: err } : {});
      if (!v6) new MockNode(server, { network: 'regtest' });
      return client;
    };
    // Book: 6 IPv6 seeds + 1 IPv4, target 1. random() = 0 makes the shuffle deterministic
    // (identity), so IPv6 addresses come first in book order.
    const seeds = ['[2001:db8::1]:1', '[2001:db8::2]:1', '[2001:db8::3]:1', '[2001:db8::4]:1', '[2001:db8::5]:1', '[2001:db8::6]:1', '9.9.9.9:1'];
    const pool = new PeerPool({ network: 'regtest', seeds, targetPeers: 1, transportFactory: factory, dnsSeeds: [], allowDns: false, random: () => 0, minBackoffMs: 5, maxBackoffMs: 10 });
    const connected = new Promise<void>((r) => pool.on('peer', () => r()));
    await pool.start();
    await connected;
    pool.stop();
    // First dial is IPv6 (fails with no route); after that IPv4 must be preferred immediately.
    expect(dials[0]!.startsWith('[')).toBe(true);
    expect(dials.filter((d) => d.startsWith('[')).length).toBe(1);
    expect(dials[1]).toBe('9.9.9.9:1');
  });
});
