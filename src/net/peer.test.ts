import { describe, expect, it } from 'vitest';
import { toHex, utf8 } from '../common/bytes.js';
import { encodeMessage } from './codec.js';
import { MessageType, ServiceFlags, decodePing, decodeVersion, encodeAddr, encodePong } from './messages.js';
import { MockNode, MockTransport, type MockNodeOptions } from './mock-transport.js';
import { Peer, type PeerOptions } from './peer.js';

function setup(nodeOpts: Partial<MockNodeOptions> = {}, peerOpts: Partial<PeerOptions> = {}) {
  const [client, server] = MockTransport.pair('127.0.0.1:18444', 'node');
  const node = new MockNode(server, { network: 'regtest', ...nodeOpts });
  const peer = new Peer(client, { network: 'regtest', pingIntervalMs: 0, ...peerOpts });
  return { peer, node, client, server };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe('Peer', () => {
  it('completes the handshake both ways and records peerVersion', async () => {
    const { peer, node } = setup({ clockSkewSeconds: 42, userAgent: '/naviod:1.0/', startHeight: 77 });
    const connectedEvents: unknown[] = [];
    peer.on('connected', (v) => connectedEvents.push(v));

    await peer.connect();

    expect(peer.connected).toBe(true);
    expect(peer.state).toBe('connected');
    expect(connectedEvents).toHaveLength(1);
    expect(peer.peerVersion?.userAgent).toBe('/naviod:1.0/');
    expect(peer.peerVersion?.startHeight).toBe(77);
    expect(peer.peerVersion?.version).toBe(70016);
    expect(peer.peerVersion?.services).toBe(ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG_V2);
    expect(peer.clockOffsetSeconds).toBeGreaterThanOrEqual(41);
    expect(peer.clockOffsetSeconds).toBeLessThanOrEqual(43);

    // Our side: version first, then (after their version) sendaddrv2 + verack, then getaddr after handshake.
    await node.waitFor(MessageType.GETADDR);
    const cmds = node.received.map((m) => m.command);
    expect(cmds).toEqual(['version', 'sendaddrv2', 'verack', 'getaddr']);
    expect(cmds.indexOf('sendaddrv2')).toBeLessThan(cmds.indexOf('verack'));
    expect(node.handshakeComplete).toBe(true);

    const ourVersion = decodeVersion(node.received[0]!.payload);
    expect(ourVersion.services).toBe(ServiceFlags.NODE_P2PMSG_LEAF);
    expect(ourVersion.relay).toBe(false);
    expect(ourVersion.startHeight).toBe(0);
    expect(ourVersion.userAgent).toMatch(/^\/navio-p2pmsg:/);

    peer.close();
    expect(peer.closed).toBe(true);
  });

  it('proceeds with an old-protocol peer (no sendaddrv2 for < 70016)', async () => {
    const { peer, node } = setup({ version: 70015 });
    await peer.connect();
    await node.waitFor(MessageType.GETADDR);
    expect(node.received.map((m) => m.command)).toEqual(['version', 'verack', 'getaddr']);
    peer.close();
  });

  it('replies to ping with pong carrying the same nonce', async () => {
    const { peer, node } = setup();
    await peer.connect();
    node.send(MessageType.PING, encodePong(0xdeadbeefn));
    const pong = await node.waitFor(MessageType.PONG);
    expect(decodePing(pong.payload)).toBe(0xdeadbeefn);
    peer.close();
  });

  it('sends periodic pings, emits pong RTT, and drops the peer when pong never comes', async () => {
    // Responsive node: pong arrives, 'pong' event fires.
    {
      const { peer, node } = setup({}, { pingIntervalMs: 20 });
      await peer.connect();
      const rtt = await new Promise<number>((r) => peer.once('pong', r));
      expect(rtt).toBeGreaterThanOrEqual(0);
      await node.waitFor(MessageType.PING);
      peer.close();
    }
    // Silent node: closed with a ping-timeout error after 2x interval.
    {
      const { peer } = setup({ respondPing: false }, { pingIntervalMs: 20 });
      const closed = new Promise<Error | undefined>((r) => peer.on('close', r));
      await peer.connect();
      const err = await closed;
      expect(err?.message).toMatch(/ping timeout/);
      expect(peer.closed).toBe(true);
    }
  });

  it('emits message for p2pmsg (fluff) and dp2pmsg (stem)', async () => {
    const { peer, node } = setup();
    const got: { stem: boolean; payload: Uint8Array }[] = [];
    peer.on('message', (m) => got.push(m));
    await peer.connect();
    node.sendP2pMsg(utf8('fluff'), false);
    node.sendP2pMsg(utf8('stem'), true);
    while (got.length < 2) await tick();
    expect(got[0]!.stem).toBe(false);
    expect(toHex(got[0]!.payload)).toBe(toHex(utf8('fluff')));
    expect(got[1]!.stem).toBe(true);
    expect(toHex(got[1]!.payload)).toBe(toHex(utf8('stem')));
    peer.close();
  });

  it('sendP2pMsg picks the command from the stem flag', async () => {
    const { peer, node } = setup();
    await peer.connect();
    peer.sendP2pMsg(utf8('a'), true);
    peer.sendP2pMsg(utf8('b'), false);
    await node.waitFor(MessageType.P2PMSG);
    const cmds = node.received.map((m) => m.command);
    expect(cmds).toContain('dp2pmsg');
    expect(cmds).toContain('p2pmsg');
    peer.close();
  });

  it('emits addr for addrv2 and legacy addr messages', async () => {
    const addrs = [{ host: '9.9.9.9', port: 48470, services: ServiceFlags.NODE_P2PMSG, time: 123 }];
    const { peer, node } = setup({ addrs });
    const got: unknown[] = [];
    peer.on('addr', (a) => got.push(a));
    await peer.connect();
    // MockNode replies to getaddr with addrv2; also send a legacy addr.
    node.send(MessageType.ADDR, encodeAddr([{ host: '8.8.8.8', port: 1, services: 0n, time: 5 }]));
    while (got.length < 2) await tick();
    expect(got[0]).toEqual(addrs);
    expect(got[1]).toEqual([{ host: '8.8.8.8', port: 1, services: 0n, time: 5 }]);
    peer.close();
  });

  it('rejects connect on handshake timeout', async () => {
    const { peer } = setup({ autoHandshake: false }, { handshakeTimeoutMs: 30 });
    const closed = new Promise<Error | undefined>((r) => peer.on('close', r));
    await expect(peer.connect()).rejects.toThrow(/handshake timeout/);
    expect((await closed)?.message).toMatch(/handshake timeout/);
    expect(peer.closed).toBe(true);
  });

  it('rejects connect when the transport fails to connect', async () => {
    const [client] = MockTransport.pair('x', 'y', { failConnect: new Error('ECONNREFUSED') });
    const peer = new Peer(client, { network: 'regtest' });
    const closed = new Promise<Error | undefined>((r) => peer.on('close', r));
    await expect(peer.connect()).rejects.toThrow('ECONNREFUSED');
    expect((await closed)?.message).toBe('ECONNREFUSED');
  });

  it('rejects connect when the remote drops mid-handshake', async () => {
    const { peer, node } = setup({ autoHandshake: false });
    const p = peer.connect();
    await node.waitFor(MessageType.VERSION);
    node.close();
    await expect(p).rejects.toThrow(/closed before handshake/);
  });

  it('ignores unrelated commands and pre-handshake p2pmsg', async () => {
    const { peer, node, client } = setup({ autoHandshake: false });
    const got: unknown[] = [];
    peer.on('message', (m) => got.push(m));
    const p = peer.connect().catch((e: Error) => e);
    await node.waitFor(MessageType.VERSION);
    node.send(MessageType.P2PMSG, utf8('early'));
    node.send('inv', new Uint8Array([0]));
    node.send('headers', new Uint8Array([0]));
    // Echo our own version back: our nonce → self-connection detection closes the peer.
    node.send(MessageType.VERSION, node.received[0]!.payload);
    const err = await p;
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/self/);
    expect(got).toHaveLength(0);
    await tick();
    expect(client.closed).toBe(true);
  });

  it('closes with ProtocolError on an oversize frame and emits error on bad checksum', async () => {
    const { peer, node, server } = setup();
    const errors: Error[] = [];
    peer.on('error', (e) => errors.push(e));
    await peer.connect();

    const bad = encodeMessage(peer.magic, 'ping', new Uint8Array(8));
    bad[20] ^= 1;
    server.send(bad);
    while (errors.length < 1) await tick();
    expect(errors[0]!.message).toMatch(/bad checksum/);
    expect(peer.connected).toBe(true);

    const closed = new Promise<Error | undefined>((r) => peer.on('close', r));
    const huge = encodeMessage(peer.magic, 'block', new Uint8Array(0));
    new DataView(huge.buffer).setUint32(16, 0xffffffff, true);
    server.send(huge);
    const err = await closed;
    expect(err?.name).toBe('ProtocolError');
    await tick();
    expect(node.closed).toBe(true);
  });

  it('close is idempotent and emits close exactly once', async () => {
    const { peer } = setup();
    let n = 0;
    peer.on('close', () => n++);
    await peer.connect();
    peer.close();
    peer.close();
    await tick();
    expect(n).toBe(1);
    expect(() => peer.send('ping')).toThrow(/not connected/);
  });
});
