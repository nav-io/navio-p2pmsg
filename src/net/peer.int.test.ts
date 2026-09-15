/**
 * Integration: real `naviod -regtest` <-> Peer over TcpTransport.
 * Run with `npm run test:int` (excluded from `npm test`).
 */
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, startRegtestNode, type RegtestNode } from '../../test/regtest-node.js';
import { MessageType, ServiceFlags, hasService } from './messages.js';
import { Peer } from './peer.js';
import { PeerPool } from './pool.js';
import { TcpTransport } from './tcp-transport.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);

describe.skipIf(!haveBinary)('Peer <-> naviod regtest', () => {
  let node: RegtestNode;

  beforeAll(async () => {
    node = await startRegtestNode();
  });

  afterAll(async () => {
    await node?.stop();
  });

  it('completes the handshake, exchanges ping/pong, and closes cleanly', async () => {
    const transport = new TcpTransport('127.0.0.1', node.port, { connectTimeoutMs: 5000 });
    // Count outgoing pongs (the node pings us right after verack, and again on `rpc ping`).
    let pongsSent = 0;
    const origSend = transport.send.bind(transport);
    transport.send = (b: Uint8Array) => {
      origSend(b);
      if (new TextDecoder().decode(b.subarray(4, 16)).replace(/\0+$/, '') === MessageType.PONG) pongsSent++;
    };
    const peer = new Peer(transport, {
      network: 'regtest',
      services: ServiceFlags.NODE_P2PMSG_LEAF,
      handshakeTimeoutMs: 15_000,
      pingIntervalMs: 0,
    });
    const errors: Error[] = [];
    peer.on('error', (e) => errors.push(e));
    const closed = new Promise<Error | undefined>((r) => peer.on('close', r));

    await peer.connect();
    expect(peer.connected).toBe(true);
    const v = peer.peerVersion!;
    expect(v.version).toBeGreaterThanOrEqual(70016);
    expect(hasService(v.services, ServiceFlags.NODE_P2PMSG)).toBe(true);
    expect(hasService(v.services, ServiceFlags.NODE_NETWORK)).toBe(true);
    expect(v.userAgent).toMatch(/^\/.+\/$/);
    expect(Math.abs(peer.clockOffsetSeconds)).toBeLessThan(5);

    // Our ping → its pong.
    const rtt = new Promise<number>((r) => peer.once('pong', r));
    peer.ping();
    expect(await rtt).toBeGreaterThanOrEqual(0);

    // The node should see us as an inbound peer advertising the leaf bit.
    const peers = await node.rpc<{ inbound: boolean; subver: string; services: string }[]>('getpeerinfo');
    expect(peers).toHaveLength(1);
    expect(peers[0]!.inbound).toBe(true);
    expect(peers[0]!.subver).toMatch(/navio-p2pmsg/);
    expect(BigInt('0x' + peers[0]!.services) & ServiceFlags.NODE_P2PMSG_LEAF).toBe(ServiceFlags.NODE_P2PMSG_LEAF);

    // Its ping → our pong. Provoke a fresh ping via RPC and wait for our reply to go out.
    const before = pongsSent;
    await node.rpc('ping');
    const deadline = Date.now() + 10_000;
    while (pongsSent === before) {
      if (Date.now() > deadline) throw new Error('no pong sent in response to the node ping');
      await new Promise((r) => setTimeout(r, 20));
    }

    // Sending an envelope is accepted at the framing level (node validates PoW later).
    peer.sendP2pMsg(new Uint8Array(10), false);
    await new Promise((r) => setTimeout(r, 200));
    expect(peer.connected).toBe(true);

    expect(errors).toEqual([]);
    peer.close();
    expect(await closed).toBeUndefined();
    await new Promise((r) => setTimeout(r, 300));
    expect(await node.rpc<unknown[]>('getpeerinfo')).toHaveLength(0);
  });

  it('PeerPool keeps a connection to the node over TCP', async () => {
    const pool = new PeerPool({
      network: 'regtest',
      seeds: [`127.0.0.1:${node.port}`],
      targetPeers: 1,
      allowDns: false,
      peerOptions: { pingIntervalMs: 0 },
    });
    const connected = new Promise<void>((resolve) => pool.once('peer', () => resolve()));
    await pool.start();
    await connected;
    expect(pool.peers()).toHaveLength(1);
    expect(hasService(pool.peers()[0]!.services, ServiceFlags.NODE_P2PMSG)).toBe(true);
    expect(pool.broadcast(new Uint8Array(4), { stem: true })).toBe(1);
    pool.stop();
    await new Promise((r) => setTimeout(r, 300));
    expect(await node.rpc<unknown[]>('getpeerinfo')).toHaveLength(0);
  });
});
