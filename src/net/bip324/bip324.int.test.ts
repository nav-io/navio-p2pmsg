/**
 * Integration: a real BIP324 v2 handshake against naviod.
 *
 * The BIP's own vectors pin the cryptography; this pins the thing vectors
 * cannot — that our handshake, garbage handling, message-id encoding and
 * framing are what an actual node expects. Run with `npm run test:int`.
 */
import { existsSync } from 'node:fs';
import { createConnection, type Socket } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_NAVIOD, type RegtestNode, startRegtestNode, supportedFlags } from '../../../test/regtest-node.js';
import { randomBytes } from '../../common/bytes.js';
import { decodeVersion, encodeVersion, NetworkMagic, ServiceFlags } from '../messages.js';
import { V2Session } from './session.js';

const haveBinary = existsSync(DEFAULT_NAVIOD);
const haveV2 = haveBinary && supportedFlags(DEFAULT_NAVIOD).has('-v2transport');

describe.skipIf(!haveV2)('BIP324 <-> naviod regtest', () => {
  let node: RegtestNode;

  beforeAll(async () => {
    node = await startRegtestNode({ extraArgs: ['-v2transport=1', '-p2pmsg=1', '-p2pmsgpowbits=8'] });
  }, 120000);

  afterAll(async () => {
    await node?.stop();
  });

  it('completes a v2 handshake and exchanges version/verack and ping/pong', async () => {
    const magic = NetworkMagic.regtest;
    const session = new V2Session({ magic, randomBytes });
    const sock: Socket = createConnection({ host: '127.0.0.1', port: node.port });
    const seen = new Map<string, Uint8Array>();
    let failure: Error | undefined;
    let transport: string | undefined;

    try {
      await new Promise<void>((resolve, reject) => {
        sock.once('connect', resolve);
        sock.once('error', reject);
      });
      sock.write(session.start());

      let sentVersion = false;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timeout; saw ${[...seen.keys()].join(',') || 'nothing'}`)), 30000);
        sock.on('error', reject);
        sock.on('close', () => reject(new Error('node closed the connection')));
        sock.on('data', (chunk) => {
          try {
            const res = session.receive(new Uint8Array(chunk));
            if (res.v1Fallback) throw new Error('node fell back to v1 despite -v2transport=1');
            if (session.currentState === 'failed') throw new Error('v2 session failed');
            if (res.send) sock.write(res.send);

            // Send our version as soon as the encrypted channel is up.
            if (session.currentState === 'ready' && !sentVersion) {
              sentVersion = true;
              sock.write(session.encode('version', encodeVersion({
                version: 70016,
                services: ServiceFlags.NODE_P2PMSG_LEAF,
                timestamp: BigInt(Math.floor(Date.now() / 1000)),
                addrRecv: { services: 0n, host: '::', port: 0 },
                addrFrom: { services: ServiceFlags.NODE_P2PMSG_LEAF, host: '::', port: 0 },
                nonce: 0n,
                userAgent: '/navio-p2pmsg-bip324-test/',
                startHeight: 0,
                relay: false,
              })));
            }

            for (const m of res.messages) {
              seen.set(m.command, m.payload);
              if (m.command === 'version') sock.write(session.encode('verack', new Uint8Array(0)));
              if (m.command === 'verack') sock.write(session.encode('ping', new Uint8Array(8)));
              if (m.command === 'pong') {
                clearTimeout(timer);
                resolve();
              }
            }
          } catch (e) {
            clearTimeout(timer);
            reject(e instanceof Error ? e : new Error(String(e)));
          }
        });
      });

      // While the connection is still OPEN: the node must agree this is a v2
      // link, not merely that it answered us.
      const peers = await node.rpc<Array<{ transport_protocol_type?: string; subver: string }>>('getpeerinfo');
      transport = peers.find((p) => p.subver.includes('bip324-test'))?.transport_protocol_type;
    } catch (e) {
      failure = e instanceof Error ? e : new Error(String(e));
    } finally {
      sock.destroy();
    }

    if (failure) throw failure;

    expect(session.currentState).toBe('ready');
    expect(session.sessionId).toHaveLength(32);
    // The node answered inside the encrypted channel, which is only possible
    // if every derived key, the garbage terminator and the framing all match.
    expect(seen.has('version')).toBe(true);
    expect(seen.has('verack')).toBe(true);
    expect(seen.has('pong')).toBe(true);

    const v = decodeVersion(seen.get('version')!);
    expect(v.version).toBeGreaterThanOrEqual(70016);
    expect(v.userAgent).toMatch(/Navio/i);

    expect(transport).toBe('v2');
  }, 120000);

  it('drives a full Peer handshake over v2', async () => {
    // The raw test above proves the cryptography interoperates; this proves the
    // integration does — that `Peer` queues its `version` behind the BIP324
    // handshake and everything above the transport is unaware of the change.
    const { Peer } = await import('../peer.js');
    const { TcpTransport } = await import('../tcp-transport.js');
    const peer = new Peer(new TcpTransport('127.0.0.1', node.port), {
      network: 'regtest',
      transportVersion: 'v2-only',
      userAgent: '/navio-p2pmsg-v2-peer-test/',
      handshakeTimeoutMs: 20000,
    });
    try {
      await peer.connect();
      expect(peer.connected).toBe(true);
      expect(peer.transportVersion).toBe('v2');
      expect(peer.sessionId).toHaveLength(32);
      expect(peer.peerVersion?.userAgent).toMatch(/Navio/i);

      const peers = await node.rpc<Array<{ transport_protocol_type?: string; subver: string }>>('getpeerinfo');
      const us = peers.find((p) => p.subver.includes('v2-peer-test'));
      expect(us?.transport_protocol_type).toBe('v2');
    } finally {
      peer.close();
    }
  }, 120000);
});
