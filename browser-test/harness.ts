/**
 * Browser test harness: regtest naviod with a WebSocket listener, a Node-side
 * MessagingClient ("bob") on TCP that echoes every message back, and a static
 * server for the page. Prints the URL to open. Ctrl-C to stop.
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { getFreePort, startRegtestNode } from '../test/regtest-node.js';
import { MessagingClient, MemoryStore, ServiceFlags, utf8, fromUtf8 } from '../src/index.js';

const wsPort = await getFreePort();
const httpPort = await getFreePort();
const node = await startRegtestNode({ extraArgs: [`-p2pwsbind=127.0.0.1:${wsPort}`] });
console.log(`naviod pid=${node.pid} p2p=${node.port} rpc=${node.rpcPort} ws=${wsPort}`);

const bob = await MessagingClient.create({
  network: 'regtest',
  seed: new Uint8Array(32).fill(0x42),
  store: new MemoryStore(),
  peers: [`127.0.0.1:${node.port}`],
  targetPeers: 1,
  dnsSeeds: [],
  powBits: 8,
  powWorkers: 1,
  ackDelayMs: 100,
  services: ServiceFlags.NODE_P2PMSG_LEAF,
});
bob.on('peer', (p) => console.log(`[bob] peer ${p.address}`));
bob.on('error', (e) => console.log(`[bob] error ${e.message}`));
bob.on('contact', (c) => console.log(`[bob] learned ${c.identity}`));
bob.on('ack', (a) => console.log(`[bob] ack from ${a.to}`));
bob.on('sent', (s) => console.log(`[bob] sent msg=${Buffer.from(s.msgId).toString('hex').slice(0,8)} chunk=${s.chunk} attempt=${s.attempt} peers=${s.peers} t=${Date.now() % 100000}`));
bob.on('expired', (e) => console.log(`[bob] expired ${e.to}`));
bob.on('message', async (m) => {
  console.log(`[bob] message from ${m.from} scope=${m.scope}: ${fromUtf8(m.payload)}`);
  if (m.from) await bob.send(m.from, utf8(`echo: ${fromUtf8(m.payload)}`));
});
await bob.connect();
console.log(`[bob] identity ${bob.identity}`);

const root = join(import.meta.dirname, '.');
const types: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.map': 'application/json' };
createServer(async (req, res) => {
  const path = req.url === '/' || req.url?.startsWith('/?') ? '/index.html' : req.url!.split('?')[0]!;
  const file = path === '/index.html' ? join(root, 'index.html') : join(root, 'out', path);
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(httpPort, '127.0.0.1');

const url = `http://127.0.0.1:${httpPort}/?ws=ws://127.0.0.1:${wsPort}`;
console.log(`URL ${url}`);
console.log(`BOB ${bob.identity}`);
console.log(`BOBBUNDLE ${bob.bundle()}`);
process.on('SIGINT', async () => { bob.close(); await node.stop(); process.exit(0); });
process.on('SIGTERM', async () => { bob.close(); await node.stop(); process.exit(0); });
