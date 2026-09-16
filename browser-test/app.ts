/** Browser smoke test page script: MessagingClient over ws:// with IndexedDB persistence and PoW in a Web Worker. */
import { MessagingClient, IndexedDBStore, utf8, fromUtf8, toHex } from '../src/index.js';

declare global {
  interface Window {
    p2p: { client?: MessagingClient; log: string[]; received: Array<{ from?: string; text: string; scope: string }>; acks: number; ready: boolean; error?: string };
  }
}

const state = (window.p2p = { log: [], received: [], acks: 0, ready: false });
const out = document.getElementById('log')!;
function log(s: string) {
  state.log.push(s);
  out.textContent += s + '\n';
  console.log('[p2p]', s);
}

async function main() {
  const params = new URLSearchParams(location.search);
  const ws = params.get('ws')!;
  const seedHex = params.get('seed') ?? '11'.repeat(32);
  const seed = new Uint8Array(seedHex.match(/../g)!.map((h) => parseInt(h, 16)));
  const store = await IndexedDBStore.open(params.get('db') ?? 'navio-p2pmsg-browser-test');
  const client = await MessagingClient.create({
    network: 'regtest',
    seed,
    store,
    peers: [ws],
    targetPeers: 1,
    dnsSeeds: [],
    powBits: Number(params.get('powbits') ?? 8),
    powWorkers: Number(params.get('workers') ?? 2),
    ackDelayMs: 100,
    retryTickMs: 2000,
  });
  state.client = client;
  client.on('peer', (p) => log(`peer connected ${p.address}`));
  client.on('peerclose', (p) => log(`peer closed ${p.address}`));
  client.on('error', (e) => log(`error ${e.message}`));
  client.on('message', (m) => {
    const text = fromUtf8(m.payload);
    state.received.push({ from: m.from, text, scope: m.scope });
    log(`message from=${m.from ?? 'anon'} scope=${m.scope} topic=${m.topic}: ${text}`);
  });
  client.on('ack', (a) => {
    state.acks++;
    log(`ack ${toHex(a.msgId)} from ${a.to}`);
  });
  client.on('contact', (c) => log(`learned bundle ${c.identity}`));
  await client.connect();
  (document.getElementById('id') as HTMLElement).textContent = client.identity;
  log(`identity ${client.identity}`);
  log(`bundle ${client.bundle()}`);
  state.ready = true;
}

(window as unknown as { send: (to: string, text: string) => Promise<string> }).send = async (to, text) => {
  const id = await state.client!.send(to, utf8(text));
  log(`sent ${toHex(id)} to ${to}`);
  return toHex(id);
};

main().catch((e) => {
  state.error = String(e?.stack ?? e);
  log(`FATAL ${state.error}`);
});
