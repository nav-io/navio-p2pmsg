# navio-p2pmsg

Standalone TypeScript SDK for Navio's **p2pmsg** encrypted broadcast bus.
Connects straight to Navio P2P nodes (TCP in Node, WebSocket in the browser).
No full node, no Electrum, no wallet. Application-agnostic: it gives any app
identity, addressing, end-to-end encryption, reliable 1:1 delivery and public
pub/sub on top of the bus. A chat app is one consumer; the library is not the
chat app.

Requires Navio nodes running nav-io/navio-core #474 (envelope v2 + fuzzy message
detection), #475 (envelope archive, for offline delivery) and, for browsers,
#462 (`-p2pwsbind`). #423 (user messaging) and #461 (`NODE_P2PMSG_LEAF`) are
already on master. **Envelope v2 is a wire break**: this SDK sends PoW header
version 2, which a node without #474 rejects outright. Until those are deployed
on mainnet, use regtest/testnet nodes built from those branches.

See `DESIGN.md` for the wire spec, the layer design and the C++ prerequisites
(`NODE_P2PMSG_LEAF` service bit, `-p2pwsbind` WebSocket listener).

`docs/` describes **v2**: the work that turns this from a messaging primitive
into a foundation for a fully featured private chat app — offline delivery via
fuzzy message detection and archive nodes, groups, multi-device, a double
ratchet, a chat schema with causal ordering, and a direct channel for
attachments and calls. Start at [docs/README.md](docs/README.md).

## Install

```bash
npm install navio-p2pmsg
```

Node >= 20. Browser builds need a bundler; the PoW worker is a separate entry
(`navio-p2pmsg/bus/pow-worker`) that you pass as `workerUrl`.

## Quick start

```ts
import { MessagingClient, FileStore, utf8, fromUtf8 } from 'navio-p2pmsg';

const client = await MessagingClient.create({
  network: 'mainnet',
  seed,                                  // 32 bytes you generated and backed up
  store: await FileStore.open('./state.json'),
  // peers: ['wss://node.example.org'],  // browser: WebSocket-enabled nodes
});

client.on('message', (m) => console.log(m.from, m.topic, fromUtf8(m.payload)));
client.on('ack', (a) => console.log('delivered', a.msgId));
await client.connect();

console.log(client.identity);            // navid1…  (share this)
console.log(client.bundle());            // navmsg1… (identity + prekey + sig)

await client.addContact('navmsg1…');     // or just a navid1…; prekey is discovered over the bus
await client.send('navid1…', utf8('hello'));

client.subscribe('news', (m) => console.log('news:', fromUtf8(m.payload)));
await client.publish('news', utf8('hello world'));

// Catch up on anything that arrived while this client was offline. Needs a
// connected peer advertising NODE_P2PMSG_ARCHIVE.
await client.syncArchive({ precision: 8 });
```

## What the library does for you

- **Identity**: stable BLS identity key + rotating inbox prekey, both derived
  from your seed. `navid1…` is the address; `navmsg1…` is the full bundle.
- **Discovery**: if you only know a `navid1…`, the prekey is fetched over the
  bus (anonymous request, signed response).
- **Encryption**: per-message ephemeral ECIES (BLS12-381 ECDH + HKDF +
  ChaCha20-Poly1305) exactly as `naviod` does it, with length-bucket padding.
- **Authentication**: every 1:1 message carries the sender's identity and a BLS
  signature bound to topic and recipient. Anonymous sends are possible.
- **Forward secrecy (lite)**: every message carries a fresh single-use reply
  key; replies ride it instead of the static prekey.
- **Reliable delivery**: signed batched acks; unacked messages are re-sent
  with backoff until acked or the TTL expires.
- **Offline delivery**: messages carry a fuzzy-detection flag, and an archiving
  node keeps the flagged envelopes it relays. `syncArchive()` retrieves what
  arrived while you were away. The flag puts **no recipient identifier** on the
  wire — holding someone's public clue key does not let you test whether a flag
  is theirs.
- **Chunking**: payloads above ~3.3 KB are split (default max 16 chunks).
- **Pub/sub**: public topics readable by every bus participant; reserved
  `_p2pmsg/*` topics carry discovery and acks.
- **PoW**: the bus's anti-spam stamp is ground in worker threads.

## Layers

| import | what |
|---|---|
| `navio-p2pmsg` | `MessagingClient` and everything below |
| `navio-p2pmsg/usermsg` | frames, keyring, bundle codecs, outbox, contacts |
| `navio-p2pmsg/bus` | `BusClient`, ECIES, PoW, BLS, envelope — raw access to any `kind` |
| `navio-p2pmsg/net` | `PeerPool`, `Peer`, TCP/WS transports, P2P codec |
| `navio-p2pmsg/stores` | `Store` interface, `MemoryStore`, `FileStore`, `IndexedDBStore` |
| `navio-p2pmsg/archive` | `ArchiveClient`, the `getp2pmsgs`/`p2pmsgs` codecs |

## Development

```bash
npm test          # unit tests
npm run test:int  # integration tests against a regtest naviod (see DESIGN.md)
npm run build
```

Example: `npx tsx examples/chat-cli.ts --network regtest --peer 127.0.0.1:18444`.

## License

MIT

## Browser smoke test

```bash
node browser-test/build.mjs          # esbuild bundle + PoW worker into browser-test/out
npx tsx browser-test/harness.ts      # regtest naviod with -p2pwsbind, a Node echo client, static server
# open the printed URL in a browser, then in the console: send('<BOB navid1…>', 'hi')
```
