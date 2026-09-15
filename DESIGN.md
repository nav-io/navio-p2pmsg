# navio-p2pmsg — design

Standalone TypeScript SDK that speaks the Navio **p2pmsg** encrypted broadcast
bus directly over the Navio P2P network. No full node, no Electrum. The
library is **application-agnostic**: it gives a chat app (or any other app)
identity, addressing, encryption, delivery and pub/sub primitives, but is not
itself a chat app.

Protocol reference: `navio-core` PR #423 (`feat/p2pmsg-user-messaging`),
`doc/p2p-encrypted-messaging.md`, `src/p2pmsg/*`.

## Decisions (interview 2026-09-16)

| # | Topic | Decision |
|---|-------|----------|
| 1 | Protocol target | `navio-usermsg` semantics: `USER_DATA = 7`, topic-framed, node-side inbox store. |
| 2 | Runtime | Node **and** browser. Pluggable transport. |
| 3 | Browser path | Native WebSocket listener in `naviod` (C++ PR), not a proxy. |
| 4 | WS payload | Same Bitcoin P2P framing as TCP; WS is a byte stream. One codec. |
| 5 | Leaf model | New service bit `NODE_P2PMSG_LEAF` (1<<25): node fluffs to leaf, never picks it as stem successor. Leaf relays nothing. |
| 6 | Offline delivery | Not in v1. Sender outbox re-broadcasts with backoff until signed ack or TTL. |
| 7 | User ID | Identity pubkey (48 B). Prekey discovered over bus; full bundle string accepted as fallback input. |
| 8 | Library scope | Layers: `net`, `bus`, `usermsg`. Discovery + acks are reserved `_p2pmsg/*` topics defined by the library. App body is opaque. |
| 9 | Sender auth | Authenticated inner frame inside ciphertext, BLS sig by identity key over (topic, recipient, msg fields). Optional anonymous mode. |
| 10 | Crypto backend | Pure JS: `@noble/curves` bls12-381, `@noble/ciphers`, `@noble/hashes`. |
| 11 | PoW | Grind in worker (worker_threads / Web Worker), midstate optimisation, pluggable hasher. |
| 12 | Peer discovery | Node: DNS seed w/ service-bit filter + addr gossip. Browser: built-in `wss://` list, overridable. Target 3 peers. |
| 13 | Forward secrecy | Reply-key ratchet-lite: every frame carries fresh single-use `reply_pub`; next message to that sender encrypts to it. Fallback prekey. |
| 14 | Persistence | `Store` interface; ship `MemoryStore`, `FileStore` (Node), `IndexedDBStore` (browser). `exportState/importState` on top. Keys derived from a 32-byte app-supplied seed. |
| 15 | Groups | Public topics + symmetric-encrypt helper only. Group membership/key mgmt = app. |
| 16 | Oversize | Transparent chunking, `maxChunks` default 16, per-chunk ack. |
| 17 | Package | Single npm package `navio-p2pmsg`, subpath exports. tsup ESM+CJS, vitest, TS strict, Node >= 20, MIT. |
| 18 | Sequencing | SDK + C++ in parallel. |
| 19 | WS listener | `-p2pwsbind=<addr:port>`, no TLS in naviod (reverse-proxy for wss), minimal RFC 6455 server wrapped as `Sock`. |
| 20 | PRs | Two PRs on nav-io/navio-core, both based on master: `feat/p2pmsg-leaf-bit`, `feat/p2p-websocket-listener`. |

Routine defaults: leaf sends stem (`dp2pmsg`) to one random peer by default;
clock = median offset from peers' `version` timestamps; `msg_id` = 16 random
bytes; acks signed, batched over ~2 s; inner frames Bitcoin-serialised with a
leading version byte; UA `/navio-p2pmsg:x.y.z/`, services `NODE_P2PMSG_LEAF`,
`relay=false`, height 0; replay cache = bounded LRU of 64k entries.

## Wire facts (must match navio-core byte for byte)

All integers little-endian, Bitcoin serialisation (`CompactSize` for vectors).

### Network

| chain | magic | port |
|-------|-------|------|
| mainnet | `bd 5f c3 00` | 48470 |
| testnet | `24 67 d2 c1` | 33670 |
| regtest | `fd bf 9f fb` | 18444 |

Protocol version 70016. Net message types `p2pmsg` (fluff) and `dp2pmsg`
(stem). Service bits: `NODE_P2PMSG = 1<<24`, `NODE_P2PMSG_LEAF = 1<<25` (new).
Envelope (whole payload of the net message) must be <= 4096 bytes
(`MAX_JOB_BYTES`) with no trailing bytes.

### Envelope

```
u8          kind
PoWHeader   pow
EciesPacket enc
```

PoWHeader (98 bytes, fixed):

```
u8   version = 1
i64  timestamp        unix seconds
u8   kind             must equal envelope kind
u8[48] session_eph    = enc.eph
u8[32] payload_hash   = enc.MsgHash()
u64  nonce
```

`PoWHeader.Hash()` = single SHA256 over those 98 bytes. Accept iff
`UintToArith256(hash) <= (2^256-1) >> bits` — note `UintToArith256` reads the
32-byte hash as a **little-endian** integer, so the leading zero bits are in
the **last** bytes of the digest. `bits` = 23 on mainnet/testnet, 8 on regtest
by default (`-p2pmsgpowbits`). Timestamp must be within ±120 s of receiver's
clock.

EciesPacket:

```
u8[48]      eph          compressed G1
CompactSize len, u8[len] ciphertext
u8[16]      tag
```

`MsgHash()` = SHA256(serialised packet) = SHA256(eph || compactsize(len) || ciphertext || tag).
Replay key = SHA256(u8 kind || MsgHash).

### ECIES

- eph_sk = random non-zero Fr scalar; eph = G1 * eph_sk.
- shared = recipient_pub * eph_sk, compressed to 48 bytes.
- key = HKDF-SHA256(ikm = shared, salt = `"navio-p2pmsg-ecies-v1"`, info = `"aead-key"`, L = 32).
- AEAD = ChaCha20-Poly1305 (RFC 8439), nonce = 12 zero bytes, AAD = `[kind]` (1 byte).
- Plaintext framing before encryption: `u32le len || payload || zero pad` to bucket size in `{64, 256, 1024, 3072, 3584}`; if `4 + len > 3584` no padding.
- Decrypt rejects eph = infinity or off-curve/off-subgroup.
- Broadcast key: private scalar = 1, public = G1 generator. Anyone can decrypt.

### BLS keys and signatures

- Public keys: G1 compressed, 48 bytes. Secret: Fr scalar, 32 bytes big-endian.
- Signature: G2 compressed, 96 bytes. Scheme = `sig = sk * H2(pk || msg)`, DST
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (message augmentation with the
  48-byte pk prepended, POP DST). Matches `blsct::PrivateKey::Sign`.
- Prekey bundle: `identity_pub(48) || prekey_pub(48) || prekey_sig(96)`,
  `prekey_sig = Sign(identity_sk, prekey_pub bytes)`.

### USER_DATA frame (kind 7), node-parsed

```
CompactSize tlen, u8[tlen] topic      1..64 bytes
CompactSize blen, u8[blen] body       opaque to node
```

Serialised frame <= 3584 bytes. Delivery scopes on the node: INBOX (encrypted to
inbox prekey), SESSION (encrypted to a minted reply key), BROADCAST (encrypted to
broadcast key, stored only for subscribed topics).

## Layers

```
src/
  net/        transport interface, TcpTransport (Node), WsTransport (Node+browser),
              codec (header/checksum), handshake, PeerPool, discovery, clock offset
  bus/        serialize (CompactSize, structs), bls (keys/sig), ecies, pow (+ worker),
              envelope, replay cache, BusClient { send(kind, to, body, {stem}), on(kind) }
  usermsg/    UserMsgFrame, inner AuthFrame, Keyring (seed -> identity/prekeys), Bundle
              (encode/decode/verify, bech32m text), Contacts, Discovery, Outbox/acks,
              Chunker, PubSub, MessagingClient (public API)
  stores/     Store interface, MemoryStore, FileStore, IndexedDBStore
  index.ts    re-exports; subpath exports ./net ./bus ./usermsg ./stores
```

### `net`

```ts
interface Transport {
  connect(): Promise<void>; close(): void;
  send(bytes: Uint8Array): void;
  onData(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: (err?: Error) => void): void;
}
```

`TcpTransport` uses `node:net`. `WsTransport` uses global `WebSocket` (browser)
or `ws` (Node), binary frames, byte-stream semantics. Everything above the
transport is `Uint8Array` only, no `Buffer`.

`Peer` wraps a transport: Bitcoin message codec (24-byte header: magic, 12-byte
command, u32 length, 4-byte checksum = first 4 bytes of double-SHA256),
`version`/`verack` handshake, `ping`/`pong`, `sendaddrv2`/`addrv2` and `addr`
parsing, `getaddr`. Ignores everything else. Advertises `NODE_P2PMSG_LEAF`,
`relay = false`, `start_height = 0`. Records peer's `version.timestamp` for
clock offset.

`PeerPool`: keeps `targetPeers` (default 3) alive, reconnect with backoff,
seeds from `peers` option, DNS seed (Node only, `x2000000.seed.nav.io`
style filter for the leaf-capable bit is NOT available, so we filter on
`NODE_P2PMSG` in gossiped `addr` service bits), and gossip. Emits `p2pmsg`
/ `dp2pmsg` payloads upward with the originating peer id.

### `bus`

`BusClient` owns: replay cache, PoW grinder, `Keyring`-independent key
registry (inbox prekeys + grace, broadcast key, session keys with TTL),
per-kind handlers. Inbound: parse envelope, check PoW/timestamp/replay, trial
decrypt against inbox keys → broadcast key → session keys, dispatch
`{kind, recipient: 'inbox'|'broadcast'|'session', sessionKey?, senderEph, body}`.
Outbound: `send(kind, recipientPub, body, {stem = true})` → encrypt, grind PoW
in worker, push `dp2pmsg` to one random peer (or `p2pmsg` to all).

### `usermsg`

Inner **AuthFrame** (body of USER_DATA frame), version 1:

```
u8     version = 1
u8     flags     bit0 SIGNED, bit1 HAS_REPLY_KEY, bit2 CHUNK
u8[16] msg_id
i64    timestamp
[SIGNED]        u8[48] sender_identity
[HAS_REPLY_KEY] u8[48] reply_pub
[CHUNK]         u16 chunk_idx, u16 chunk_total
CompactSize n, u8[n] payload
[SIGNED]        u8[96] sig
```

`sig = Sign(identity_sk, SHA256("navio-p2pmsg/usermsg/v1" || CompactSize(topic) || topic || recipient_identity(48, zeros for broadcast) || frame bytes up to and including payload))`.

Reserved topics (library-owned, apps must not use the `_p2pmsg/` prefix):

- `_p2pmsg/prekey/<hex(SHA256(identity_pub))>` — discovery **request**, BROADCAST
  scope, unsigned, `HAS_REPLY_KEY`, empty payload. Requester identity is not revealed.
- `_p2pmsg/prekey` — discovery **response**, SESSION scope to the request's
  `reply_pub`, signed, payload = 192-byte bundle.
- `_p2pmsg/ack` — signed, 1:1 (to the message's `reply_pub`, else to the
  sender's known prekey), payload = `CompactSize n, n × (u8[16] msg_id, u16 chunk_idx)`;
  `chunk_idx = 0xFFFF` means whole message.

Delivery: `Outbox` persists `{msg_id, chunks, recipient, next_at, attempts, expires_at}`.
Backoff 30 s → 60 s → 120 s … cap 10 min, TTL default 24 h. Each re-send is a
new PoW with a fresh timestamp (same msg_id, same reply_pub). Events:
`sent`, `acked`, `expired`.

Reply keys: on send, mint `reply_pub`, register as session key (TTL 7 d, one
live key per contact, replaced on next send). On receive with `reply_pub`,
store as contact's `nextKey`; use it once for the next send, then fall back to
prekey. Acks use the same rule.

Keyring: `identity_sk = HKDF(seed, salt="navio-p2pmsg", info="identity")`,
`prekey_sk(n) = HKDF(seed, salt="navio-p2pmsg", info="prekey/" + n)`; `n`
persisted. `rotatePrekey()` bumps `n`, keeps previous key in grace for 7 d.

Text encodings: identity = bech32m HRP `navid` (48 bytes); bundle = bech32m
HRP `navmsg` (192 bytes, length limit lifted). Hex accepted too.

Public API:

```ts
const client = await MessagingClient.create({
  network: 'mainnet' | 'testnet' | 'regtest',
  seed: Uint8Array,            // 32 bytes, app-owned
  store?: Store,               // default MemoryStore
  peers?: string[],            // 'host:port' or 'ws(s)://...'
  targetPeers?: number,        // 3
  powWorkers?: number,
});
client.identity: string;        // navid1...
client.bundle(): string;        // navmsg1...
await client.connect(); client.close();
client.on('message', (m: { msgId, from?: string, topic, payload, scope }) => {});
client.on('ack' | 'expired' | 'peer' | 'error', ...)
await client.send(to: string, payload: Uint8Array, { topic?, ttl?, sign? }): Promise<msgId>;
client.subscribe(topic, handler); client.unsubscribe(topic);
await client.publish(topic, payload, { sign? });
await client.rotatePrekey();
client.exportState(): Uint8Array; MessagingClient.importState(...)
```

Lower layers exported for apps that want raw bus access:
`new BusClient(pool, keys)`, `bus.send(kind, pub, body)`, `bus.on(kind, h)`.

## C++ work (nav-io/navio-core, base master)

### PR A — `feat/p2pmsg-leaf-bit`

- `protocol.h`: `NODE_P2PMSG_LEAF = (1 << 25)`; `protocol.cpp` name `P2PMSG_LEAF`.
- `init.cpp` forward(): split `eligible` into `fluff_eligible` (P2PMSG or LEAF)
  and `stem_eligible` (P2PMSG only). Leaf peers get fluff copies, never stem.
- `getp2pmsginfo`: add `leaf_peers` count.
- Functional test `p2pmsg_leaf.py`: P2PInterface advertising LEAF receives
  `p2pmsg` fluff of a node-originated message and is never chosen as stem
  successor (node with only a leaf peer fluffs).
- Doc paragraph in `doc/p2p-encrypted-messaging.md`.

### PR B — `feat/p2p-websocket-listener`

- `-p2pwsbind=<addr:port>` (repeatable), default off. Listens with a
  `ListenSocket` flagged websocket.
- `WebSocketSock : public Sock` (new files `src/util/sock_ws.{h,cpp}` or
  `src/net_ws.{h,cpp}`): performs the HTTP/1.1 upgrade handshake on first
  bytes (`Sec-WebSocket-Accept` = base64(SHA1(key + GUID)), uses
  `crypto/sha1.h`), then `Recv()` returns unframed payload bytes from binary
  frames (client→server frames must be masked; handle ping/pong/close; reject
  text frames, extensions, fragments > 4 MiB), `Send()` wraps in unmasked
  binary frames. Byte-stream semantics: framing boundaries carry no meaning.
- Accepted WS connections are ordinary `ConnectionType::INBOUND`, counted
  against `-maxconnections`, same DoS/ban rules. V1 transport only.
- No TLS. Doc: front with nginx/caddy for `wss://`.
- Functional test `p2p_websocket.py`: hand-rolled WS client framing over
  `socket` in the test (no new python deps), completes version handshake and
  receives a `p2pmsg` fluff.

Integration worktree: `/Users/alex/dev/navio-p2pmsg-int` = #423 + A + B, built
to `build/bin/naviod`, used by the SDK's regtest tests
(`-regtest -p2pmsg=1 -p2pmsgpowbits=8 -p2pwsbind=127.0.0.1:<port>`).
