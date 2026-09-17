# Changelog

## 0.1.0 — 2026-09-17

Initial release.

- `net`: TCP (Node) and WebSocket (Node + browser) transports, Bitcoin P2P codec,
  version/verack, peer pool with DNS seeds, gossip, backoff, IPv6 deprioritisation.
- `bus`: BLS12-381 keys/signatures, ECIES, PoW header + worker grinder, envelope,
  replay cache, `BusClient` for any message kind. Byte-exact with `naviod`.
- `usermsg`: `USER_DATA` frames, signed AuthFrames, seed-derived keyring with
  rotating prekey, `navid1…`/`navmsg1…` encodings, prekey discovery, outbox with
  signed batched acks and retry, chunking, reply-key ratchet, pub/sub,
  `MessagingClient`.
- `stores`: `MemoryStore`, `FileStore`, `IndexedDBStore`.
- Requires nodes with nav-io/navio-core #423, #461 and (for browsers) #462.
