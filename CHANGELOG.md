# Changelog

## Unreleased

- docs: Navio Core v0.2.2 is released and carries everything 0.2.x needs, so
  the README and the 0.2.0 notes now point at that release instead of at
  unmerged navio-core PRs, and list the node options some features depend on
  (`-p2pwsbind`, `-p2pmsgarchive`, `-v2transport=1`).

## 0.2.0 — 2026-09-27

**Breaking, at the wire.** Envelopes are v2 — a detection flag bound into the
proof of work — and the SDK routes only to peers advertising
`NODE_P2PMSG_V2`. That bit ships in Navio Core v0.2.2 (nav-io/navio-core
#474), so against older nodes this release does not work: it connects, drops
every peer as unable to relay this format, and sends nothing. That is deliberate. A
v1 node charges 10 discouragement points for an envelope it cannot parse, so a
client that kept sending would be disconnected after ten messages and banned on
a real network. Stay on 0.1.x for v0.2.1 nodes.

### Offline delivery

- `bus/fmd`: fuzzy message detection (FMD2, ePrint 2021/089 Fig. 3) over
  BLS12-381 G1. A flag is untestable without a detection key, so an envelope
  names no recipient and an archive can hold mail for someone without learning
  who.
- `archive`: retrieval from nodes advertising `NODE_P2PMSG_ARCHIVE`, with a
  per-peer and **per-detection-key** cursor, query proof of work bound to a
  per-connection challenge, and a refusal to send a detection key over a
  plaintext link.

### Chat, groups, devices

- `chat`: causal DAG ordering with gap detection, replies, edits, reactions,
  deletes, read receipts, profiles, contact requests, blocking, search, and
  attachments by reference.
- `chat/group`: one epoch secret derives the group's ECIES key, clue key and
  content key, so one envelope and one proof of work serve the whole group.
  Hash-chained membership, rekey on removal, ownership transfer, key-in-link
  and request-to-join invites.
- `devices`: pairing with a short authentication string, per-device signing
  keys, signed device lists, revocation that rotates every derived key, sent
  message mirroring, history backfill a new device verifies for itself, and
  state sync for contacts, groups and read state.
- `backup`: BIP39 seed phrases and encrypted state export under a passphrase.
- `stream`: direct-channel transport seam, resumable content-addressed file
  transfer with per-file keys, typing and presence, and an offer/answer codec.
  The WebRTC backend is **not** included.

### Transport

- `net/bip324`: BIP324 v2 transport, **on by default** now, opportunistic with
  a per-address fallback. An archive query over a v1 link is refused rather
  than degraded.

### Privacy fixes worth naming

- A discovery request used to ride a **broadcast** on a topic derived from the
  target's identity. Broadcast envelopes are encrypted to a published key, and
  an identity is a public address, so anyone holding an address could
  precompute the topic and watch the bus — a live "somebody is about to contact
  this account" oracle. Requests now go to the target's identity key, so the
  topic is inside the ciphertext.
- The detection key no longer crosses a plaintext link.
- A message and its ack no longer sit at a constant delay apart.
- `security.md` records what remains visible, measured: the traffic-class
  fingerprint table, the chunk-count size leak, and that a group detection key
  selects the whole group rather than one member's mail.

### Denial of service

- A chunk total is no longer believed. The wire allows 65535; reserving space
  for the claim turned 256 envelopes into 130 MiB of heap for ten minutes.
  Chunks are held sparsely and an implausible total is refused before anything
  is allocated.
- Every network-facing parser is swept against truncation, trailing bytes and
  random input.

### Requires

Navio Core v0.2.2 or later, which ships all of it: envelope v2 + FMD and the
archive (#474, with #475), the WebSocket listener (#462, enable with
`-p2pwsbind` for browsers), user messaging (#423) and the leaf bit (#461).
Archive sync also needs the node to run `-v2transport=1`.


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
