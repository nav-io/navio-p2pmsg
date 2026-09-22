# Roadmap — v2

Decisions 1–20 are in `DESIGN.md` and describe v1. This table continues the
numbering. Each row is a settled decision from the v2 design interview
(2026-09-21); the rationale for the ones that were close calls is in the linked
document.

## Decisions

| # | Topic | Decision |
|---|-------|----------|
| 21 | Chat home | New `chat` layer in this repo (`navio-p2pmsg/chat`). `usermsg` stays the dumb authenticated transport. |
| 22 | Offline delivery | Fuzzy Message Detection flags + opt-in archive nodes. Chosen over a stable recipient tag because a tag is a linkable recipient identifier; chosen over download-everything because that does not scale to mobile. |
| 23 | Flag on the wire | Envelope v2: `u8 kind, PoWHeader pow, CompactSize flen, u8[flen] flag, EciesPacket enc`. PoWHeader v2 redefines `payload_hash = SHA256(enc.MsgHash() ‖ flag)`, so the flag is PoW-bound and the header stays exactly 98 bytes. |
| 24 | FMD parameters | FMD2 over BLS12-381 G1. γ = 24. Flag = 83 B. Clue key = 1152 B, distributed over the existing `_p2pmsg/prekey` discovery response (bundle v2), never inside the `navid`/`navmsg` strings. Retrieval precision chosen per query. |
| 25 | Archive access | Opt-in node role, service bit `NODE_P2PMSG_ARCHIVE = 1<<26`. Queries carry their own PoW stamp scaled to requested work, plus hard caps and ban scoring. Only envelopes with `flen > 0` are stored. |
| 26 | Link privacy | Implement BIP324 v2 transport in the SDK. A query hands the node a detection key; on-path observers must not get it. |
| 27 | Multi-device | Shared inbox prekey secret (one envelope reaches every device, no extra PoW) + per-device signing subkeys certified by the identity key. Revocation = rotate the account epoch. |
| 28 | Bulk transport | Direct client-to-client channel, signalled over the bus. Closes attachments, history backfill, typing and calls at once. |
| 29 | Stream tech | WebRTC in both runtimes. Browser: native. Node: `node-datachannel` as an **optional** peer dependency, falling back to bus-chunked transfer when absent. No STUN/TURN by default — the P2P `version` handshake already reports our reflexive address. |
| 30 | Groups | Sender-keys with epoch rotation. Envelope ECIES to a member-only group key so the topic never appears in cleartext. Group-wide FMD clue key so archive retrieval works for the whole group. |
| 31 | 1:1 forward secrecy | Double ratchet. Sending chains keyed by device id; receiver ratchet keypairs derived deterministically from the account secret so every device of the recipient derives the same receiving chain. |
| 32 | Ordering | Causal DAG: bounded parent hashes + Lamport counter. Message id = content hash. Gaps are detectable and therefore fetchable. |
| 33 | Encoding | Bitcoin serialisation (CompactSize, LE), versioned frames. One serialiser in the codebase, byte-exact testable, compact against a 3584 B ceiling. |
| 34 | Ephemeral signals | Typing and presence travel **only** over an open direct channel — no direct channel, no typing indicator. Read receipts are durable state and ride the bus, coalesced like delivery acks. |
| 35 | Push notifications | Out of SDK scope. Expose the clue key and archive cursor so an app-supplied always-on component can detect and wake a device. |
| 36 | Calls | 1:1 audio/video: signal over the bus, media over the WebRTC channel. Group calls deferred. |
| 37 | Abuse | Contact requests for unknown senders, local-only blocklist, optional per-identity PoW floor above the network minimum. |
| 38 | History | Chat state persists through the `Store` interface with explicit secondary indexes. **Ship a bundled full-text search index** rather than leaving search to the app. |
| 39 | Backup | BIP39 24-word mnemonic for the seed, plus a separate encrypted full-state export. Mnemonic alone restores identity and address, not history — stated plainly. |
| 40 | Payments | First-class chat message types backed by `navio-sdk` as an **optional** peer dependency. |
| 41 | Sequencing | Protocol-breaking changes first, while envelope v1 is still unreleased, so mainnet never sees it. |
| 42 | Packaging | One package. New subpaths `./chat`, `./stream`, `./fmd`, `./archive` beside the existing four. |

## Milestones

### M1 — wire (blocks everything)

**Status update (2026-09-22).** Two premises from the interview changed:
navio-core #423 (user messaging) and #461 (leaf bit) are **already merged to
master**; #462 (WebSocket listener) is not. No release tag contains them, so
the wire break is still free — but the window is "before a release ships
envelope v1", not "before #423 merges".

C++ side, both committed in the `navio-fmd` worktree:

- ✅ **PR C** `feat/p2pmsg-envelope-v2-fmd` — envelope v2 (`flen`/`flag`),
  PoWHeader v2 (`payload_hash = SHA256(MsgHash ‖ flag)`, still 98 bytes),
  `src/p2pmsg/fmd.{h,cpp}`, clue key in `getp2pmsginfo`,
  `getp2pmsgdetectionkey`, `cluekey` on `sendp2pmsg`. 16 unit tests, one
  functional test, doc.
- ✅ **PR D** `feat/p2pmsg-archive` — `NODE_P2PMSG_ARCHIVE` (1<<26),
  `src/p2pmsg/archive.{h,cpp}` LevelDB store, `getp2pmsgs`/`p2pmsgs`, query
  proof of work, caps, per-peer metering. 7 unit tests, one functional test
  running the real offline scenario, doc.

SDK side, done:

- ✅ `src/bus/fmd.ts` — keygen, flag, extract, test, clue-key codec.
- ✅ Envelope v2 codec, PoW v2 `payloadHash`, replay key over the flag.
- ✅ Bundle v2 over prekey discovery, so a contact's clue key is learned
  automatically; `send()` flags whenever one is known.
- ✅ `src/archive/` — stamp grinder, request/response codecs, `ArchiveClient`,
  per-peer cursor persistence, `MessagingClient.syncArchive()`.
- ✅ **Cross-implementation vectors both ways**: a flag made by the SDK tests
  true in navio-core and vice versa, and the seed→clue-key derivation and the
  query-stamp pricing are pinned on both sides.
- ✅ Exit criteria met: `src/archive/archive.int.test.ts` runs the full loop
  against a real archiving naviod — recipient offline, message flagged and
  archived, recipient returns and retrieves it.

Still open in M1:

- **BIP324 in the SDK is not started** (decision 26). Until it lands, an
  archive query hands the detection key to anyone on the path, so a client
  should only query a node it reaches over a trusted link.
- Confirm BIP324 works over the #462 WebSocket listener. `WebSocketSock` is a
  `Sock` and v2 transport detection is byte-stream based, so it is expected to
  work unchanged — expectation, not evidence, until a test proves it.

### M2 — chat layer

Chat frames, causal DAG, history store and indexes, search index, conversations,
profiles, contact requests, blocklist, read receipts, delivery state UI hooks.
Exit: two CLI clients hold a real conversation with replies, reactions, edits,
deletes and read state, surviving restart and out-of-order archive replay.

### M3 — groups

Group key schedule, epochs, membership operations, invites, roles, group FMD
key, group archive retrieval. Exit: a five-member group survives an add, a
remove and a rekey, with a removed member provably unable to read the next
epoch.

### M4 — multi-device

Account epochs, device certificates, QR + SAS pairing, device list publication,
revocation, state sync (contacts, group epochs, read state, sent-message
mirror). Exit: phone paired to desktop, both receive everything, revoking the
phone locks it out of the next epoch.

### M5 — stream layer

`StreamTransport`, bus signalling, WebRTC both runtimes, chunked encrypted file
transfer with resume, attachments in the chat schema, typing and presence,
new-device history backfill, bus-chunked fallback.

### M6 — product surface

Full-text search, BIP39 and encrypted export, payment message types over
`navio-sdk`, 1:1 calls.

## Dependency graph

```
M1 wire ──┬── M2 chat ──┬── M3 groups ──┐
          │             │               ├── M6
          └─────────────┴── M4 devices ─┤
                        └── M5 stream ──┘
```

M5 depends on M2 only for the attachment schema; the transport itself can be
built in parallel with M3/M4.

## Open items

- ~~FMD2 must be validated against the published scheme~~ — **done
  2026-09-22**, against ePrint 2021/089 Figure 3. The construction in `fmd.md`
  was correct. The compact single-point clue key used by some deployments was
  evaluated and rejected; `fmd.md` records why.
- Archive scan cost is linear in window × precision. The caps in `archive.md`
  are implemented as written but are still first estimates; they need
  measurement on real hardware before mainnet.
- Symmetric-NAT pairs have no direct path and no TURN. The bus-chunked fallback
  caps them at ~53 KB. Acceptable for v2; revisit if the failure rate is high.
- Bundled search means an index at rest. `security.md` records the exposure;
  encryption-at-rest for the index is not yet designed.
