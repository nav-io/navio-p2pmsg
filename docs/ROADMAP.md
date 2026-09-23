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

- ✅ **BIP324** (decision 26) — `src/net/bip324/`. ElligatorSwift over
  secp256k1 (the interview note saying X25519 was wrong), the two rekeying
  ciphers, key derivation, framing, message ids and the handshake. Verified
  against the BIP's own vectors and against a live naviod, which reports the
  link as `transport_protocol_type: "v2"`. Opt in with
  `transportVersion: 'v2'`.

Still open in M1:

- **Turn v2 on by default.** It is opt-in because a v1 responder answers a v2
  opening by hanging up rather than negotiating, so every v1 peer costs a
  wasted dial and a redial. `PeerPool` handles that and remembers the result
  per address, but flipping the default should wait until enough of the
  network runs v2.
- Confirm BIP324 works over the #462 WebSocket listener. `WebSocketSock` is a
  `Sock` and v2 transport detection is byte-stream based, so it is expected to
  work unchanged — expectation, not evidence, until a test proves it.

### M2 — chat layer (in progress)

Done, in `src/chat/`:

- ✅ `frame.ts` — versioned chat frames, Bitcoin-serialised, content-addressed
  ids, and the text / edit / delete / reaction / receipt / profile / contact
  bodies. Deterministic 1:1 conversation ids, so neither side negotiates.
- ✅ `dag.ts` — parent hashes + Lamport, deterministic topological order, head
  tracking, and **gap detection**: a cited parent we do not hold is reported,
  which is what lets a client tell "nothing was said" from "something was
  lost".
- ✅ `store.ts` — persistence over the existing `Store` with prefix-scan
  indexes, plus resolution of edits, deletes and reactions into a render-ready
  view. Edits and deletes are honoured only from the original author.
- ✅ `client.ts` — `ChatClient`: send, reply, edit, delete, react, read state,
  contact requests, and a local-only blocklist that is never published.

- ✅ Read receipts applied by **causal ancestry**, surfaced as `readBy`: a
  receipt names only the heads a reader had seen, so reading a later message
  implies everything before it.
- ✅ Bundled full-text search (decision 38), Unicode-aware, prefix match on the
  last term, and a deleted message leaves the index — an index that still
  matched removed text would leak exactly what the user deleted.
- ✅ Profiles exchanged on change and automatically on accepting a request.

Still open in M2:

- Typing and presence — they belong on the direct channel (decision 34), so
  they wait for M5.
- The exit criterion below is met by the in-process tests but not yet by two
  real CLI clients across a restart.

Exit: two CLI clients hold a real conversation with replies, reactions, edits,
deletes and read state, surviving restart and out-of-order archive replay.

### M3 — groups (core done)

Done, in `src/chat/group/`:

- ✅ `schedule.ts` — one epoch secret derives the group ECIES key (so ONE
  envelope and ONE proof of work serve the whole group), the group FMD clue key
  (so group messages are archivable and any member can catch up), and a content
  key that goes stale for a removed member who recorded ciphertext.
- ✅ `state.ts` — membership, roles and a **hash chain**: a state that does not
  chain to the one we hold is rejected and surfaced, which is what makes an
  admin showing two different histories detectable rather than silent.
- ✅ `ops.ts` — add / remove / leave / promote / rename, with the rekey policy.
  Removal always rekeys; without that, removal would mean nothing.
- ✅ `invite.ts` — `navinv1…`, both key-in-link and request-to-join, with the
  difference between them documented rather than smoothed over.
- ✅ `ChatClient` integration: create, send, membership ops, key distribution
  1:1 over the ratchet, and re-registration of group keys on restart.

Exit criterion met by test: a group survives an add, a remove and a rekey, and
the removed member provably cannot read the next message.

Still open in M3:

- Group archive retrieval across a rekey boundary (querying with the detection
  keys of several epochs).
- Ownership transfer, and admitting a request-to-join invite.
- Divergent-history conflicts are surfaced as an error; there is no UI-level
  resolution path yet.

### M4 — multi-device (foundation done)

Done, in `src/devices/`:

- ✅ `hierarchy.ts` — the account-epoch key schedule. `account_secret(e)` is
  derived from the seed and shared with every device, so one envelope reaches
  all of them and a sender never pays for the recipient's device count. Only
  the primary holds the seed, so only it can derive `e+1` — which is what makes
  revocation mean anything. Also the deterministic receiving ratchet keys,
  needed so a message decrypts on every device rather than just the one that
  happened to advance the chain.
- ✅ `list.ts` — the signed device list. Both the list signature and each
  device certificate are checked: a valid list signature must not be able to
  smuggle in a device the identity never admitted.
- ✅ `pairing.ts` — `navpair1…` offers, the single-use pairing topic derived
  from a hash of the offer key, the short authentication string both screens
  show, and the announce/grant bodies. The grant never carries the root seed.
- ✅ `Keyring` now derives the inbox prekey and the FMD key through the account
  secret, and `rotateAccountEpoch()` is the revocation primitive.

**Breaking derivation change.** A given seed now produces a different inbox
prekey and clue key than it did before, because both go through the account
secret. Nothing is deployed on mainnet, so this is free now and would not have
been later.

- ✅ **Per-device message signing.** `AuthFrame` gains `FLAG_DEVICE_SIGNED`
  and a device public key; the signature verifies under that key, and whether
  the device belongs to the account is decided separately against the sender's
  published device list. A revoked device still produces a valid signature —
  it is simply no longer listed, which is the whole mechanism.
- ✅ **Device list distribution.** Bundle v3 carries the signed list, so a
  receiver has it before the first device-signed message rather than after. v1
  and v2 bundles still parse, degrading to "no device list".
- ✅ `MessagingClient` takes a `device` option and signs with the device key.

- ✅ **`Keyring.forDevice`.** A secondary is built from what a grant carries —
  the account secret for one epoch and the identity PUBLIC key — and nothing
  else. It shares the account's address and inbox key, so one envelope reaches
  both devices, and it signs with its device key. `Keyring.identity.sk` is now
  optional in the type, so the compiler finds every operation that needs the
  seed; those throw with a plain message rather than producing a signature
  nobody can verify. A secondary does not answer prekey discovery, because it
  cannot sign a bundle and an unsigned one would be worse than silence.

- ✅ **The live pairing exchange.** `startPairing()` on the primary returns a
  `navpair1…` offer; `requestPairing()` on the joining device answers on a
  topic derived from a hash of the single-use offer key and returns the short
  authentication string; `confirmPairing()` signs the device into the account,
  publishes the updated device list and sends the grant. Nothing is granted
  until a human confirms the two strings match — ECDH alone proves nothing
  about who is on the other end.

Still open in M4:
- ✅ **Revocation.** `revokeDevice()` rotates the account epoch, republishes
  the device list without the device, and hands the new secret to every device
  that remains — each reachable at its own device key, which is the only key it
  still holds once the shared inbox key has moved. A peer refuses a device list
  whose `accountEpoch` goes backwards, so replaying the list from before a
  revocation cannot re-admit the device.
- ✅ **Group rekey on revocation.** The account epoch moving no longer leaves
  group secrets stale: every group we administer rotates automatically, and
  groups we only belong to are reported through `groupsNeedRekey` so the user
  can ask an admin rather than assume the revocation was complete.
- ✅ **Sent-message mirror, through the chat layer.** An outgoing message is
  encrypted to the recipient, so our other devices cannot read it; without a
  mirror a paired phone shows half of every conversation. Copies are batched —
  the second envelope costs a second proof of work — and an account with one
  device sends none at all. `ChatClient` ingests them as its own messages,
  membership frames included, which is also how a second device learns about a
  group: the frame carrying a group's state and epoch secret goes to the
  group's members, and our own devices are not among them.
- ✅ **Reply keys suspended on a multi-device account.** A one-shot reply key
  lives in one device's memory, so publishing it told the contact to send
  where our other devices could not read. An account with more than one device
  keeps the conversation on the account prekey instead, at the cost of that
  session's forward secrecy, until the ratchet lands.
- ✅ **Device state sync** (`src/stream/statesync.ts`). Contacts, group states
  with their epoch secrets, and read state move device to device over the same
  direct channel history uses, and every item is checked on arrival: a bundle
  by its own signature, a group state against the chain we hold, read state by
  union. The known list and the blocklist are deliberately not carried — a set
  with no tombstones can only be unioned, and a union would resurrect a removed
  contact or forget an unblock.
- ✅ **Announcing a new device.** A contact holding the device list from before
  a device existed rejects everything it signs, so `confirmPairing`
  republishes the bundle to contacts, and a frame naming an unknown device
  triggers a rate-limited re-discovery as the fallback.
- ✅ **Closing the window after a revoke.** Two parts. The bus inbox key now
  moves with the keyring, which it did not: revocation republished a prekey
  the bus had never been told about, so the account went deaf to every sender
  that discovered the new bundle. And `revokeDevice(pub, { notifyContacts:
  true })` pushes the new bundle to every contact rather than waiting to be
  asked — the only lever there is, since the revoked device keeps its own copy
  of the previous inbox secret and nothing local takes that away.

### M5 — stream layer (core done, WebRTC backend pending)

Done, in `src/stream/`:

- ✅ `transport.ts` — the `StreamTransport` / `StreamSession` / `StreamChannel`
  seam, plus a loopback pair that delivers **asynchronously**, so code relying
  on synchronous delivery fails in tests rather than over a socket.
- ✅ `file.ts` — resumable, content-addressed transfer with per-file
  encryption. The key travels in the chat message, never with the bytes, so the
  ciphertext is safe to move over any carrier.
- ✅ `ephemeral.ts` — typing and presence, direct channel only and coalesced.
- ✅ `signal.ts` — offer/answer/candidate codec, carried on ordinary chat
  frames so an offer survives the peer being offline.
- ✅ Attachments in the chat layer, with an honest ~50 KB ceiling when there is
  no direct channel.

Still open in M5:

- **The WebRTC backend.** Written and then removed: with no browser and no
  signalling partner available here it could only have been a class whose
  behaviour is to throw, and an untested implementation behind a confident API
  is worse than an absent one. The interface and the signal codec are the seam
  it plugs into.
- ✅ **History backfill** (`src/stream/backfill.ts`). A newly paired device
  asks another device of the account for a conversation over a direct channel
  and verifies every frame that carries a signature, rather than trusting the
  device that sent it. Our own sent messages and anything stored before the
  signed frame was kept have no proof to check; the result says how many were
  taken on trust, and an entry whose proof is present and wrong is dropped.
- Calls.

### M6 — product surface (done except calls)

- ✅ Full-text search (M2).
- ✅ BIP39 seed phrases and encrypted state export, under a passphrase rather
  than the seed so the two backups fail independently.
- ✅ Payment message types; the wallet stays an application concern, which is
  the reason this package has no chain dependency.
- Calls remain, and depend on the WebRTC backend.

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
