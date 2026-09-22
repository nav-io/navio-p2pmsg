# Gap analysis: v1 vs a fully featured private chat app

v1 gives an application identity, addressing, end-to-end encryption, reliable
1:1 delivery and public pub/sub. That is a messaging *primitive*. A chat
product people actually live in needs considerably more, and several of the
gaps are not things an application can paper over — they are missing from the
protocol.

This document is the justification for everything in `ROADMAP.md`. Each gap
states the constraint that causes it, so a future reader can re-open a decision
if the constraint changes.

## 1. Offline delivery — the load-bearing gap

**v1 behaviour.** Sender re-broadcasts with backoff until a signed ack or the
24 h TTL expires. If the recipient is never online during that window, the
message is lost.

**Why the obvious fix does not work.** navio-core already has a node-side
`UserInbox` (LevelDB, `-p2pmsgstoresize`, `-p2pmsgstoreexpiry`, drained by
`listp2pmsgs`). It is useless to us: it stores only messages the *node itself*
decrypted with its *own* prekey. A leaf client's messages are opaque to the
node, so they are never stored.

**Why it is hard to fix privately.** The bus deliberately carries no recipient
field. An envelope is `kind ‖ PoWHeader ‖ EciesPacket`; the only way to learn
who a message is for is to hold the key and try. That is an excellent privacy
property and it is exactly what makes a mailbox hard: a store has nothing to
index on. Any naive fix — a recipient tag, a discovery key, a per-user queue —
reintroduces a linkable recipient identifier on the wire and hands a third
party the social graph.

**Decision.** Fuzzy Message Detection (`fmd.md`) plus an opt-in archive node
role (`archive.md`). FMD gives the store something to filter on *without*
giving anyone the ability to test an arbitrary identity, and the false-positive
rate is chosen by the retrieving client, not by the server.

## 2. Multi-device

**v1 behaviour.** One seed, one identity, one device. There is no device
concept at all.

**Why it matters beyond convenience.** Multi-device is also a delivery
mechanism: a desktop that is always on is a mailbox you fully control, with no
third party involved. It is the strongest available answer to gap 1 for users
who have a second device.

**Constraint.** Mainnet PoW is 23 bits per envelope. Encrypting a separate copy
per device — the standard approach — multiplies the sender's work by the
recipient's device count. Unacceptable on this bus.

**Decision.** Shared inbox key so a single envelope reaches every device at zero
extra cost, per-device signing subkeys for attribution and revocation
(`devices.md`).

## 3. Groups

**v1 behaviour.** "Groups are the application's problem." The SDK offers public
topics and nothing else.

**Trap.** The obvious implementation — a public topic with a symmetric group
key — leaks more than it looks like. BROADCAST scope encrypts the envelope to
the generator point, so *anyone* on the bus can decrypt the ECIES layer and
read the `topic` field of the USER_DATA frame. The content stays secret; the
group's existence, its identifier and its complete activity timeline do not.

**Decision.** Groups ECIES to a member-only group key, which the bus's existing
session-key trial-decrypt already supports, so the topic is never visible
(`groups.md`).

## 4. Message semantics

**v1 behaviour.** A message is an opaque payload with a `msg_id` and a delivery
ack. There is no reply, no reaction, no edit, no delete, no mention, no read
state, no typing, no presence, no attachment, no profile.

**Why the SDK should own the schema.** Two applications built on v1 cannot talk
to each other, because "what is a reply" is undefined. A chat protocol is a
schema as much as it is a transport.

**Decision.** A versioned chat frame, Bitcoin-serialised for consistency with
every other frame in the repo, with a causal DAG for ordering (`chat.md`).

## 5. Ordering and consistency

**v1 behaviour.** None. Messages are delivered as they arrive.

**Why v2 forces the issue.** Archive delivery replays history out of order.
Multi-device means your own messages arrive from several sources. Groups mean
concurrent senders. Reactions and edits target a message that may not have
arrived yet. Sorting by a sender-claimed timestamp fails all four.

**Decision.** Parent hashes plus a Lamport counter, message id = content hash
(`chat.md`). Gaps become detectable, which is what makes resync possible at
all.

## 6. Forward secrecy and post-compromise security

**v1 behaviour.** Fresh ephemeral per message (good) against a static recipient
prekey per epoch, softened by a one-shot reply key. Compromising a prekey
secret decrypts everything in that epoch. There is no recovery after a
compromise.

**Decision.** Full double ratchet, made multi-device-safe by keying sending
chains to a device id and deriving the receiver's ratchet keys deterministically
from the shared account secret (`ratchet.md`).

## 7. Bulk data

**v1 behaviour.** 3584 B per frame, 16 chunks, PoW per envelope. Ceiling is
roughly 53 KB and it costs 16 proofs of work.

**Consequence.** No images, no files, no voice notes, no new-device history
backfill, no calls. Four separate product holes with one cause.

**Decision.** A direct client-to-client channel, signalled over the bus
(`stream.md`). One mechanism closes all four.

## 8. Abuse

**v1 behaviour.** Anyone who learns your `navid1…` can message you. PoW is the
only gate, and PoW is cheap for a motivated spammer and expensive for a phone.

**Decision.** Contact requests, a local (never published) blocklist, and an
optional per-identity difficulty floor for strangers (`chat.md`).

## 9. Operational essentials

Backup is a raw hex state blob. There is no mnemonic, no profile, no search, no
push path for a sleeping mobile device. Individually small, collectively the
difference between a library and a product. See `ROADMAP.md` decisions 35, 38,
39.

## Explicitly out of scope

- **Group calls.** A mesh works to roughly five participants; beyond that needs
  an SFU, which is a server, which the architecture rejects. Revisit later.
- **A hosted push service.** The SDK exposes the detection primitive so an
  always-on component can wake a device. Running that component is not the
  SDK's job.
- **Full-node or wallet functionality.** The reason this package exists is that
  it needs neither. Payments integrate through `navio-sdk` as an optional peer
  dependency, never a hard one.
