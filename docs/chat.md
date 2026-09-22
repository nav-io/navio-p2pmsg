# Chat layer

`navio-p2pmsg/chat`. Decision 21: it lives in this repo, above `usermsg`, which
stays the dumb authenticated transport. Nothing below this layer knows what a
reply is.

## Why the SDK owns the schema

Two applications built on v1 cannot interoperate, because "what is a reply" is
undefined. A chat protocol is a schema as much as it is a transport. The schema
is versioned so it can grow.

## Chat frame

Carried as the AuthFrame payload, Bitcoin-serialised (decision 33), on topic
`c/<hex8(conv_id)>`.

```
u8          version = 1
u8          type
u8[32]      conv_id
i64         timestamp        sender clock, display hint only
u64         lamport
CompactSize np, np × u8[32]  parents        // bounded, see below
CompactSize bl, u8[bl]       body           // type-specific
```

**Message id** = `SHA256("navio-p2pmsg/chat/v1" ‖ frame bytes)`. Content
addressed, so edits and reactions target something immutable, dedupe is free,
and the same message arriving from the bus, from the archive and from a device
mirror collapses to one entry.

### Types

| # | type | body |
|---|---|---|
| 1 | `TEXT` | text, mentions, attachment refs, reply target |
| 2 | `EDIT` | `u8[32] target`, new text |
| 3 | `DELETE` | `u8[32] target` |
| 4 | `REACTION` | `u8[32] target`, emoji, `u8` add/remove |
| 5 | `RECEIPT` | read-up-to heads |
| 6 | `PROFILE` | display name, avatar ref, status |
| 7 | `MEMBERSHIP` | group operations (`groups.md`) |
| 8 | `CONTACT` | contact request / accept / decline |
| 9 | `PAYMENT` | request / sent (`navio-sdk`) |
| 10 | `CALL` | call signalling (`stream.md`) |
| 11 | `STREAM` | direct-channel signalling (`stream.md`) |
| 12 | `EPHEMERAL` | typing, presence — **direct channel only, never the bus** |

`TEXT` body:

```
CompactSize len, u8[len]     text (UTF-8)
CompactSize n, n × u8[48]    mentions (identity keys)
CompactSize n, n × AttachRef
u8          has_reply
[has_reply] u8[32]           reply_to
```

`AttachRef`:

```
u8[32]      content_hash
u64         size
CompactSize len, u8[len]     mime
u8[32]      key                 // per-file symmetric key
CompactSize len, u8[len]     thumbnail      // ≤ 1 KB, inline, optional
```

The thumbnail rides the bus so a preview renders before the file transfers; the
file itself goes over the direct channel (`stream.md`).

An unknown `type` is **stored and ignored**, not dropped. A newer peer's
feature must survive a round trip through an older client, or history diverges
between versions.

## Conversation ids

- 1:1: `SHA256("navio-p2pmsg/conv/1to1/v1" ‖ min(id_a, id_b) ‖ max(id_a, id_b))`
  over the two identity keys, byte-compared. Both sides derive it independently
  with no negotiation.
- Group: the random 32-byte `group_id`.
- Self (notes to self, device mirror): `SHA256("…/conv/self/v1" ‖ identity)`.

## Ordering — the causal DAG

Decision 32. Each frame cites the ids of the messages its sender had seen — the
current **heads** of its view — plus a Lamport counter one greater than the
highest it has seen.

```
parents: up to 4 heads, oldest dropped first
lamport: max(seen) + 1
```

Why this and not timestamps:

- **Gaps become detectable.** A cited parent you do not hold is a message you
  missed. Without this you never know, and "never know" is how P2P chat quietly
  loses history.
- **Edits, reactions and deletes are unambiguous**, because they target a
  content hash rather than a position.
- **Concurrency is legible.** Two people typing at once is a fork, not a
  conflict, and it renders as a fork.
- **Dedupe is free.**
- **Clock skew and lying clocks cannot reorder history.** `timestamp` is a
  display hint, never a sort key on its own.

Display order: topological sort, ties broken by `lamport`, then `timestamp`,
then `msg_id` bytes. Deterministic across devices — two devices showing the
same conversation in different orders is a bug users notice immediately.

**Gap repair.** A missing parent is requested, in order of cheapness: the
direct channel if one is open, then the archive, then a group member. A gap
that cannot be repaired is surfaced to the application as a visible break in
the conversation. Silence is not an option — the user must be able to tell the
difference between "nothing was said" and "something was lost".

Parents are capped at 4 to bound frame size; `lamport` preserves the ordering
information the dropped parents would have carried.

## Edits, deletes, reactions

- **Edit**: valid only from the original author's account; the chat store keeps
  the edit chain and renders the latest, with history available.
- **Delete**: a tombstone. It removes content locally and asks peers to do the
  same. It is a request, not an erasure — anyone who received the message could
  have kept it. The API and the documentation say so plainly rather than
  implying a guarantee the protocol cannot make.
- **Reaction**: last write per `(reactor, target, emoji)` wins, by Lamport
  order.

## Receipts

- **Delivered** is the existing `_p2pmsg/ack` — already implemented, unchanged.
- **Read** is a `RECEIPT` frame naming read-up-to heads. Durable state, so it
  rides the bus (decision 34), coalesced with the same ~2 s batching as acks,
  and mirrored to your own devices.
- **Typing and presence** are `EPHEMERAL` frames that travel **only** over an
  open direct channel. No direct channel, no typing indicator. A typing
  indicator that costs 23 bits of proof of work and updates every 30 seconds is
  worse than none.

## Contact requests

Decision 37. Anyone who learns your `navid1…` can send to you, and PoW is a
weak gate — cheap for a spammer with hardware, expensive for a phone.

- A first message from an unknown identity lands in a **request queue**, not
  the inbox. The application surfaces the sender identity and a short intro
  payload, nothing more.
- **Accept** promotes to contact and establishes the ratchet session.
  **Decline** drops it. **Block** adds to a local blocklist.
- The blocklist is **never published** and never signalled, so blocking is
  invisible to the person blocked.
- Anonymous (unsigned) senders always land in requests.
- Optional per-identity PoW floor above the network minimum for strangers,
  advertised in bundle v2. Contacts send at the network minimum.

## Profiles

A `PROFILE` frame: display name, avatar (an `AttachRef`), status text. Sent to
contacts on change and on request; never broadcast. There is no directory and
no global namespace — the address is the identity key, and a display name is
something a contact chose to tell you. Applications should show the identity
alongside the name where impersonation matters.

## History, storage and search

Decision 38. State persists through the existing `Store` interface, with
explicit secondary indexes:

```
chat/msg/<conv_id>/<lamport>/<msg_id>     message frames
chat/head/<conv_id>                        current heads
chat/conv/<conv_id>                        metadata, unread count, last read
chat/gap/<conv_id>/<msg_id>                known-missing parents
chat/contact/<identity>                    contact and request state
chat/group/<group_id>                      group state and epoch secrets
chat/search/<term>/<msg_id>                inverted index
```

The current `Store` is `get/put/delete/list(prefix)` — workable for this
layout, since every index is a sorted key prefix, but crude. An optional richer
interface (ranges, compound keys, transactions) should be added for backends
that can do better (IndexedDB, LevelDB, SQLite), falling back to prefix scans
otherwise.

**Search ships with the SDK** (decision 38): a bundled inverted index over
message text, updated on insert, with Unicode-aware tokenisation, prefix
matching and per-conversation filters. The alternative — decrypt and scan at
query time — is unusable past a few thousand messages.

The index is plaintext-derived and sits at rest next to the encrypted store. A
disk-level attacker who can read the index learns which words appear in your
conversations even if message bodies are separately encrypted. This is a real
exposure, it is recorded in `security.md`, and encryption-at-rest for the index
is an open item.

## Public API sketch

```ts
import { ChatClient } from 'navio-p2pmsg/chat';

const chat = await ChatClient.create({ client, store });

chat.on('message', (m) => {});     // new or repaired, already ordered
chat.on('update',  (m) => {});     // edit, delete, reaction, receipt
chat.on('gap',     (g) => {});     // detected, repair attempted or failed
chat.on('request', (r) => {});     // unknown sender

const conv = await chat.conversation(identityOrGroupId);
await conv.send('hello', { replyTo, mentions, attachments });
await conv.react(msgId, '👍');
await conv.edit(msgId, 'hello!');
await conv.delete(msgId);
await conv.markRead(msgId);
conv.typing();                     // no-op without a direct channel

for await (const m of conv.history({ before, limit })) {}
for await (const m of chat.search('invoice', { conv })) {}
```

## Module layout

```
src/chat/
  frame.ts       chat frame codec, message id
  dag.ts         parents, lamport, topological sort, gap detection
  store.ts       indexes, cursors, conversation state
  search.ts      tokeniser, inverted index, query
  contacts.ts    requests, blocklist, PoW floor
  profile.ts     profile frames
  group/         see groups.md
  client.ts      ChatClient
```

## Checklist

- [ ] frame codec + content-hash ids, round-trip and vector tests
- [ ] DAG: insert, sort determinism across devices, gap detection and repair
- [ ] unknown-type frames stored and ignored, not dropped
- [ ] edit/delete/reaction resolution rules
- [ ] read receipts, coalesced and mirrored
- [ ] contact requests, blocklist, per-identity PoW floor
- [ ] search index, incremental update, deletion on tombstone
- [ ] test: out-of-order archive replay of 1 000 messages converges to the same order
