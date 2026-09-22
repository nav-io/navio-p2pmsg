# Archive nodes

The retrieval side of offline delivery.

> **Implemented** in navio-core, branch `feat/p2pmsg-archive` (worktree
> `~/dev/navio-fmd`), 2026-09-22. This document now describes what was built;
> where the original design and the implementation diverged, the reason is
> noted inline. The SDK client is still to be written.

## Role

An archive node is an ordinary p2pmsg node that additionally persists the
envelopes it relays, so a client that was offline can come back and ask for
what it missed. It is opt-in, it holds only ciphertext, and it learns nothing
about who a stored envelope is for until someone presents a detection key.

It stores **only** envelopes that carry a detection flag (`flen > 0`) and whose
kind is `USER_DATA`. Nothing else is retrievable, so nothing else is worth the
disk.

```
-p2pmsgarchive=<0|1>          default 0
-p2pmsgarchiveexpiry=<days>   default 14, 0 = no age limit
-p2pmsgarchivesize=<MiB>      default 4096
-p2pmsgarchivepowbits=<n>     default = -p2pmsgpowbits, base cost of a query
```

Service bit `NODE_P2PMSG_ARCHIVE = (1 << 26)`, name `P2PMSG_ARCHIVE`, so a leaf
can find one through `addr` gossip the same way it finds `NODE_P2PMSG` peers
today. `getp2pmsginfo` gains `archive: {enabled, entries, bytes, oldest_id,
newest_id, retention_days}`.

## Store

LevelDB, mirroring the existing `UserInbox` structure so the code is familiar:

```
key   u64be id                     monotonic, never reused
value  u64 id
       i64 received_at
       u8  kind
       CompactSize flen, u8[flen] flag
       CompactSize elen, u8[elen] envelope     // the complete v2 envelope as relayed
```

Secondary index `received_at -> id` for expiry. Pruning is enforced on insert,
oldest first, by both caps. Ids increase monotonically for the life of the
store and never repeat, so a client that polls with `since_id` misses nothing
that was not pruned — the same contract `UserInbox` already offers.

## Protocol

Two net messages. **Names must be ≤ 12 bytes** — `COMMAND_SIZE` is 12 and a
longer name silently never matches on the wire. (navio-core already has this
bug: `getoutputdata` is 13 characters and therefore dead.) Both names below fit
with room to spare.

### `getp2pmsgs` (10 chars)

```
u8            version = 1
ArchiveStamp  stamp          u8 version, i64 timestamp, u256 query_hash, u64 nonce
u64           cursor         return entries with id > cursor
u16           limit          max entries, node caps it
u8            precision      n, 1 … 24
CompactSize n, u8[n]  detection_key    x_1 … x_n, so n = precision * 32
i64           not_before     0 = no lower bound on received_at
```

**Changed from the design.** The stamp is a dedicated `ArchiveStamp`, not a
`PoWHeader` with a reserved kind. `PoWHeader` carries a session ephemeral
*pubkey* and a payload kind, neither of which means anything for a query — and
the pubkey field cannot even hold a placeholder, because an all-zero G1 point
is not a valid compressed encoding and the deserializer rejects it. The stamp
is the same flat hashcash over the fields that actually exist.

`query_hash` = SHA256 over the query fields (everything but the stamp), so the
work is bound to the exact query. Every field is covered: a peer cannot pay for
a cheap scan and then ask for an expensive one.

### `p2pmsgs` (7 chars)

```
u8          version = 1
u64         next_cursor    highest id SCANNED, not highest returned
u8          complete       1 = window fully scanned, 0 = node stopped at its cap
CompactSize count
count × {
  u64         id
  i64         received_at
  CompactSize elen, u8[elen] envelope
}
```

`next_cursor` is the highest id scanned, not the highest returned. A client
that advances its cursor to `next_cursor` will not re-scan ground already
covered even when nothing matched. `complete = 0` tells the client to issue
another query from `next_cursor` rather than assume it is caught up — the
distinction between "you have everything" and "I stopped early" must never be
ambiguous, or clients silently lose messages.

Responses are also bounded by a byte cap; a node truncates on whichever limit
binds first and sets `complete = 0`.

## Cost and abuse

A scan costs `(window size) × (precision + 2)` G1 multiplications. That is
linear in exactly the two numbers the client picks, which is why the client
pays for both.

**Query PoW.** The request carries its own stamp. Required difficulty, as
implemented in `ArchiveStampBits()`:

```
units = max(limit,1) × max(precision,1)
bits  = base_bits + (number of halvings to bring units down to 400), capped at +8
```

A small cheap query (100 entries, precision 4 → 400 units) costs the base; the
largest allowed one costs 256× more work. The client buys node CPU with its own
CPU, the same bargain the bus already strikes for relay. The stamp is verified
against the **capped** limit, so a requester that asks for more than the node
serves pays for what it gets, not for what is discarded.

**Hard caps**, enforced regardless of the stamp:

| cap | default |
|---|---|
| `limit` | 500 entries |
| response bytes | 2 MiB |
| entries scanned per query | 50 000 |
| queries per peer, burst | 3 |
| queries per peer per minute | 6 |

**Changed from the design.** Rate-limit violations are **not** ban-scored: the
query is dropped silently. A client syncing a long window legitimately issues
back-to-back queries and should back off, not be disconnected. Malformed
queries and insufficient work are still ban-scored, because those are cheap to
detect and costly to emit.

**Privacy of the query.** The detection key is the one secret in the exchange
and it must not reach an on-path observer, which is why the SDK implements
BIP324 (decision 26, `wire-v2.md`). A client SHOULD refuse to send a detection
key over a v1 link unless the application explicitly allows it.

## Client behaviour

`navio-p2pmsg/archive`:

```ts
const archive = client.archive;            // undefined if no archive peer
archive.precision = 8;                     // 2^-8 false positives
await archive.sync();                      // resume from the persisted cursor
archive.on('progress', ({ scanned, matched, complete }) => {});
```

- Cursor is persisted per archive peer, in the `archive` namespace of the
  `Store`. Different peers have different id spaces.
- Query at least two archive peers when available; an archive node that omits
  results is indistinguishable from one with nothing to send, and the only
  defence is asking someone else.
- Retrieved envelopes go through the ordinary inbound path — PoW check,
  timestamp check, replay cache, trial decrypt — with the timestamp window
  relaxed, since an archived envelope is by definition old. Everything above
  the bus therefore treats an archived message identically to a live one; the
  causal DAG (`chat.md`) puts it back in the right place.
- Decoys fail to decrypt and are dropped silently. They are not an error
  condition and must not be logged per-message.
- Precision defaults: 8 on desktop, 12 on mobile, configurable. Document that
  raising it shrinks the anonymity set.

## Checklist

- [x] PR D: service bit, store, both net messages, query PoW, caps, RPC fields
- [x] functional test: offline client retrieves, decoys included, caps enforced
- [x] regtest end-to-end: send while recipient offline → recipient retrieves
      (`test/functional/p2pmsg_archive.py`)
- [x] SDK `./archive`: cursor persistence, multi-peer, relaxed timestamp window
- [x] SDK end-to-end against a real archiving naviod
      (`src/archive/archive.int.test.ts`)
- [ ] benchmark `FmdTest` to fix the caps in this document on real hardware
- [ ] BIP324, so the detection key is not exposed on the path

Note the node deliberately never *sends* `getp2pmsgs`: retrieval belongs to the
client holding the detection key, and a full node already stores its own
messages in the local inbox. The SDK is the intended consumer.
