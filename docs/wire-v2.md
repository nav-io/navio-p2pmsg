# Wire v2

> **Implemented in navio-core** on branch `feat/p2pmsg-envelope-v2-fmd`
> (worktree `~/dev/navio-fmd`), 2026-09-22, exactly as specified below. The SDK
> side is still to be written. BIP324 (decision 26) is **not** started.

Changes to the bus wire format. Everything here must match navio-core byte for
byte; v1 wire facts in `DESIGN.md` remain accurate except where superseded
below.

## Why the wire has to break

`ParseEnvelope` (`src/p2pmsg/transport.cpp:39`) rejects trailing bytes:

```cpp
if (!ss.empty()) return false;
```

So there is no backward-compatible place to put a detection flag. Any addition
is a relay-breaking change — a node running v1 will reject and not relay a v2
envelope. Since PR #423 is not merged and nothing is deployed on mainnet, the
change is free now and permanently expensive later. This is the reason
milestone M1 comes first (decision 41).

## Envelope v2

```
u8           kind
PoWHeader    pow           // version 2, still exactly 98 bytes
CompactSize  flen          // 0 = no detection flag
u8[flen]     flag          // FMD flag, 83 bytes when present (γ = 24)
EciesPacket  enc
```

Total envelope stays bounded by `MAX_JOB_BYTES = 4096`. With an 83-byte flag
the practical ceiling on `MAX_USER_MSG_BYTES` is unchanged at 3584: the fixed
overhead grows from ~170 B to ~256 B and the headroom absorbs it.

`flen` rules:

- `flen == 0` for kinds that are never retrieved from an archive (`PING`,
  `PONG`, `AGG_ANN`, `CANDIDATE_TX`, `RFQ_REQ`, `RFQ_QUOTE`, `ORDER_ANN`).
  Nodes MUST accept a flag on any kind — relay stays kind-blind — but archive
  nodes only store `USER_DATA`.
- `flen == 83` for a γ = 24 FMD2 flag. Other lengths are reserved; a node
  relays them unchanged and an archive node stores them but cannot test them,
  so it treats them as non-matching.
- A flag is never required. A sender who does not care about offline delivery
  omits it, and the envelope is then indistinguishable from v1 apart from the
  PoW version byte.

## PoWHeader v2

The header is unchanged in size and field layout:

```
u8      version        = 2
i64     timestamp      unix seconds
u8      kind           must equal envelope kind
u8[48]  session_eph    = enc.eph
u8[32]  payload_hash   see below
u64     nonce
```

Only the meaning of `payload_hash` changes:

| version | payload_hash |
|---|---|
| 1 | `enc.MsgHash()` |
| 2 | `SHA256(enc.MsgHash() ‖ flag)` — with `flag` the raw `flen` bytes, empty when `flen == 0` |

Consequences, all deliberate:

- The header stays 98 bytes, so the grinder's midstate optimisation, the target
  comparison and every existing test vector survive untouched.
- The flag is covered by the proof of work. A relay cannot strip the flag to
  silently deny offline delivery, nor rewrite it into a third party's detection
  bucket, without redoing the work.
- `flen == 0` under version 2 gives `SHA256(MsgHash ‖ "")`, which is *not*
  equal to the v1 `payload_hash`. Versions are therefore cleanly separable and
  a v1 header can never be replayed as v2.

Acceptance is otherwise as in v1: `UintToArith256(SHA256(header))` read
little-endian must be `<= (2^256-1) >> bits`, timestamp within ±120 s.

## Replay cache

Replay key becomes `SHA256(u8 kind ‖ payload_hash)` — that is, it now covers
the flag. Two envelopes with identical ciphertext but different flags are
distinct messages and both relay. This is intentional: it lets a sender
re-flag a retransmission for a recipient whose clue key changed. It is also a
small amplification surface, bounded by the fact that each variant costs a
fresh proof of work.

## Query PoW

Archive queries reuse `PoWHeader` with:

- `kind = 0xFE` (reserved, never a valid envelope kind)
- `session_eph` = 48 zero bytes
- `payload_hash` = SHA256 over the serialised request with `nonce` zeroed
- `bits` = archive node's advertised base bits, scaled by requested work

See `archive.md` for the scaling rule.

## BIP324

The SDK currently implements v1 transport only. Decision 26 adds BIP324 v2
transport to `net`:

- ElligatorSwift-encoded **secp256k1** x-only ECDH (not X25519, as an earlier
  draft of this document said), garbage and garbage terminators, packet-level
  ChaCha20-Poly1305 with the BIP324 session keys, short message id table.
- Advertise `NODE_P2P_V2`; navio-core already gates this behind `-v2transport`
  (`src/init.cpp:999`).
- Opportunistic: try v2, fall back to v1 on failure, and allow the application
  to require v2.

WebSocket transport is expected to carry v2 unchanged. PR #462 wraps the
connection as a `Sock`, and v2 detection operates on the byte stream, so
nothing above the socket knows the difference. **This is expectation, not
evidence** — M1 includes a test that proves it.

## Implementation checklist

navio-core (done):

- [x] `src/p2pmsg/transport.h`: envelope `flen`/`flag`, `ExpectedPayloadHash()`
- [x] `src/p2pmsg/pow.{h,cpp}`: version constants, `PayloadHash()`
- [x] `OnWire`: v1 rejected, flag size bounded, replay key covers the flag
- [x] `Transport::Send`: optional flag, v2 stamp

SDK:

- [x] `src/bus/envelope.ts`: encode/decode `flen`/`flag`, `expectedPayloadHash`
- [x] `src/bus/pow.ts`: v2 `payloadHash`, version constants, v1 rejected
- [x] the grinder needed no change — the header is still 98 bytes and the flag
      is folded into `payloadHash` before grinding starts
- [x] replay key is now `SHA256(kind ‖ payloadHash)`, covering the flag
- [x] shared test vectors with navio-core, both directions
- [x] `src/net/bip324/`: ElligatorSwift (map, inverse map, ECDH), FSChaCha20 and
      FSChaCha20Poly1305, key derivation, packet framing, message-id table and
      the handshake state machine
- [x] verified against the BIP's own vectors (ellswift decode, `xswiftec_inv`,
      packet encoding through several rekeys) and against a live naviod
- [x] `Peer`/`PeerPool` integration with a v1 redial, opt-in via
      `transportVersion`
