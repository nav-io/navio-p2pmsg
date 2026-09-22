# Session setup and the double ratchet

Replaces the v1 "reply-key ratchet-lite" (decision 13) for 1:1 conversations.
Groups use a different scheme (`groups.md`).

## What v1 gives and what it misses

v1 already encrypts every message to a fresh ephemeral key, so compromising a
*sender* yields nothing retroactively. The weakness is on the receiving side:
messages are encrypted to a static inbox prekey that lives for a whole epoch.
Compromise that secret and every message in the epoch opens. The one-shot reply
key narrows this to a single message for replies, but there is no recovery — an
attacker who reads your state once reads everything afterwards.

A double ratchet fixes both: each message key is deleted after use (forward
secrecy) and a fresh DH each round heals the session after a compromise
(post-compromise security).

## The multi-device problem

A textbook double ratchet assumes one endpoint per side. Decision 27 gives
every device of an account the *same* inbox secret, so two devices sending to
the same contact would advance the same sending chain independently and diverge
immediately.

The resolution splits the two directions:

- **Sending chains are per device.** Each device keeps its own ratchet keypair
  and its own sending chain, identified on the wire by an 8-byte `device_id`.
  A recipient keeps one receiving chain per `(contact, device_id)` pair. Your
  contact's phone and desktop are simply two chains under one identity.
- **Receiving ratchet keys are derived, not random.** The recipient's ratchet
  keypairs come deterministically from the account secret:

  ```
  ratchet_sk(epoch, j) = HKDF(account_secret_e, salt="navio-p2pmsg",
                              info="ratchet/" ‖ u32le(j)) mod q
  ```

  Every device of the recipient derives the same `j`-th keypair, so every
  device can advance the same receiving chain and decrypt the same message.
  `j` is carried in the message header so a device that is behind can catch up.

This costs the receiver-side DH ratchet its randomness — the sequence of
receiving keys is fixed for an account epoch — but it stays secret, it rotates
with the account epoch, and it is the price of one envelope reaching N devices.
`security.md` records the trade.

## Session establishment

X3DH shaped, over the keys that already exist, all DH being
`DH(a, B) = compress(B · a)` in G1.

Published in bundle v2 (`fmd.md`) plus a batch of one-time prekeys:

| key | lifetime |
|---|---|
| `IK` identity | permanent, is the address |
| `SPK` signed prekey (= the existing inbox prekey) | account epoch |
| `OPK_i` one-time prekeys | single use, batch of 100, replenished |
| `FMD` clue key | account epoch |

Initiator with ephemeral `EK`:

```
DH1 = DH(IK_a, SPK_b)
DH2 = DH(EK_a, IK_b)
DH3 = DH(EK_a, SPK_b)
DH4 = DH(EK_a, OPK_b)          omitted if no one-time prekey was available
SK  = HKDF(DH1‖DH2‖DH3‖DH4, salt="navio-p2pmsg", info="x3dh/v1")
```

The initial message carries `IK_a`, `EK_a` and the `OPK` id in the AuthFrame,
which is already inside the ECIES layer and already signed.

Omitting `DH4` costs replay protection on the first message; the chat layer's
content-hash dedupe (`chat.md`) absorbs a replayed first message, and the
responder rate-limits sessions opened without an `OPK`.

One-time prekeys are served by the existing `_p2pmsg/prekey` discovery
response, which pops one per request. A requester that asks repeatedly to
exhaust the batch is rate-limited per epoch; exhaustion degrades to the
no-`OPK` path rather than failing.

## Message header

Carried in the AuthFrame, inside the ECIES layer — so it is already hidden from
anyone but the recipient's account, and no separate header encryption is
needed:

```
u8      version = 1
u8[8]   device_id        sender's device
u8[48]  ratchet_pub      sender's current ratchet public key
u32     j                index of the RECIPIENT ratchet key this targets
u32     pn               messages in the previous sending chain
u32     n                index in the current sending chain
```

## Chains

Standard: a root chain advanced by each DH ratchet step, and symmetric sending
and receiving chains advanced per message.

```
root, ck_send    = HKDF(root, DH(ratchet_sk, peer_ratchet_pub), info="ratchet/root")
mk, ck           = HKDF(ck, info="ratchet/chain")
```

AEAD is ChaCha20-Poly1305 with `mk`, matching the bus.

## Skipped keys — not optional here

Archive retrieval delivers messages out of order by construction: a client
syncs a two-week window and receives `n = 40` before `n = 12`. Skipped message
keys must therefore be stored, not merely tolerated.

| bound | default |
|---|---|
| skipped keys per chain | 2 000 |
| skipped keys total | 50 000 |
| retention | 30 days |
| max chains per contact | 8 devices |

Exceeding a bound drops the oldest skipped keys; those messages become
permanently undecryptable and are surfaced to the application as a gap rather
than silently vanishing. The causal DAG makes the gap visible.

## Interaction with the rest of v2

- **Archive.** A retrieved message decrypts through the same path; only the
  timestamp window is relaxed.
- **Multi-device.** Sending devices are independent. A newly paired device
  starts a fresh sending chain; it does not need any peer's ratchet state.
- **Revocation.** Rotating the account epoch changes `account_secret_e` and
  therefore every derived receiving ratchet key, so a revoked device cannot
  follow the session forward. Peers learn the new epoch from bundle v2.
- **Groups.** Not used. Group content keys come from the epoch schedule in
  `groups.md`; the ratchet carries the *distribution* of those secrets, 1:1.

## Module layout

```
src/usermsg/ratchet/
  x3dh.ts        session establishment
  chain.ts       root/sending/receiving chain KDFs
  session.ts     per-(contact, device) state, skipped-key store
  header.ts      header codec
```

## Checklist

- [ ] one-time prekey batch, publication, replenishment, exhaustion policy
- [ ] deterministic receiver ratchet derivation, shared across devices
- [ ] per-device sending chains, chain-per-(contact, device)
- [ ] skipped-key store with the bounds above, persisted through `Store`
- [ ] out-of-order test: deliver 1 000 messages in reverse, all decrypt
- [ ] compromise test: leak state at message k, prove message k+2 (post-DH) is safe
