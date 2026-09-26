# Fuzzy Message Detection

The mechanism that makes private offline delivery possible.

> **Status: verified 2026-09-22** against Beck, Len, Miers and Green, *Fuzzy
> Message Detection*, ePrint 2021/089, Figure 3 (FMD2). The algorithms below
> match the paper; only the group (BLS12-381 G1), the hash instantiations and
> the key derivation from a seed are ours. The security argument is the
> paper's, under DDH in the chosen group with `H` and `G` as random oracles.
> Two published variants were considered and rejected — see *Variants
> rejected* at the end.

## The problem it solves

A store needs something to filter on. The bus deliberately gives it nothing:
an envelope carries no recipient field, and the only way to learn who a
message is for is to hold the key and try to decrypt.

The naive fixes all fail:

| approach | why it fails |
|---|---|
| tag = `H(prekey ‖ epoch)` | prekeys are public and discoverable, so anyone who knows your address computes your tag — no anonymity against the attacker who matters |
| tag = `H(shared_secret ‖ epoch)` per contact | unlinkable, but the retrieving client must query one tag per contact, handing the node its contact count and a stable fingerprint |
| download everything | genuinely unlinkable, but bandwidth scales with total network volume, not with your inbox |
| single-server PIR | correct and far too expensive |

FMD gives the store a filter that produces **false positives at a rate the
retrieving client chooses**, and — the key property — an observer holding your
public clue key still **cannot test whether a given flag is yours**. Testing
requires a detection key, which only you can derive.

## Parameters

| symbol | value | notes |
|---|---|---|
| group | BLS12-381 G1 | already present: `blst` in navio-core, `@noble/curves` in the SDK |
| `g` | G1 generator | same generator the broadcast key uses |
| `γ` | 24 | maximum detection precision |
| clue key | 24 × 48 B = **1152 B** | distributed over the bus, not in the address string |
| detection key at precision `n` | `n` × 32 B | handed to the archive node per query |
| flag | 48 + 32 + 3 = **83 B** | per envelope |
| false-positive rate | `2^-n`, `n ≤ 24` | chosen by the retrieving client |

`γ = 24` is future-proofing: it costs 1152 B in the discovery response and
`γ + 2` group multiplications per send, and it caps how private retrieval can
ever get. At `2^-24`, even a bus carrying a million messages a day returns well
under one decoy per day; at `2^-8` it returns a few thousand, which is the
right setting for a desktop that wants a large anonymity set.

## Scheme

Let `H_bit(·) → {0,1}` and `H_scalar(·) → Z_q` be domain-separated SHA-256
based hashes with prefixes `navio-p2pmsg/fmd/v1/bit` and
`navio-p2pmsg/fmd/v1/scalar`.

### KeyGen

```
x_1 … x_γ  ←$ Z_q \ {0}        root detection secret
H_i = g^{x_i}                  i = 1 … γ
clue key  = (H_1 … H_γ)        1152 B, public
```

In the SDK the `x_i` are derived, not random, so they survive a restore from
mnemonic:

```
x_i = HKDF-SHA256(seed, salt = "navio-p2pmsg", info = "fmd/" ‖ u32le(epoch) ‖ u32le(i)) mod q
```

### Flag — sender, given the recipient's clue key

```
r ←$ Z_q \ {0}        u = g^r
z ←$ Z_q \ {0}        w = g^z
for i in 1…γ:  k_i = H_bit(u ‖ H_i^r ‖ w)
               c_i = k_i XOR 1                  // all bits encode 1 for the true recipient
m = H_scalar(u ‖ c_1…c_γ)
y = (z - m) · r^{-1}  mod q
flag = ( u:48 ‖ y:32 ‖ c:ceil(γ/8) )
```

Cost: `γ + 2` G1 multiplications ≈ 26. Tens of milliseconds in JS — negligible
beside a 23-bit proof of work.

`c` is serialised least-significant-bit-first, `c_1` in bit 0 of byte 0.

### Extract — recipient, choosing a precision

```
detection key at precision n  =  (x_1 … x_n),  n ≤ γ
```

Note the structure: a precision-`n` key tests only the first `n` bits, so it
matches with probability `2^-n` on a flag that is not yours. Handing out a
precision-`n` key does **not** let the holder derive precision `n+1`.

### Test — archive node, per flag

```
m = H_scalar(u ‖ c)
w = g^m · u^y
for i in 1…n:
    k_i = H_bit(u ‖ u^{x_i} ‖ w)
    if (c_i XOR k_i) != 1: return NO_MATCH
return MATCH
```

Cost: `n + 2` G1 multiplications per flag. At `n = 8` with `blst`, roughly
0.5–1 ms per flag; a 10 000-envelope window therefore costs a node on the order
of 5–10 seconds of CPU. That number is the reason archive queries are
PoW-stamped and hard-capped (`archive.md`), and it needs measuring on real
hardware before the caps are finalised.

### Correctness and the false-positive rate

For the true recipient every `k_i` is the same bit the sender computed, so
every `c_i XOR k_i` is 1 and the test always accepts. For anyone else each bit
matches with probability 1/2 independently, giving `2^-n`.

## Properties

**What an observer with your clue key learns from a flag: nothing.** Testing
requires `x_i`, and the clue key contains only `g^{x_i}`. This is the property
that a hash-based tag cannot provide and the reason FMD was chosen.

**What the archive node learns.** The set of envelopes matching your
precision-`n` key — your real messages plus `2^-n` of everything else — and the
fact that a connection asked for them. It does not learn which of the returned
envelopes are genuinely yours. Choosing `n` is choosing a point on the
bandwidth/anonymity curve, and the client owns that choice.

**Flags are unlinkable to each other.** `u` is fresh per message, so two flags
to the same recipient are independent.

**Flags cannot be replayed onto another message.** The PoW header binds the
flag (`wire-v2.md`).

**A detection key is long-lived.** Handing one to an archive node lets it test
*future* flags too. The SDK therefore rotates the FMD epoch alongside the inbox
prekey epoch, and `security.md` records the exposure.

## Clue key distribution

The clue key is 1152 B — too large for the `navid1…`/`navmsg1…` strings, which
stay as they are (decision 24). It travels in **bundle v2**, returned by the
existing discovery response (`_p2pmsg/prekeyreq` asks, addressed to the
target's identity key so the request names nobody on the wire):

```
u8      version = 2
u8[48]  identity_pub
u8[48]  prekey_pub
u8[96]  prekey_sig
u32     fmd_epoch
u8[1152] fmd_clue_key
u8[96]  fmd_sig           = Sign(identity_sk, fmd_epoch ‖ fmd_clue_key)
```

1440 B total — comfortably inside `MAX_USER_MSG_BYTES`. The bundle v1 layout
(192 B, no version byte) is still accepted on receive and distinguished by
length.

Senders MUST verify `prekey_sig` and `fmd_sig` under `identity_pub` before
using either key. An unverified clue key from a MITM means flagging your
messages to an attacker's detection key.

## Variants rejected

### Compact clue key (single point, γ derived)

A deployed variant compresses the clue key to a single point `X = g^x` and
derives the rest publicly:

```
x_i = x + H(X ‖ i)          X_i = X + g^{H(X ‖ i)}
```

48 bytes instead of 1152 — very attractive, and **unusable here**. `H(X ‖ i)`
is computable by anyone, so a detector given a precision-`n` key recovers the
root immediately:

```
x = x_1 - H(X ‖ 1)      →      every x_i, i ≤ γ
```

and can then test at full precision `2^-γ`, identifying your messages exactly.
Precision stops being something the client chooses and becomes something the
detector chooses.

That is tolerable when the detector is a service you picked and the adversary
is a network observer. Our adversary **is** the archive node (`security.md`),
so it is not tolerable here. We pay 1152 bytes, once per epoch, over an
already-encrypted discovery response, to keep precision enforced.

### IBE variant (paper §5.3)

The paper's own answer to large public keys replaces ElGamal with a
Boneh-Franklin IBE KEM (Appendix G). It shrinks the clue key by a factor of γ
*and* gives time-epoch detection keys that expire on their own — which would
directly address the "a detection key keeps working on future flags" exposure
in `security.md`. BLS12-381 is pairing-friendly and both `blst` and
`@noble/curves` expose pairings, so it is available to us.

Rejected on **Test cost**. Detection would need roughly `n` pairings per flag
instead of `n` G1 multiplications — order 1 ms versus 0.1 ms each — and the
results cannot be batched into a multi-pairing because each `k_i` is a separate
bit. A 10 000-envelope scan goes from seconds to minutes, which breaks the
archive query model in `archive.md`.

The limitation it would have solved is handled instead by rotating the account
epoch, which the paper also lists as the simple mitigation (§5.3).

## Module layout

```
src/fmd/
  keys.ts      derive(seed, epoch) -> { clueKey, root }, extract(root, n)
  flag.ts      flag(clueKey) -> Uint8Array(83)
  test.ts      test(detectionKey, flag) -> boolean
  index.ts     exported as navio-p2pmsg/fmd
```

The same three operations exist in navio-core PR C; `test` is the only one the
node needs, but `flag` is implemented there too so `sendp2pmsg` can flag.

## Checklist

- [ ] validate the construction against the paper, including hash inputs
- [ ] constant-time scalar handling; reject identity/off-subgroup `u`
- [ ] cross-implementation test vectors (TS ⇄ C++)
- [ ] benchmark `test` in `blst` to fix the archive caps
- [ ] property test: false-positive rate over 10^6 random flags matches `2^-n`
