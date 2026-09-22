# Multi-device

Decision 27. Also the strongest offline-delivery answer available to anyone who
owns two devices: a desktop that is always on is a mailbox with no third party
in it.

## Constraint that shapes everything

Mainnet PoW is 23 bits per envelope. Encrypting one copy per device — what
Signal does — multiplies the *sender's* work by the recipient's device count.
A sender should not pay more because the recipient bought a tablet. So a single
envelope must reach every device, which means every device must hold the same
inbox secret.

## Key hierarchy

```
BIP39 mnemonic (24 words)
        │
     root seed (32 B)                          PRIMARY DEVICE ONLY
        ├── identity_sk          = HKDF(seed, info="identity")
        └── account_secret_e     = HKDF(seed, info="account/" ‖ u32le(e))
                 │                              shared with every active device
                 ├── inbox prekey_sk            what senders encrypt to
                 ├── fmd root (x_1 … x_γ)       offline retrieval
                 └── ratchet_sk(e, j)           deterministic receiving keys

device_sk                                       per device, random, never leaves it
device_cert = Sign(identity_sk, device_id ‖ device_pub ‖ created_at ‖ caps)
```

Two invariants:

1. **The root seed never leaves the primary device.** A secondary holds
   `account_secret_e` for the current epoch and the epochs it has been given —
   never the seed, and never a way to derive epoch `e+1`.
2. **Only the primary can rotate the account epoch**, because rotation needs
   the seed. Revocation therefore requires the primary. If the primary itself
   is lost, recovery is from the mnemonic, which produces a new primary that
   can rotate.

`device_id` = first 8 bytes of `SHA256("navio-p2pmsg/device/v1" ‖ device_pub)`.

## Device list

Published in bundle v2 and synced to all devices:

```
u8      version = 1
u32     account_epoch
CompactSize n
n × {
  u8[8]   device_id
  u8[48]  device_pub
  i64     created_at
  u8      caps            bit0 PRIMARY, bit1 CAN_PAIR, bit2 CAN_ADMIN_GROUPS
  CompactSize len, u8[len] label      // "Alex's phone", user-supplied
  u8[96]  cert
}
u8[96]  list_sig          = Sign(identity_sk, everything above)
```

A recipient verifies `list_sig` under the sender's identity key and then
accepts per-message signatures from any listed `device_pub`. A message signed
by a device that is not on the list is surfaced as untrusted — it is the exact
signature an attacker who stole one device would produce after revocation.

## Pairing

No server, no QR service, no account. The primary shows a QR; the new device
scans it; they meet on the bus.

```
QR payload:  navpair1…  (bech32m)
    u8      version = 1
    u8      network
    u8[48]  pair_pub        ephemeral BLS public key, single use
    u8[16]  salt
```

1. Primary mints `pair_sk`/`pair_pub`, shows the QR, and subscribes to
   `_p2pmsg/pair/<hex(SHA256(pair_pub))>`.
2. New device generates `device_sk`, sends a BROADCAST-scope message on that
   topic with `HAS_REPLY_KEY` set, payload = `device_pub ‖ label`. The topic is
   a hash of a single-use key, so it identifies nothing and expires with the
   pairing.
3. Both compute `sas = first 6 digits of HKDF(DH(pair, device), salt, info="sas")`
   and **display it**. The user confirms the two screens match. This is the
   only step that authenticates the channel; without it the pairing is
   vulnerable to an attacker who photographed the QR.
4. On confirmation the primary replies to the reply key with, encrypted:
   `account_secret_e`, the signed `device_cert`, the device list, the contact
   list, group epoch secrets, and the archive cursors.
5. Primary publishes the updated device list and bundle v2.
6. History backfill happens separately over the direct channel (`stream.md`) —
   it is megabytes and does not belong on the bus.

Pairing offers expire after 5 minutes and are single-use.

## Revocation

1. User removes the device on the primary.
2. Primary bumps `e`, derives `account_secret_{e+1}`, and delivers it 1:1 to
   each *remaining* device over the ratchet.
3. Primary publishes bundle v2 with the new inbox prekey, the new clue key and
   the new device list, plus a signed revocation record naming the removed
   `device_id` and the epoch from which it is invalid.
4. Group epochs the revoked device belonged to are rotated too (`groups.md`).
5. Previous-epoch keys stay in a 7-day grace window so senders holding a cached
   bundle keep working — **the revoked device can also still read that grace
   window**. Applications should say so when the user revokes, and offer a
   "cut off immediately" option that skips the grace at the cost of dropping
   messages from stale senders.

Revocation is forward-only. It cannot unread what the device already read.

## State sync

What syncs, and how:

| state | mechanism |
|---|---|
| incoming messages | free — every device decrypts the same envelope |
| **sent** messages | a self-addressed mirror copy (below) |
| read state | chat `RECEIPT` frames, self-addressed, coalesced |
| contacts, blocklist | self-addressed, on change |
| group epoch secrets | self-addressed, on change |
| device list | bundle v2 |
| history backfill | direct channel (`stream.md`) |
| drafts | not synced |

**The sent-message mirror.** Outgoing messages are encrypted to the recipient,
so your other devices cannot read them. A mirror copy addressed to your own
account is needed — at the cost of a second envelope and a second proof of
work. That cost is real (23 bits ≈ seconds on a phone), so mirrors are
**batched**: up to 3 KB of recent sent frames ride one envelope, flushed after
30 seconds of inactivity or when full. A single-device account skips mirroring
entirely.

## Module layout

```
src/devices/
  hierarchy.ts    epoch derivation, device keys, certs
  list.ts         device list codec, verification
  pairing.ts      QR payload, SAS, the bus handshake
  sync.ts         self-addressed mirror batching, contact/group/read sync
```

## Checklist

- [ ] account epoch derivation and rotation
- [ ] device certificates and signed device list; reject unlisted signers
- [ ] pairing with mandatory SAS confirmation and a 5-minute expiry
- [ ] revocation including group rekey and the grace-window warning
- [ ] batched sent-message mirror, disabled for single-device accounts
- [ ] test: 3 devices, send from each, all three converge on identical history
- [ ] test: revoked device cannot decrypt epoch e+1
