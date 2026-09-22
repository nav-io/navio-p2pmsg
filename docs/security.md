# Security and privacy model

What v2 protects, what it does not, and who learns what. Written to be read by
someone deciding whether to trust this, so the losses are stated as plainly as
the wins.

## Adversaries

| | capability |
|---|---|
| **Passive network observer** | sees all bus traffic and all P2P links |
| **Malicious relay node** | the above, plus can drop, delay and reorder |
| **Archive node** | the above, plus holds ciphertext and receives detection keys |
| **Direct-channel peer** | someone you connect to for a file or a call |
| **Former group member** | held a past epoch secret |
| **Revoked device** | held a past account secret |
| **Device thief** | has the device and whatever is at rest on it |

## What each one learns

### Passive observer

- Every envelope: `kind`, PoW header, flag, ciphertext, size bucket.
- **Not** the recipient. There is no recipient field, and the flag is
  untestable without a detection key — this is FMD's central property and the
  reason a hash-based tag was rejected (`fmd.md`).
- **Not** the topic, for 1:1 and group messages. The topic lives inside the
  ECIES layer. Public BROADCAST topics are, by design, visible to everyone.
- Timing and volume, always. If you send at 09:00 every day, that is visible.
- Which node you connect to. BIP324 hides the content of the link, not its
  existence.
- Size within a bucket is hidden by the padding ladder (64/256/1024/3072/3584);
  which bucket you used is not.

### Archive node

Everything above, plus:

- **Your detection key at the precision you chose**, and therefore the ability
  to test *future* flags at that precision until you rotate the account epoch.
  This is inherent to FMD, not a flaw in the deployment.
- On a **v1** link, so does anyone on the path — the query is not encrypted.
  Enable `transportVersion: 'v2'` before using `syncArchive()`; it is not the
  default yet only because most of the network still speaks v1.
- The set of envelopes matching it — your real messages plus `2^-n` of
  everything else. It does not learn which are which.
- Your IP, and your sync timing and frequency.

Mitigations: choose `n` deliberately (8 on desktop, 12 on mobile; lower is more
private and more bandwidth), query more than one archive node, rotate the
account epoch periodically, and prefer an archive node you run.

### Direct-channel peer

- **Your IP address.** This is the single largest privacy change in v2. Bus-only
  operation never reveals it to a correspondent; opening a direct channel does.
  It is opt-in per contact, off for contact requests, and globally disableable
  (`stream.md`).
- Your approximate online time, and file sizes and transfer timing.

### Former group member

- Everything from the epochs it was in, including ciphertext it recorded then.
- **Nothing from epoch `e+1` onward**, which is why removal always rekeys
  (`groups.md`).

### Revoked device

- Everything up to revocation, permanently. Revocation is forward-only; it
  cannot unread what was read.
- **The 7-day grace window as well**, because stale senders are still using the
  previous prekey. Applications must say this when the user revokes and offer
  an immediate cut-off that skips the grace at the cost of dropping messages
  from senders holding a cached bundle.

### Device thief

- Message history, the search index, contacts, group secrets and ratchet state,
  to whatever extent the application encrypted them at rest — which the SDK
  does not do for you.
- The search index is **plaintext-derived** and is the softest target: it
  reveals which words appear in your conversations even where bodies are
  encrypted. Encryption-at-rest for the index is an open item (`ROADMAP.md`).
- Forward secrecy limits what *past* ciphertext a thief can open from network
  captures, but not what is already stored decrypted on the device.

## Properties v2 adds

| property | mechanism |
|---|---|
| Offline delivery without a recipient identifier on the wire | FMD flags + archive (`fmd.md`, `archive.md`) |
| Detection key cannot be forged from public data | FMD: clue key holds `g^x`, testing needs `x` |
| Flag cannot be stripped or swapped | PoW binds it (`wire-v2.md`) |
| Forward secrecy per message | double ratchet (`ratchet.md`) |
| Post-compromise security | DH ratchet steps |
| Group secrecy after removal | epoch rekey (`groups.md`) |
| Group topic hidden | member-only group ECIES key |
| Device revocation | account epoch rotation (`devices.md`) |
| Link metadata protection | BIP324 v2 transport (`transportVersion: 'v2'`) |
| Sender authentication | per-message BLS signature over a verified device list |
| Anonymous sending | unsigned frames, unchanged from v1 |

## Properties v2 does **not** provide

- **Anonymity of the sender's network location** from an archive node or a
  direct peer. There is no mixnet and no onion routing. Use Tor if that is the
  requirement; the SDK does not do it for you.
- **Deletion.** A delete is a tombstone and a request. Anyone who received a
  message could have kept it. The API says so.
- **Protection against a compromised primary device.** It holds the root seed.
  Everything follows from it.
- **Metadata resistance against a global passive adversary** correlating timing
  across the whole network.
- **Post-quantum security.** BLS12-381, secp256k1 and the ratchet are all
  classical. A recorded transcript is a future problem.
- **Group calls, or calls with any server assistance.**

## Deliberate trade-offs

Each of these was a decision, not an oversight.

**Shared inbox key across devices** (decision 27). One envelope reaches every
device, so a sender does not pay for the recipient's device count. The cost:
every device holds the same decryption secret, so compromising any one of them
opens the account's incoming mail for that epoch.

**Deterministic receiver ratchet keys** (decision 31). Necessary for the above
— every device must derive the same receiving chain. The cost: the receiving
ratchet key sequence is fixed for an account epoch rather than random. It stays
secret and rotates with the epoch.

**FMD precision is a knob** (decision 24). The client chooses its own anonymity
set. A client that sets `n = 24` for bandwidth has effectively told the archive
node which envelopes are its own. Defaults are conservative and the
documentation is explicit.

**Search index at rest** (decision 38). Search is unusable without it past a
few thousand messages. The index is the softest target on a stolen device.

**Direct channels leak IP** (decision 28). Attachments, backfill, typing and
calls all require it. Opt-in, per contact, disableable.

## Review gates

Before mainnet, and before any claim of privacy is made publicly:

- [ ] FMD2 construction validated against the published paper, including hash
      inputs and the security argument for BLS12-381 G1
- [ ] Double ratchet reviewed against the Signal specification, especially the
      multi-device deviations, which are ours and not covered by that analysis
- [ ] Constant-time review of all scalar and point handling in both languages
- [ ] Cross-implementation test vectors, TS ⇄ C++, for every wire structure
- [ ] Independent review of the group key schedule and the rekey paths
- [ ] Fuzzing of every decoder: envelope, flag, chat frame, group state, invite
- [ ] Denial-of-service review of the archive query path with measured costs

Until these are done, the correct description of v2 is "designed for privacy",
not "private".
