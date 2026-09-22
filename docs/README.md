# navio-p2pmsg documentation

`DESIGN.md` at the repo root describes **v1 as shipped**: the bus, the wire
format, the `net`/`bus`/`usermsg`/`stores` layers and the two navio-core PRs
they depend on. It stays the reference for what exists today.

This directory describes **v2**: the work that turns the SDK from a messaging
primitive into a foundation a fully featured private chat app can be built on.

| doc | subject |
|---|---|
| [gap-analysis.md](gap-analysis.md) | what v1 is missing, and why each gap matters |
| [ROADMAP.md](ROADMAP.md) | decisions 21–42, milestones, sequencing, C++ PRs |
| [wire-v2.md](wire-v2.md) | envelope v2, PoW header v2, flag binding, BIP324 |
| [fmd.md](fmd.md) | Fuzzy Message Detection: keys, flags, detection, parameters |
| [archive.md](archive.md) | archive node role, `getp2pmsgs`/`p2pmsgs`, retention, abuse |
| [ratchet.md](ratchet.md) | session setup and the double ratchet, multi-device aware |
| [devices.md](devices.md) | multi-device key model, pairing, revocation, state sync |
| [groups.md](groups.md) | group keys, epochs, membership, invites, roles |
| [chat.md](chat.md) | chat layer: frames, causal DAG, history, search, profiles |
| [stream.md](stream.md) | direct channel, attachments, typing, backfill, calls |
| [security.md](security.md) | threat model: what leaks to whom, and what does not |

## Reading order

New to the project: `DESIGN.md` → `gap-analysis.md` → `ROADMAP.md`.

Implementing: `wire-v2.md` and `fmd.md` first — everything else depends on the
wire being settled.
