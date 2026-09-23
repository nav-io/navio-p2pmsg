# Direct channel

`navio-p2pmsg/stream`. Decisions 28, 29, 34, 36.

One mechanism closes four product holes at once: attachments, new-device
history backfill, typing and presence, and calls. All four have the same cause
— the bus caps a frame at 3584 B and charges a proof of work per envelope, so
the ceiling is roughly 53 KB and 16 proofs of work.

## Shape

The bus is the signalling channel; it is already authenticated, encrypted and
reachable, which is exactly what signalling needs. Media and bulk data go
direct.

```
    A ──── bus (signalling: offer, answer, candidates) ──── B
    A ═══════════ direct encrypted channel ═══════════════ B
```

## Transport

Decision 29. A browser cannot accept inbound sockets and cannot do raw UDP, so
any browser↔Node pair forces WebRTC on both ends. That settles it: WebRTC
everywhere, one stack.

| runtime | implementation |
|---|---|
| browser | native `RTCPeerConnection` data channels |
| Node | `node-datachannel` (libdatachannel, prebuilt binaries) as an **optional** peer dependency |

Optional matters: with the module absent the SDK still works and falls back to
bus-chunked transfer. A protocol library that fails to install because a native
module would not build is a library nobody embeds.

Everything sits behind a `StreamTransport` interface so a raw-UDP or QUIC
backend can replace WebRTC later without touching the layers above.

```ts
interface StreamTransport {
  connect(signal: SignalChannel): Promise<StreamSession>;
  accept(signal: SignalChannel): Promise<StreamSession>;
}
interface StreamSession {
  open(channel: string): StreamChannel;   // 'control' | 'file' | 'media'
  close(): void;
  on(e: 'channel' | 'close', cb): void;
}
```

### ICE without servers

No STUN, no TURN by default. The reflexive address comes free: the P2P
`version` handshake already reports the address a peer sees us at (`addrMe`).
Host candidates plus that one srflx candidate cover most networks.

Applications may supply their own ICE servers, and the SDK will use them; it
just never requires them.

**Symmetric NAT on both sides has no direct path.** Those pairs fall back to
bus-chunked transfer, capped at ~53 KB — enough for a thumbnail or a voice
note, not a video. This is a real, permanent limitation of a server-free
design; it is documented rather than papered over. The failure rate needs
measuring once there is a deployment to measure.

## Signalling

Chat frames of type `STREAM` (`chat.md`), so they are already end-to-end
encrypted, signed, delivered and — importantly — **retrievable from the
archive**, which means an offer placed while the peer was offline still arrives.

```
u8      op           1 offer, 2 answer, 3 candidate, 4 close
u8[16]  session_id
CompactSize len, u8[len] sdp_or_candidate      // deflate-compressed
```

SDP is compressed because it is verbose and the bus charges by the byte.
Candidates are trickled as separate frames. Offers expire after 60 s.

## Framing

The data channel carries a multiplexed, length-prefixed stream:

```
u8          channel      1 control, 2 file, 3 media-meta
u32         length
u8[length]  payload
```

The WebRTC channel is DTLS-encrypted, but the peer authentication that matters
is ours: the session key is bound to the identity keys via the bus signalling,
so a successful connection proves the peer holds the identity key we addressed
the offer to. DTLS alone would only prove the peer holds the fingerprint in an
SDP that was, itself, delivered over the bus.

## File transfer

```
control:  REQUEST  { content_hash, offset, length }
          HAVE     { content_hash, size }
          DENY     { content_hash, reason }
file:     CHUNK    { content_hash, offset, bytes }
```

- Content-addressed and **resumable** — `offset` means a dropped connection
  costs the remaining bytes, not all of them.
- Each file is encrypted with its own key (the `key` in the `AttachRef` from
  `chat.md`) *in addition to* the channel encryption. The channel may be a
  fallback path, and a per-file key means the ciphertext is safe to relay or
  store anywhere without trusting the carrier.
- Chunk size 16 KB, up to 8 chunks in flight.
- The receiver verifies `content_hash` on completion and discards a mismatch.
- The sender is the source; there is no seeding from third parties. A file is
  available while the sender has the file and both are online. Applications
  should say so.

## History backfill

A newly paired device asks its primary for history over the same channel:

```
control:  SYNC_REQUEST  { conv_id, from_lamport, limit }
          SYNC_BATCH    { frames[] }
```

Frames are the original chat frames, so the receiving device verifies every
signature itself rather than trusting the device that sent them. Backfill is
bounded by the application — most want the last N per conversation, not
everything.

This is why backfill is not on the bus: it is megabytes and would cost one
proof of work per 3 KB.

**What a signature covers, and what carries it.** A chat frame is not signed;
the transport frame it arrived in is, over (topic, recipient key, frame). So an
entry carries that signed `AuthFrame` and the recipient key it binds to, and
the receiver checks three things: the signature holds, the recipient key is the
one the signature covers (a forger cannot substitute a convenient one, since it
is signed too), and the frame in the entry is byte-for-byte the one the
signature was over. Checking only the signature would let a device staple a
genuine one to different content.

Two kinds of entry have no proof and never can: **our own sent messages**,
which were signed to the recipient and not to us, and anything stored before
the signed frame was kept. They are still history, and a device that hands us
history already holds the account's secrets — it is simply not trusted to
invent what a contact said. `backfillFrom()` returns `verified`, `unverified`
and `rejected` counts so an application can say which is which. A rejected
entry is dropped, never stored.

## Typing and presence

`EPHEMERAL` frames on the control channel only (decision 34). They never touch
the bus and are never stored. No direct channel means no typing indicator —
honest degradation, and the alternative costs a proof of work per keystroke
burst.

```
control:  TYPING    { conv_id, u8 state }         0 stopped, 1 typing
          PRESENCE  { u8 state, i64 since }
```

Presence is only ever shared with an already-connected peer, which by
construction is someone you are in a conversation with. There is no global
presence and no presence broadcast.

## Calls

Decision 36: 1:1 now, groups later.

- Offer/answer/candidates over `CALL` frames on the bus.
- Media over the WebRTC connection already established for data.
- Audio and video, mute, camera switch, hold.
- Ringing needs the callee online, or a push wake (decision 35, out of SDK
  scope) — a call is inherently synchronous and the archive does not help.
- **Group calls are deferred.** A mesh works to roughly five participants;
  beyond that needs an SFU, which is a server, which the architecture rejects.

## Connection policy

- Direct channels open lazily: when a transfer is requested, a call starts, or
  a conversation is in the foreground and the application opted in.
- Idle channels close after 5 minutes.
- Maximum 8 concurrent sessions.
- **Opening a direct channel reveals your IP address to the peer.** That is a
  significant change from bus-only operation, where nothing reveals it. It must
  be opt-in per contact, defaulting to on for accepted contacts and off for
  contact requests, and the application must be able to disable it entirely.
  `security.md` records this.

## Module layout

```
src/stream/
  transport.ts    StreamTransport interface
  webrtc.ts       browser + node-datachannel backends
  signal.ts       STREAM/CALL frame codecs, offer/answer/trickle
  mux.ts          channel framing
  file.ts         request/chunk/resume, per-file encryption
  backfill.ts     SYNC_REQUEST/SYNC_BATCH
  ephemeral.ts    typing, presence
  call.ts         1:1 media
  fallback.ts     bus-chunked transfer under the 53 KB cap
```

## Checklist

- [ ] `StreamTransport` + both WebRTC backends; optional dep degrades cleanly
- [ ] srflx candidate from the P2P `version` handshake, no STUN dependency
- [ ] signalling over chat frames, including an offer retrieved from the archive
- [ ] resumable file transfer with per-file keys and hash verification
- [ ] bus-chunked fallback with an explicit size cap and a clear error past it
- [x] backfill verifying signatures on the receiving device
- [ ] IP-exposure policy: opt-in per contact, off for requests, globally disableable
- [ ] browser ⇄ Node interop test for every channel type
