/**
 * Wire envelope of a `p2pmsg` / `dp2pmsg` net message, **version 2**:
 *   u8 kind || PoWHeader (98) || CompactSize flen || u8[flen] flag || EciesPacket
 * Whole payload <= 4096 bytes, no trailing bytes (navio-core `MAX_JOB_BYTES`).
 *
 * `flag` is optional and empty for everything except messages a recipient may
 * want to retrieve after being offline — see `./fmd.js`. A flag of exactly
 * `FMD_FLAG_SIZE` bytes is one this build can test; other non-empty sizes are
 * reserved, relayed and stored unchanged but never matched, so a future
 * parameter change propagates without a node upgrade.
 *
 * v1 had no `flen` field and a version-1 `PoWHeader`. navio-core rejects v1
 * outright rather than accepting both, because a v1 stamp bound only the
 * ciphertext and could otherwise be replayed with an attacker's flag attached.
 */
import { sha256 } from '@noble/hashes/sha256';
import { Reader, Writer } from '../common/serialize.js';
import { type EciesPacket, packetMsgHash, parsePacket, writePacket } from './ecies.js';
import { type PoWHeader, parsePoWHeader, payloadHash, writePoWHeader } from './pow.js';

export const MAX_ENVELOPE_BYTES = 4096;
/**
 * Upper bound on the detection flag, matching navio-core `MAX_FLAG_BYTES`.
 * Keeps envelope overhead predictable while leaving room for a future gamma.
 */
export const MAX_FLAG_BYTES = 128;

export interface Envelope {
  kind: number;
  pow: PoWHeader;
  /** Detection flag; empty when the sender does not want it archivable. */
  flag: Uint8Array;
  enc: EciesPacket;
}

export function serializeEnvelope(env: Envelope): Uint8Array {
  const w = new Writer().u8(env.kind);
  writePoWHeader(w, env.pow);
  w.varBytes(env.flag);
  writePacket(w, env.enc);
  return w.finish();
}

/** Parse an envelope. Throws on truncation, invalid eph encoding, trailing bytes or size > 4096. */
export function parseEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length > MAX_ENVELOPE_BYTES) throw new Error('envelope too large');
  const r = new Reader(bytes);
  const kind = r.u8();
  const pow = parsePoWHeader(r);
  const flag = r.varBytes().slice();
  if (flag.length > MAX_FLAG_BYTES) throw new Error('detection flag too large');
  const enc = parsePacket(r);
  r.assertDone();
  return { kind, pow, flag, enc };
}

/** What `env.pow.payloadHash` must equal. */
export function expectedPayloadHash(env: Envelope): Uint8Array {
  return payloadHash(env.pow.version, packetMsgHash(env.enc), env.flag);
}

/**
 * A message's identity, for relay and for delivery alike:
 * `SHA256(u8 kind || MsgHash)` — the kind and the CIPHERTEXT, with the flag
 * left out and the nonce irrelevant.
 *
 * The flag is deliberately not in it. It is a retrieval hint, it is not
 * secret, and it must not be able to mint a fresh identity for a message:
 * anyone who saw an envelope could otherwise attach or rewrite a flag over
 * somebody else's ciphertext, pay one proof of work, and have it flooded and
 * delivered all over again. The cost would sit with the wrong party.
 *
 * A sender that genuinely needs to re-flag — because the recipient's clue key
 * rotated — re-encrypts, which is a new ciphertext and honestly a new
 * message. navio-core keys its relay cache the same way.
 */
export function messageKey(env: Envelope): Uint8Array {
  const h = packetMsgHash(env.enc);
  const buf = new Uint8Array(1 + h.length);
  buf[0] = env.kind & 0xff;
  buf.set(h, 1);
  return sha256(buf);
}

/** @deprecated Use {@link messageKey}; kept so the old name still resolves. */
export const deliveryKey = messageKey;
