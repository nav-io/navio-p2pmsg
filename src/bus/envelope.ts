/**
 * Wire envelope of a `p2pmsg` / `dp2pmsg` net message:
 *   u8 kind || PoWHeader (98) || EciesPacket
 * Whole payload <= 4096 bytes, no trailing bytes (navio-core `MAX_JOB_BYTES`).
 */
import { sha256 } from '@noble/hashes/sha256';
import { Reader, Writer } from '../common/serialize.js';
import { type EciesPacket, packetMsgHash, parsePacket, writePacket } from './ecies.js';
import { type PoWHeader, parsePoWHeader, writePoWHeader } from './pow.js';

export const MAX_ENVELOPE_BYTES = 4096;

export interface Envelope {
  kind: number;
  pow: PoWHeader;
  enc: EciesPacket;
}

export function serializeEnvelope(env: Envelope): Uint8Array {
  const w = new Writer().u8(env.kind);
  writePoWHeader(w, env.pow);
  writePacket(w, env.enc);
  return w.finish();
}

/** Parse an envelope. Throws on truncation, invalid eph encoding, trailing bytes or size > 4096. */
export function parseEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length > MAX_ENVELOPE_BYTES) throw new Error('envelope too large');
  const r = new Reader(bytes);
  const kind = r.u8();
  const pow = parsePoWHeader(r);
  const enc = parsePacket(r);
  r.assertDone();
  return { kind, pow, enc };
}

/** Replay-cache key: SHA256(u8 kind || MsgHash). Nonce-independent. */
export function replayKey(env: Envelope): Uint8Array {
  const h = packetMsgHash(env.enc);
  const buf = new Uint8Array(1 + h.length);
  buf[0] = env.kind & 0xff;
  buf.set(h, 1);
  return sha256(buf);
}
