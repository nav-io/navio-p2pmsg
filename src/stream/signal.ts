/**
 * Signalling for the direct channel.
 *
 * The two ends meet over the BUS — already authenticated, encrypted, reachable,
 * and (because signalling rides ordinary chat frames) retrievable from an
 * archive, so an offer made while the peer was offline still arrives.
 *
 * SDP is verbose and the bus charges by the byte, so it is carried as a
 * length-prefixed string and applications are expected to keep it minimal.
 * Candidates trickle as separate messages.
 *
 * The backend that consumes these is not in this package yet: WebRTC is the
 * one that works in both runtimes (a browser can neither accept inbound
 * sockets nor speak raw UDP), and it needs a signalling partner to test
 * against. This codec and the `StreamTransport` interface are the seam it
 * will plug into. See docs/stream.md.
 */
import { Reader, Writer } from '../common/serialize.js';

export const SignalOp = { OFFER: 1, ANSWER: 2, CANDIDATE: 3, CLOSE: 4 } as const;

/** Offers expire: a stale one would have a peer dialling a session nobody kept. */
export const SIGNAL_OFFER_TTL_SECONDS = 60;

export interface StreamSignal {
  op: number;
  /** Ties an answer and its candidates to one offer. */
  sessionId: Uint8Array; // 16
  /** SDP, or a single ICE candidate. */
  data: string;
}

export function serializeSignal(s: StreamSignal): Uint8Array {
  if (s.sessionId.length !== 16) throw new Error('sessionId must be 16 bytes');
  if (s.op < 1 || s.op > 4) throw new Error(`unknown signal op ${s.op}`);
  return new Writer().u8(s.op).bytes(s.sessionId).varString(s.data).finish();
}

export function parseSignal(bytes: Uint8Array): StreamSignal {
  const r = new Reader(bytes);
  const op = r.u8();
  if (op < 1 || op > 4) throw new Error(`unknown signal op ${op}`);
  const out = { op, sessionId: r.bytes(16).slice(), data: r.varString() };
  r.assertDone();
  return out;
}
