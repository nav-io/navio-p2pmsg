/**
 * Typing and presence.
 *
 * These travel ONLY over an open direct channel. They never touch the bus and
 * are never stored.
 *
 * The reason is arithmetic: a typing indicator that costs 23 bits of proof of
 * work per keystroke burst, and therefore updates every thirty seconds, is
 * worse than no typing indicator at all. Honest degradation — no direct
 * channel, no typing indicator — beats a feature that lies about what it is
 * showing.
 *
 * Presence is only ever shared with a peer we already have a channel to, which
 * by construction is someone we are in a conversation with. There is no global
 * presence and nothing is broadcast.
 */
import { Reader, Writer } from '../common/serialize.js';
import type { StreamChannel } from './transport.js';

export const EphemeralOp = { TYPING: 1, PRESENCE: 2 } as const;
export const TypingState = { STOPPED: 0, TYPING: 1 } as const;
export const PresenceState = { OFFLINE: 0, ONLINE: 1, AWAY: 2 } as const;

export type EphemeralMessage =
  | { op: typeof EphemeralOp.TYPING; convId: Uint8Array; state: number }
  | { op: typeof EphemeralOp.PRESENCE; state: number; since: bigint };

export function serializeEphemeral(m: EphemeralMessage): Uint8Array {
  const w = new Writer().u8(m.op);
  if (m.op === EphemeralOp.TYPING) {
    if (m.convId.length !== 32) throw new Error('convId must be 32 bytes');
    return w.bytes(m.convId).u8(m.state).finish();
  }
  return w.u8(m.state).i64(m.since).finish();
}

export function parseEphemeral(bytes: Uint8Array): EphemeralMessage {
  const r = new Reader(bytes);
  const op = r.u8();
  let out: EphemeralMessage;
  if (op === EphemeralOp.TYPING) out = { op, convId: r.bytes(32).slice(), state: r.u8() };
  else if (op === EphemeralOp.PRESENCE) out = { op, state: r.u8(), since: r.i64() };
  else throw new Error(`unknown ephemeral op ${op}`);
  r.assertDone();
  return out;
}

/**
 * Sends and receives typing/presence on a control channel.
 *
 * Repeated `typing()` calls are coalesced: a keystroke handler will call it on
 * every key, and the peer needs a heartbeat, not a packet per character.
 */
export class EphemeralSignals {
  // Negative infinity, not 0: with a clock that starts near zero (a test, or
  // a monotonic timer) a 0 would throttle the very first signal, which is the
  // one that matters most.
  private lastTypingAt = Number.NEGATIVE_INFINITY;
  private off: (() => void) | undefined;

  constructor(
    private readonly channel: StreamChannel,
    private readonly onMessage: (m: EphemeralMessage) => void,
    private readonly now: () => number = () => Date.now(),
    /** Minimum gap between typing packets. */
    private readonly throttleMs = 3000,
  ) {
    this.off = channel.onMessage((data) => {
      try {
        this.onMessage(parseEphemeral(data));
      } catch {
        // Not an ephemeral message, or a newer encoding: ignore.
      }
    });
  }

  typing(convId: Uint8Array): void {
    const at = this.now();
    if (at - this.lastTypingAt < this.throttleMs) return;
    this.lastTypingAt = at;
    this.channel.send(serializeEphemeral({ op: EphemeralOp.TYPING, convId, state: TypingState.TYPING }));
  }

  stoppedTyping(convId: Uint8Array): void {
    // Not throttled: "stopped" is the state a stale "typing" would otherwise
    // leave showing forever. Reset so the next "typing" is sent immediately.
    this.lastTypingAt = Number.NEGATIVE_INFINITY;
    this.channel.send(serializeEphemeral({ op: EphemeralOp.TYPING, convId, state: TypingState.STOPPED }));
  }

  presence(state: number): void {
    this.channel.send(serializeEphemeral({ op: EphemeralOp.PRESENCE, state, since: BigInt(Math.floor(this.now() / 1000)) }));
  }

  close(): void {
    this.off?.();
    this.off = undefined;
  }
}
