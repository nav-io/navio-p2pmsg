/**
 * Splits an application payload into chunk payloads that each fit a USER_DATA
 * frame, and reassembles them on receive. Chunks share a msgId; each chunk is
 * an AuthFrame with FLAG_CHUNK and (idx, total).
 */
import { concat, toHex } from '../common/bytes.js';
import { AUTH_FRAME_MAX_OVERHEAD, MAX_USER_MSG_BYTES } from './frame.js';

/** Bytes available for application payload in one chunk of a given topic. */
export function chunkCapacity(topic: string): number {
  const topicBytes = new TextEncoder().encode(topic).length;
  // USER_DATA frame: CompactSize(topic) topic CompactSize(body) body; body = AuthFrame.
  const outer = 1 + topicBytes + 3; // compactsize(topic)=1 (<=64), compactsize(body) up to 3
  const cap = MAX_USER_MSG_BYTES - outer - AUTH_FRAME_MAX_OVERHEAD;
  if (cap < 1) throw new Error('topic too long');
  return cap;
}

export function splitChunks(payload: Uint8Array, topic: string, maxChunks: number): Uint8Array[] {
  const cap = chunkCapacity(topic);
  if (payload.length <= cap) return [payload];
  const total = Math.ceil(payload.length / cap);
  if (total > maxChunks) throw new PayloadTooLargeError(payload.length, cap * maxChunks);
  const out: Uint8Array[] = [];
  for (let i = 0; i < total; i++) out.push(payload.subarray(i * cap, Math.min(payload.length, (i + 1) * cap)));
  return out;
}

export class PayloadTooLargeError extends Error {
  constructor(
    public readonly size: number,
    public readonly max: number,
  ) {
    super(`payload is ${size} bytes, max ${max}`);
    this.name = 'PayloadTooLargeError';
  }
}

/**
 * The most chunks one message may claim.
 *
 * The wire allows a u16, so a peer can claim 65535 — a 230 MB message, which
 * nothing here supports. Believing the claim was an amplification: the old
 * reassembler allocated `new Array(total)` on the FIRST chunk, so 256 envelopes
 * each claiming the maximum reserved 130 MiB of heap for ten minutes, bought
 * with 256 proofs of work. Chunks are now held in a map, so memory tracks what
 * actually arrived, and a total past this cap is refused before anything is
 * allocated at all.
 *
 * 256 chunks is ~900 KB, well past what the SDK will send (`maxChunks`,
 * default 16) and far short of what an attacker needs for the claim to be
 * worth making.
 */
export const MAX_CHUNKS_PER_MESSAGE = 256;

interface Pending {
  /** Sparse on purpose: memory is proportional to chunks received, not claimed. */
  parts: Map<number, Uint8Array>;
  total: number;
  firstSeen: number;
  sender?: string;
}

/** Reassembles chunked messages. Keyed by msgId (+ sender when signed). */
export class Reassembler {
  private pending = new Map<string, Pending>();
  constructor(
    private readonly opts: {
      ttlMs?: number;
      maxPending?: number;
      /** Largest chunk total to believe. Default `MAX_CHUNKS_PER_MESSAGE`. */
      maxChunks?: number;
      now?: () => number;
    } = {},
  ) {}

  /**
   * Returns the full payload when the last chunk arrives, otherwise undefined.
   * Duplicate chunks are ignored. Mismatched totals are rejected (throws).
   */
  add(msgId: Uint8Array, sender: Uint8Array | undefined, idx: number, total: number, part: Uint8Array): Uint8Array | undefined {
    // Check the claim before allocating anything for it.
    const cap = this.opts.maxChunks ?? MAX_CHUNKS_PER_MESSAGE;
    if (total < 1 || total > cap) throw new Error(`chunk total ${total} out of range (max ${cap})`);
    if (idx >= total) throw new Error('chunk index out of range');

    this.sweep();
    const key = `${toHex(msgId)}:${sender ? toHex(sender) : '-'}`;
    let p = this.pending.get(key);
    if (!p) {
      if (this.pending.size >= (this.opts.maxPending ?? 256)) this.evictOldest();
      p = { parts: new Map(), total, firstSeen: this.now() };
      this.pending.set(key, p);
    }
    if (p.total !== total) throw new Error('chunk total mismatch');
    if (!p.parts.has(idx)) p.parts.set(idx, part);
    if (p.parts.size < total) return undefined;
    this.pending.delete(key);
    const ordered: Uint8Array[] = [];
    for (let i = 0; i < total; i++) ordered.push(p.parts.get(i)!);
    return concat(...ordered);
  }

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }
  private sweep(): void {
    const ttl = this.opts.ttlMs ?? 10 * 60 * 1000;
    const cutoff = this.now() - ttl;
    for (const [k, p] of this.pending) if (p.firstSeen < cutoff) this.pending.delete(k);
  }
  private evictOldest(): void {
    let oldestKey: string | undefined;
    let oldest = Infinity;
    for (const [k, p] of this.pending) {
      if (p.firstSeen < oldest) {
        oldest = p.firstSeen;
        oldestKey = k;
      }
    }
    if (oldestKey) this.pending.delete(oldestKey);
  }
}
