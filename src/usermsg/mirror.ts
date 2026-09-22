/**
 * Sent-message mirroring between an account's own devices.
 *
 * An outgoing message is encrypted to the recipient, so the sender's OTHER
 * devices cannot read it. Without a mirror, a phone paired to a desktop shows
 * only half of every conversation.
 *
 * The copy costs a second envelope and a second proof of work — seconds on a
 * phone at 23 bits — so mirrors are batched: several sent messages ride one
 * envelope, flushed on a timer or when the batch is full. An account with one
 * device never sends them at all.
 */
import { Reader, Writer } from '../common/serialize.js';

export const MIRROR_VERSION = 1;

export interface MirrorEntry {
  /** Who the original went to. */
  recipient: Uint8Array; // 48
  topic: string;
  /** Unix seconds, as the original carried. */
  timestamp: bigint;
  payload: Uint8Array;
}

export function serializeMirror(entries: MirrorEntry[]): Uint8Array {
  const w = new Writer().u8(MIRROR_VERSION).compactSize(entries.length);
  for (const e of entries) {
    if (e.recipient.length !== 48) throw new Error('recipient must be 48 bytes');
    w.bytes(e.recipient).varString(e.topic).i64(e.timestamp).varBytes(e.payload);
  }
  return w.finish();
}

export function parseMirror(bytes: Uint8Array): MirrorEntry[] {
  const r = new Reader(bytes);
  if (r.u8() !== MIRROR_VERSION) throw new Error('unknown mirror version');
  const n = r.compactSize();
  const out: MirrorEntry[] = [];
  for (let i = 0; i < n; i++) {
    out.push({
      recipient: r.bytes(48).slice(),
      topic: r.varString(),
      timestamp: r.i64(),
      payload: r.varBytes().slice(),
    });
  }
  r.assertDone();
  return out;
}

/**
 * Accumulates sent messages and hands them over in batches.
 *
 * Bounded by BOTH a byte budget and a count: one envelope has a hard ceiling,
 * and a batch that overflowed it would be dropped rather than delivered.
 */
export class MirrorBatcher {
  private pending: MirrorEntry[] = [];
  private bytes = 0;

  constructor(
    private readonly maxBytes: number,
    private readonly maxEntries = 64,
  ) {}

  get size(): number {
    return this.pending.length;
  }

  /** Returns a batch when adding this entry filled one, else undefined. */
  add(entry: MirrorEntry): MirrorEntry[] | undefined {
    const cost = 48 + entry.topic.length + 8 + entry.payload.length + 8;
    // Flush BEFORE adding when this entry would overflow, so the batch that
    // goes out is always one that fits.
    if (this.pending.length > 0 && (this.bytes + cost > this.maxBytes || this.pending.length >= this.maxEntries)) {
      const batch = this.flush();
      this.pending.push(entry);
      this.bytes = cost;
      return batch;
    }
    this.pending.push(entry);
    this.bytes += cost;
    if (this.bytes >= this.maxBytes || this.pending.length >= this.maxEntries) return this.flush();
    return undefined;
  }

  flush(): MirrorEntry[] {
    const out = this.pending;
    this.pending = [];
    this.bytes = 0;
    return out;
  }
}
