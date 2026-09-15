/**
 * Reliable-delivery bookkeeping: which chunks of which messages still await a
 * signed ack, when to re-send, when to give up. Pure state machine with an
 * injectable clock; persistence via Store namespace "outbox".
 */
import type { Store } from '../stores/store.js';
import { Reader, Writer } from '../common/serialize.js';
import { toHex } from '../common/bytes.js';

export interface OutboxEntry {
  msgId: Uint8Array;
  recipient: Uint8Array; // identity (48)
  topic: string;
  chunks: Uint8Array[]; // application payload per chunk
  acked: boolean[];
  attempts: number;
  nextAt: number; // ms
  expiresAt: number; // ms
  createdAt: number;
}

export interface OutboxOptions {
  now?: () => number;
  ttlMs?: number; // default 24h
  backoffBaseMs?: number; // default 30s
  backoffCapMs?: number; // default 10min
}

const NS = 'outbox';

export class Outbox {
  private entries = new Map<string, OutboxEntry>();
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly base: number;
  private readonly cap: number;

  constructor(
    private readonly store: Store,
    opts: OutboxOptions = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.ttlMs = opts.ttlMs ?? 24 * 3600 * 1000;
    this.base = opts.backoffBaseMs ?? 30_000;
    this.cap = opts.backoffCapMs ?? 600_000;
  }

  async load(): Promise<void> {
    for (const { value } of await this.store.list(NS)) {
      const e = decode(value);
      this.entries.set(toHex(e.msgId), e);
    }
  }

  get size(): number {
    return this.entries.size;
  }

  get(msgId: Uint8Array): OutboxEntry | undefined {
    return this.entries.get(toHex(msgId));
  }

  async add(e: Omit<OutboxEntry, 'acked' | 'attempts' | 'nextAt' | 'expiresAt' | 'createdAt'> & { ttlMs?: number }): Promise<OutboxEntry> {
    const now = this.now();
    const entry: OutboxEntry = {
      msgId: e.msgId,
      recipient: e.recipient,
      topic: e.topic,
      chunks: e.chunks,
      acked: e.chunks.map(() => false),
      attempts: 0,
      nextAt: now,
      expiresAt: now + (e.ttlMs ?? this.ttlMs),
      createdAt: now,
    };
    this.entries.set(toHex(entry.msgId), entry);
    await this.persist(entry);
    return entry;
  }

  /** Entries whose retry time has come. Expired ones are removed and returned separately. */
  async due(): Promise<{ due: OutboxEntry[]; expired: OutboxEntry[] }> {
    const now = this.now();
    const due: OutboxEntry[] = [];
    const expired: OutboxEntry[] = [];
    for (const e of this.entries.values()) {
      if (e.expiresAt <= now) expired.push(e);
      else if (e.nextAt <= now) due.push(e);
    }
    for (const e of expired) await this.remove(e.msgId);
    return { due, expired };
  }

  /** Record a send attempt and schedule the next retry with exponential backoff + jitter. */
  async markSent(msgId: Uint8Array): Promise<void> {
    const e = this.entries.get(toHex(msgId));
    if (!e) return;
    e.attempts++;
    const delay = Math.min(this.cap, this.base * 2 ** (e.attempts - 1));
    const jitter = delay * (0.8 + Math.random() * 0.4);
    e.nextAt = Math.round(this.now() + jitter);
    await this.persist(e);
  }

  /** Apply an ack; returns the entry if it became fully acked (and was removed). */
  async ack(msgId: Uint8Array, chunkIdx: number | 'whole'): Promise<OutboxEntry | undefined> {
    const e = this.entries.get(toHex(msgId));
    if (!e) return undefined;
    if (chunkIdx === 'whole') e.acked.fill(true);
    else if (chunkIdx < e.acked.length) e.acked[chunkIdx] = true;
    if (e.acked.every(Boolean)) {
      await this.remove(msgId);
      return e;
    }
    await this.persist(e);
    return undefined;
  }

  /** Chunk indexes still unacked. */
  pendingChunks(e: OutboxEntry): number[] {
    const out: number[] = [];
    e.acked.forEach((a, i) => {
      if (!a) out.push(i);
    });
    return out;
  }

  async remove(msgId: Uint8Array): Promise<void> {
    const k = toHex(msgId);
    if (this.entries.delete(k)) await this.store.delete(NS, k);
  }

  private persist(e: OutboxEntry): Promise<void> {
    return this.store.put(NS, toHex(e.msgId), encode(e));
  }
}

function encode(e: OutboxEntry): Uint8Array {
  const w = new Writer()
    .u8(1)
    .bytes(e.msgId)
    .bytes(e.recipient)
    .varString(e.topic)
    .compactSize(e.chunks.length);
  for (let i = 0; i < e.chunks.length; i++) w.varBytes(e.chunks[i]!).u8(e.acked[i] ? 1 : 0);
  return w.u32(e.attempts).i64(BigInt(e.nextAt)).i64(BigInt(e.expiresAt)).i64(BigInt(e.createdAt)).finish();
}

function decode(b: Uint8Array): OutboxEntry {
  const r = new Reader(b);
  if (r.u8() !== 1) throw new Error('bad outbox record version');
  const msgId = r.bytes(16);
  const recipient = r.bytes(48);
  const topic = r.varString();
  const n = r.compactSize();
  const chunks: Uint8Array[] = [];
  const acked: boolean[] = [];
  for (let i = 0; i < n; i++) {
    chunks.push(r.varBytes());
    acked.push(r.u8() === 1);
  }
  const attempts = r.u32();
  const nextAt = Number(r.i64());
  const expiresAt = Number(r.i64());
  const createdAt = Number(r.i64());
  r.assertDone();
  return { msgId, recipient, topic, chunks, acked, attempts, nextAt, expiresAt, createdAt };
}
