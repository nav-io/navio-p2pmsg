/**
 * History backfill over a direct channel.
 *
 * A newly paired device starts empty. Everything it will ever receive from now
 * on it can decrypt, but the conversation that happened before it existed is
 * held only by the devices that were there. Backfill moves it across.
 *
 * It is not on the bus on purpose: history is megabytes, and the bus charges
 * one proof of work per ~3 KB envelope.
 *
 * What travels is the ORIGINAL signed transport frame for every message that
 * has one, so the receiving device verifies authorship itself. A device that
 * hands over history is trusted to hand over the account's own secrets already
 * — it is not trusted to invent what a contact said. Messages stored before
 * the signature was kept, and our own sent messages, have no proof to check;
 * they are accepted for what they are, and `unverified` reports how many.
 */
import { Reader, Writer } from '../common/serialize.js';
import { toHex } from '../common/bytes.js';
import { parseAuthFrame } from '../usermsg/frame.js';
import { verifyAuthFrame } from '../usermsg/auth.js';
import type { StreamChannel } from './transport.js';

export const SyncOp = { REQUEST: 1, BATCH: 2, DONE: 3, DENY: 4 } as const;

/** Frames per batch. Bounded so a slow channel makes progress visibly. */
export const SYNC_BATCH_SIZE = 64;

export interface SyncEntry {
  /** The chat frame, serialised exactly as it was signed. */
  frame: Uint8Array;
  /** Sender identity, absent for an unsigned message. */
  sender?: Uint8Array;
  receivedAt: number;
  /** The signed transport frame and the recipient key it binds to. */
  signed?: Uint8Array;
  signedFor?: Uint8Array;
}

export type SyncMessage =
  | { op: typeof SyncOp.REQUEST; convId: Uint8Array; fromLamport: bigint; limit: number }
  | { op: typeof SyncOp.BATCH; convId: Uint8Array; entries: SyncEntry[] }
  | { op: typeof SyncOp.DONE; convId: Uint8Array }
  | { op: typeof SyncOp.DENY; convId: Uint8Array; reason: string };

function writeEntry(w: Writer, e: SyncEntry): void {
  w.varBytes(e.frame).i64(BigInt(e.receivedAt));
  if (e.sender) w.u8(1).bytes(e.sender);
  else w.u8(0);
  if (e.signed && e.signedFor) w.u8(1).varBytes(e.signed).bytes(e.signedFor);
  else w.u8(0);
}

function readEntry(r: Reader): SyncEntry {
  const frame = r.varBytes().slice();
  const receivedAt = Number(r.i64());
  const sender = r.u8() === 1 ? r.bytes(48).slice() : undefined;
  const hasProof = r.u8() === 1;
  const signed = hasProof ? r.varBytes().slice() : undefined;
  const signedFor = hasProof ? r.bytes(48).slice() : undefined;
  const out: SyncEntry = { frame, receivedAt };
  if (sender) out.sender = sender;
  if (signed && signedFor) {
    out.signed = signed;
    out.signedFor = signedFor;
  }
  return out;
}

export function serializeSyncMessage(m: SyncMessage): Uint8Array {
  const w = new Writer().u8(m.op).bytes(m.convId);
  switch (m.op) {
    case SyncOp.REQUEST:
      return w.i64(m.fromLamport).u32(m.limit).finish();
    case SyncOp.BATCH:
      w.u32(m.entries.length);
      for (const e of m.entries) writeEntry(w, e);
      return w.finish();
    case SyncOp.DENY:
      return w.varString(m.reason).finish();
    default:
      return w.finish();
  }
}

export function parseSyncMessage(bytes: Uint8Array): SyncMessage {
  const r = new Reader(bytes);
  const op = r.u8();
  const convId = r.bytes(32).slice();
  let out: SyncMessage;
  switch (op) {
    case SyncOp.REQUEST:
      out = { op: SyncOp.REQUEST, convId, fromLamport: r.i64(), limit: r.u32() };
      break;
    case SyncOp.BATCH: {
      const count = r.u32();
      const entries: SyncEntry[] = [];
      for (let i = 0; i < count; i++) entries.push(readEntry(r));
      out = { op: SyncOp.BATCH, convId, entries };
      break;
    }
    case SyncOp.DONE:
      out = { op: SyncOp.DONE, convId };
      break;
    case SyncOp.DENY:
      out = { op: SyncOp.DENY, convId, reason: r.varString() };
      break;
    default:
      throw new Error(`unknown sync op ${op}`);
  }
  r.assertDone();
  return out;
}

/** Everything a server needs to answer one request. */
export interface BackfillSource {
  /**
   * Messages of `convId` with `lamport >= fromLamport`, oldest first, at most
   * `limit`. The topic is needed to verify the frames at the other end, so it
   * travels with them implicitly: the receiver derives it from `convId`.
   */
  history(convId: Uint8Array, fromLamport: bigint, limit: number): Promise<SyncEntry[]>;
}

/** Answers backfill requests from this device's history. */
export class BackfillServer {
  private off: (() => void) | undefined;

  constructor(
    private readonly channel: StreamChannel,
    private readonly source: BackfillSource,
    private readonly opts: { maxLimit?: number } = {},
  ) {
    this.off = channel.onMessage((data) => {
      void this.onMessage(data);
    });
  }

  close(): void {
    this.off?.();
    this.off = undefined;
  }

  private async onMessage(data: Uint8Array): Promise<void> {
    let msg: SyncMessage;
    try {
      msg = parseSyncMessage(data);
    } catch {
      return;
    }
    if (msg.op !== SyncOp.REQUEST) return;
    const limit = Math.min(msg.limit || SYNC_BATCH_SIZE, this.opts.maxLimit ?? 5000);
    let entries: SyncEntry[];
    try {
      entries = await this.source.history(msg.convId, msg.fromLamport, limit);
    } catch (e) {
      this.channel.send(
        serializeSyncMessage({
          op: SyncOp.DENY,
          convId: msg.convId,
          reason: e instanceof Error ? e.message : 'unavailable',
        }),
      );
      return;
    }
    for (let at = 0; at < entries.length; at += SYNC_BATCH_SIZE) {
      this.channel.send(
        serializeSyncMessage({
          op: SyncOp.BATCH,
          convId: msg.convId,
          entries: entries.slice(at, at + SYNC_BATCH_SIZE),
        }),
      );
    }
    this.channel.send(serializeSyncMessage({ op: SyncOp.DONE, convId: msg.convId }));
  }
}

export interface BackfillResult {
  /** Entries whose signature checked out. */
  verified: SyncEntry[];
  /** Entries that carried no proof of authorship — see the module comment. */
  unverified: SyncEntry[];
  /** Entries whose proof was present and WRONG. Counted, never returned. */
  rejected: number;
}

/** Asks another device of this account for a conversation's history. */
export class BackfillClient {
  private pending:
    | {
        key: string;
        resolve: (v: BackfillResult) => void;
        reject: (e: Error) => void;
        result: BackfillResult;
        timer: ReturnType<typeof setTimeout>;
      }
    | undefined;
  private off: (() => void) | undefined;

  constructor(
    private readonly channel: StreamChannel,
    /** Chat topic for a conversation id; the signature binds it. */
    private readonly topicFor: (convId: Uint8Array) => string,
  ) {
    this.off = channel.onMessage((data) => this.onMessage(data));
  }

  close(): void {
    this.off?.();
    this.off = undefined;
    this.finish(new Error('backfill client closed'));
  }

  /**
   * Fetch `convId` from `fromLamport` onwards. One request at a time: the
   * answer is matched by conversation, and two in flight for the same one
   * could not be told apart.
   */
  fetch(
    convId: Uint8Array,
    opts: { fromLamport?: bigint; limit?: number; timeoutMs?: number } = {},
  ): Promise<BackfillResult> {
    if (this.pending) return Promise.reject(new Error('a backfill is already in flight'));
    return new Promise<BackfillResult>((resolve, reject) => {
      const timer = setTimeout(() => this.finish(new Error('backfill timed out')), opts.timeoutMs ?? 60_000);
      this.pending = {
        key: toHex(convId),
        resolve,
        reject,
        result: { verified: [], unverified: [], rejected: 0 },
        timer,
      };
      this.channel.send(
        serializeSyncMessage({
          op: SyncOp.REQUEST,
          convId,
          fromLamport: opts.fromLamport ?? 0n,
          limit: opts.limit ?? 500,
        }),
      );
    });
  }

  private finish(err?: Error): void {
    const p = this.pending;
    if (!p) return;
    this.pending = undefined;
    clearTimeout(p.timer);
    if (err) p.reject(err);
    else p.resolve(p.result);
  }

  private onMessage(data: Uint8Array): void {
    let msg: SyncMessage;
    try {
      msg = parseSyncMessage(data);
    } catch {
      return;
    }
    const p = this.pending;
    if (!p || toHex(msg.convId) !== p.key) return;
    if (msg.op === SyncOp.DENY) {
      this.finish(new Error(msg.reason || 'backfill denied'));
      return;
    }
    if (msg.op === SyncOp.DONE) {
      this.finish();
      return;
    }
    if (msg.op !== SyncOp.BATCH) return;
    const topic = this.topicFor(msg.convId);
    for (const e of msg.entries) {
      if (!e.signed || !e.signedFor) {
        p.result.unverified.push(e);
        continue;
      }
      if (verifyEntry(e, topic)) p.result.verified.push(e);
      else p.result.rejected++;
    }
  }
}

/**
 * Check that the frame in the entry is the one the signature covers, and that
 * the signature holds. Checking the signature alone would be pointless: a
 * device could staple a genuine signed frame to different content.
 */
export function verifyEntry(e: SyncEntry, topic: string): boolean {
  if (!e.signed || !e.signedFor) return false;
  let auth;
  try {
    auth = parseAuthFrame(e.signed);
  } catch {
    return false;
  }
  if (!auth.sender) return false;
  if (e.sender && toHex(e.sender) !== toHex(auth.sender)) return false;
  if (toHex(auth.payload) !== toHex(e.frame)) return false;
  return verifyAuthFrame(auth, topic, e.signedFor);
}
