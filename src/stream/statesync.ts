/**
 * Account state sync between the devices of one account, over a direct channel.
 *
 * `backfill.ts` moves conversations. This moves the state around them: who the
 * contacts are, what keys they publish, which groups exist and under which
 * epoch secrets, and how far the user has read. A device that was offline
 * while any of that changed has no other way to find out — the change was not
 * a message, so nothing replays it.
 *
 * Three sections, and three deliberate omissions.
 *
 * CONTACTS carries each contact's signed bundle, which the receiver verifies
 * for itself; a bundle that does not check out is dropped, so a sibling cannot
 * point us at a substituted key.
 *
 * GROUPS carries the current signed group state and every epoch secret the
 * sender holds. The state is hash-chained and validated on arrival, so the
 * receiver is not taking the sender's word for the membership either.
 *
 * READ carries each conversation's read heads, merged as a union: read state
 * only ever moves forward, and a union cannot un-read something one device had
 * already read.
 *
 * NOT carried: the known list, the blocklist, and drafts. A set with no
 * tombstones can only be unioned, and a union is wrong in both directions here
 * — it would resurrect a contact the user removed, or forget an unblock. They
 * need a change log with deletions, which is a different design, and shipping
 * a union that silently does the opposite of what the user asked would be
 * worse than shipping nothing.
 */
import { Reader, Writer } from '../common/serialize.js';
import { toHex } from '../common/bytes.js';
import type { StreamChannel } from './transport.js';

export const StateOp = { REQUEST: 1, BATCH: 2, DONE: 3, DENY: 4 } as const;

/** Section bits, so a caller can ask for only what it is missing. */
export const StateSection = { CONTACTS: 1, GROUPS: 2, READ: 4 } as const;
export const ALL_SECTIONS = StateSection.CONTACTS | StateSection.GROUPS | StateSection.READ;

/** Items per batch, so a slow channel makes visible progress. */
export const STATE_BATCH_SIZE = 32;

export type StateMessage =
  | { op: typeof StateOp.REQUEST; sections: number }
  | { op: typeof StateOp.BATCH; section: number; items: Uint8Array[] }
  | { op: typeof StateOp.DONE }
  | { op: typeof StateOp.DENY; reason: string };

export function serializeStateMessage(m: StateMessage): Uint8Array {
  const w = new Writer().u8(m.op);
  switch (m.op) {
    case StateOp.REQUEST:
      return w.u32(m.sections).finish();
    case StateOp.BATCH:
      w.u32(m.section).compactSize(m.items.length);
      for (const i of m.items) w.varBytes(i);
      return w.finish();
    case StateOp.DENY:
      return w.varString(m.reason).finish();
    default:
      return w.finish();
  }
}

export function parseStateMessage(bytes: Uint8Array): StateMessage {
  const r = new Reader(bytes);
  const op = r.u8();
  let out: StateMessage;
  switch (op) {
    case StateOp.REQUEST:
      out = { op: StateOp.REQUEST, sections: r.u32() };
      break;
    case StateOp.BATCH: {
      const section = r.u32();
      const count = r.compactSize();
      if (count > 10_000) throw new Error('state batch too large');
      const items: Uint8Array[] = [];
      for (let i = 0; i < count; i++) items.push(r.varBytes().slice());
      out = { op: StateOp.BATCH, section, items };
      break;
    }
    case StateOp.DONE:
      out = { op: StateOp.DONE };
      break;
    case StateOp.DENY:
      out = { op: StateOp.DENY, reason: r.varString() };
      break;
    default:
      throw new Error(`unknown state op ${op}`);
  }
  r.assertDone();
  return out;
}

// ---------------------------------------------------------------- item codecs

/** GROUPS item: the signed state, plus every epoch secret the sender holds. */
export interface GroupSnapshot {
  state: Uint8Array;
  secrets: { epoch: number; secret: Uint8Array }[];
}

export function serializeGroupSnapshot(s: GroupSnapshot): Uint8Array {
  const w = new Writer().varBytes(s.state).compactSize(s.secrets.length);
  for (const e of s.secrets) w.u32(e.epoch).bytes(e.secret);
  return w.finish();
}

export function parseGroupSnapshot(bytes: Uint8Array): GroupSnapshot {
  const r = new Reader(bytes);
  const state = r.varBytes().slice();
  const n = r.compactSize();
  if (n > 1024) throw new Error('too many epoch secrets');
  const secrets: { epoch: number; secret: Uint8Array }[] = [];
  for (let i = 0; i < n; i++) secrets.push({ epoch: r.u32(), secret: r.bytes(32).slice() });
  r.assertDone();
  return { state, secrets };
}

/** READ item: how far the user has read in one conversation. */
export interface ReadSnapshot {
  convId: Uint8Array;
  heads: Uint8Array[];
}

export function serializeReadSnapshot(s: ReadSnapshot): Uint8Array {
  const w = new Writer().bytes(s.convId).compactSize(s.heads.length);
  for (const h of s.heads) w.bytes(h);
  return w.finish();
}

export function parseReadSnapshot(bytes: Uint8Array): ReadSnapshot {
  const r = new Reader(bytes);
  const convId = r.bytes(32).slice();
  const n = r.compactSize();
  if (n > 4096) throw new Error('too many read heads');
  const heads: Uint8Array[] = [];
  for (let i = 0; i < n; i++) heads.push(r.bytes(32).slice());
  r.assertDone();
  return { convId, heads };
}

// ---------------------------------------------------------------- server

export interface StateSource {
  /** Signed bundles, one per contact. */
  contacts(): Promise<Uint8Array[]>;
  groups(): Promise<GroupSnapshot[]>;
  read(): Promise<ReadSnapshot[]>;
}

/** Answers state requests from another device of this account. */
export class StateSyncServer {
  private off: (() => void) | undefined;

  constructor(
    private readonly channel: StreamChannel,
    private readonly source: StateSource,
  ) {
    this.off = channel.onMessage((data) => {
      void this.onMessage(data);
    });
  }

  close(): void {
    this.off?.();
    this.off = undefined;
  }

  private send(section: number, items: Uint8Array[]): void {
    for (let at = 0; at < items.length; at += STATE_BATCH_SIZE) {
      this.channel.send(
        serializeStateMessage({ op: StateOp.BATCH, section, items: items.slice(at, at + STATE_BATCH_SIZE) }),
      );
    }
  }

  private async onMessage(data: Uint8Array): Promise<void> {
    let msg: StateMessage;
    try {
      msg = parseStateMessage(data);
    } catch {
      return;
    }
    if (msg.op !== StateOp.REQUEST) return;
    try {
      if (msg.sections & StateSection.CONTACTS) this.send(StateSection.CONTACTS, await this.source.contacts());
      if (msg.sections & StateSection.GROUPS) {
        this.send(StateSection.GROUPS, (await this.source.groups()).map(serializeGroupSnapshot));
      }
      if (msg.sections & StateSection.READ) {
        this.send(StateSection.READ, (await this.source.read()).map(serializeReadSnapshot));
      }
    } catch (e) {
      this.channel.send(
        serializeStateMessage({ op: StateOp.DENY, reason: e instanceof Error ? e.message : 'unavailable' }),
      );
      return;
    }
    this.channel.send(serializeStateMessage({ op: StateOp.DONE }));
  }
}

// ---------------------------------------------------------------- client

export interface StateSyncResult {
  contacts: Uint8Array[];
  groups: GroupSnapshot[];
  read: ReadSnapshot[];
  /** Items that did not parse. They are dropped, never guessed at. */
  malformed: number;
}

/** Asks another device of this account for the state around the messages. */
export class StateSyncClient {
  private pending:
    | {
        resolve: (v: StateSyncResult) => void;
        reject: (e: Error) => void;
        result: StateSyncResult;
        timer: ReturnType<typeof setTimeout>;
      }
    | undefined;
  private off: (() => void) | undefined;

  constructor(private readonly channel: StreamChannel) {
    this.off = channel.onMessage((data) => this.onMessage(data));
  }

  close(): void {
    this.off?.();
    this.off = undefined;
    this.finish(new Error('state sync client closed'));
  }

  fetch(opts: { sections?: number; timeoutMs?: number } = {}): Promise<StateSyncResult> {
    if (this.pending) return Promise.reject(new Error('a state sync is already in flight'));
    return new Promise<StateSyncResult>((resolve, reject) => {
      const timer = setTimeout(() => this.finish(new Error('state sync timed out')), opts.timeoutMs ?? 60_000);
      this.pending = {
        resolve,
        reject,
        result: { contacts: [], groups: [], read: [], malformed: 0 },
        timer,
      };
      this.channel.send(
        serializeStateMessage({ op: StateOp.REQUEST, sections: opts.sections ?? ALL_SECTIONS }),
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
    let msg: StateMessage;
    try {
      msg = parseStateMessage(data);
    } catch {
      return;
    }
    const p = this.pending;
    if (!p) return;
    if (msg.op === StateOp.DENY) {
      this.finish(new Error(msg.reason || 'state sync denied'));
      return;
    }
    if (msg.op === StateOp.DONE) {
      this.finish();
      return;
    }
    if (msg.op !== StateOp.BATCH) return;
    for (const item of msg.items) {
      try {
        if (msg.section === StateSection.CONTACTS) p.result.contacts.push(item);
        else if (msg.section === StateSection.GROUPS) p.result.groups.push(parseGroupSnapshot(item));
        else if (msg.section === StateSection.READ) p.result.read.push(parseReadSnapshot(item));
      } catch {
        p.result.malformed++;
      }
    }
  }
}

/** Union of two read-head sets, which is the only direction read state moves. */
export function mergeHeads(a: Uint8Array[], b: Uint8Array[]): Uint8Array[] {
  const seen = new Map<string, Uint8Array>();
  for (const h of [...a, ...b]) seen.set(toHex(h), h);
  return [...seen.values()];
}
