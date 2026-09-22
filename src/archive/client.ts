/**
 * Retrieval of messages that arrived while we were offline.
 *
 * The bus carries no recipient field, so a node has nothing to index on and
 * cannot hold mail for an absent peer. An ARCHIVING node instead keeps the
 * flagged envelopes it relayed and hands back the subset matching a detection
 * key we supply — our messages plus a `2^-precision` fraction of everyone
 * else's, with no way for it to tell them apart. See `../bus/fmd.js`.
 *
 * Retrieved envelopes go through the ordinary inbound path (PoW, replay cache,
 * trial decrypt) with the timestamp window relaxed, since an archived envelope
 * is old by definition. Everything above the bus therefore treats an archived
 * message exactly like a live one.
 */
import type { BusClient } from '../bus/client.js';
import { FMD_GAMMA } from '../bus/fmd.js';
import { MessageType, ServiceFlags, hasService } from '../net/messages.js';
import type { PeerPool } from '../net/pool.js';
import type { Store } from '../stores/store.js';
import { Reader, Writer } from '../common/serialize.js';
import {
  type ArchiveResponse,
  MAX_ARCHIVE_LIMIT,
  buildArchiveRequest,
  parseArchiveResponse,
  serializeArchiveRequest,
} from './protocol.js';

const NS = 'archive';

export interface ArchiveClientOptions {
  pool: PeerPool;
  bus: BusClient;
  store: Store;
  /**
   * False-positive exponent. Lower means more decoys, more bandwidth and a
   * larger anonymity set; the maximum tells the archiving node almost exactly
   * which messages are ours. Default 8 — conservative, and the choice is
   * deliberately the application's.
   */
  precision?: number;
  /** Entries per query. The node caps this at 500. */
  limit?: number;
  /** Base difficulty the archive charges. Must match its `-p2pmsgarchivepowbits`. */
  powBits: number;
  /** How long to wait for a `p2pmsgs` response. Default 60 s. */
  timeoutMs?: number;
  now?: () => number;
}

export interface SyncResult {
  /** Envelopes returned across every round, including decoys. */
  received: number;
  /** Envelopes the bus accepted (decoys fail to decrypt and are dropped later). */
  accepted: number;
  /** True when every queried peer reported its window fully scanned. */
  complete: boolean;
  peers: number;
}

export class ArchiveClient {
  private readonly opts: Required<Omit<ArchiveClientOptions, 'pool' | 'bus' | 'store'>>;
  private pending = new Map<string, (res: ArchiveResponse) => void>();
  private off: (() => void) | undefined;

  constructor(private readonly o: ArchiveClientOptions) {
    this.opts = {
      precision: o.precision ?? 8,
      limit: Math.min(o.limit ?? 100, MAX_ARCHIVE_LIMIT),
      powBits: o.powBits,
      timeoutMs: o.timeoutMs ?? 60_000,
      now: o.now ?? (() => Date.now()),
    };
    if (this.opts.precision < 1 || this.opts.precision > FMD_GAMMA) {
      throw new Error(`precision must be 1..${FMD_GAMMA}`);
    }
    this.off = o.pool.on('archive', ({ peerId, payload }) => {
      const resolve = this.pending.get(peerId);
      if (!resolve) return; // unsolicited; ignore
      this.pending.delete(peerId);
      try {
        resolve(parseArchiveResponse(payload));
      } catch {
        // Malformed response: treat as no response. The timeout already covers
        // a peer that says nothing, and one that says nonsense is no better.
      }
    });
  }

  close(): void {
    this.off?.();
    this.off = undefined;
    this.pending.clear();
  }

  /** Connected peers advertising NODE_P2PMSG_ARCHIVE. */
  archivePeers(): string[] {
    return this.o.pool
      .peers()
      .filter((p) => hasService(p.services, ServiceFlags.NODE_P2PMSG_ARCHIVE))
      .map((p) => p.id);
  }

  /**
   * Catch up from every archiving peer, resuming each from its own persisted
   * cursor.
   *
   * Cursors are per peer because ids are per store: two archiving nodes have
   * unrelated id spaces. Querying more than one matters — an archive that omits
   * results is indistinguishable from one with nothing to send, and asking
   * somebody else is the only defence.
   */
  async sync(detectionKey: Uint8Array, opts: { maxRounds?: number } = {}): Promise<SyncResult> {
    const maxRounds = opts.maxRounds ?? 20;
    const peers = this.archivePeers();
    const out: SyncResult = { received: 0, accepted: 0, complete: true, peers: peers.length };
    for (const peerId of peers) {
      let cursor = await this.loadCursor(peerId);
      for (let round = 0; round < maxRounds; round++) {
        const res = await this.queryPeer(peerId, detectionKey, cursor);
        if (!res) {
          // No usable answer from this peer. Leave its cursor where it was so
          // the next sync retries the same ground rather than skipping it.
          out.complete = false;
          break;
        }
        out.received += res.items.length;
        for (const item of res.items) {
          if (this.o.bus.onArchived(peerId, item.envelope) === 'accepted') out.accepted++;
        }
        cursor = res.nextCursor;
        await this.saveCursor(peerId, cursor);
        if (res.complete) break;
        if (round === maxRounds - 1) out.complete = false;
      }
    }
    return out;
  }

  /** One query against one peer. Resolves undefined on timeout or bad response. */
  async queryPeer(peerId: string, detectionKey: Uint8Array, cursor: bigint): Promise<ArchiveResponse | undefined> {
    const peer = this.o.pool.getPeer(peerId);
    if (!peer) return undefined;
    // One outstanding query per peer: the node meters us anyway, and matching
    // responses to requests by peer id only works if there is one in flight.
    if (this.pending.has(peerId)) throw new Error(`archive query already in flight for ${peerId}`);

    const req = buildArchiveRequest(
      {
        cursor,
        limit: this.opts.limit,
        precision: this.opts.precision,
        detectionKey,
        notBefore: 0n,
      },
      { baseBits: this.opts.powBits, nowSeconds: Math.floor(this.opts.now() / 1000) },
    );

    return new Promise<ArchiveResponse | undefined>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(peerId);
        resolve(undefined);
      }, this.opts.timeoutMs);
      this.pending.set(peerId, (res) => {
        clearTimeout(timer);
        resolve(res);
      });
      try {
        peer.send(MessageType.GETP2PMSGS, serializeArchiveRequest(req));
      } catch {
        clearTimeout(timer);
        this.pending.delete(peerId);
        resolve(undefined);
      }
    });
  }

  private async loadCursor(peerId: string): Promise<bigint> {
    const raw = await this.o.store.get(NS, cursorKey(peerId));
    if (!raw) return 0n;
    try {
      const r = new Reader(raw);
      if (r.u8() !== 1) return 0n;
      return r.u64();
    } catch {
      return 0n;
    }
  }

  private saveCursor(peerId: string, cursor: bigint): Promise<void> {
    return this.o.store.put(NS, cursorKey(peerId), new Writer().u8(1).u64(cursor).finish());
  }
}

/**
 * Cursors key on the peer's ADDRESS, not its connection id: an id is unique per
 * connection attempt, so keying on it would lose the cursor on every reconnect
 * and re-download the whole window.
 */
function cursorKey(peerId: string): string {
  const hash = peerId.lastIndexOf('#');
  return hash === -1 ? peerId : peerId.slice(0, hash);
}
