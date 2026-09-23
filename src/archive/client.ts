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
import { sha256 } from '@noble/hashes/sha256';
import type { BusClient } from '../bus/client.js';
import { FMD_GAMMA } from '../bus/fmd.js';
import { MessageType, ServiceFlags, hasService } from '../net/messages.js';
import type { PeerPool } from '../net/pool.js';
import type { Store } from '../stores/store.js';
import { Reader, Writer } from '../common/serialize.js';
import {
  type ArchiveResponse,
  DEFAULT_ARCHIVE_SCAN_BUDGET,
  MAX_ARCHIVE_LIMIT,
  MAX_ARCHIVE_SCAN_ENTRIES,
  buildArchiveRequest,
  parseArchiveResponse,
  serializeArchiveRequest,
} from './protocol.js';

const NS = 'archive';
/** How long to wait for a `p2pmsgchal` that a just-connected peer owes us. */
const CHALLENGE_WAIT_MS = 5000;

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
  /**
   * Entries the node may WALK per query, and what the stamp is priced on.
   * `limit` bounds matches; this bounds work, and for a high-precision key
   * almost nothing matches, so the two are not the same number. Default
   * `DEFAULT_ARCHIVE_SCAN_BUDGET`, which the node serves for the base cost.
   */
  scanBudget?: number;
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
      scanBudget: Math.min(o.scanBudget ?? DEFAULT_ARCHIVE_SCAN_BUDGET, MAX_ARCHIVE_SCAN_ENTRIES),
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
   *
   * They are also per DETECTION KEY. A cursor records how far this key has
   * scanned, not how far we have read: a shared cursor would let the first key
   * queried advance past the whole window and leave every later key resuming
   * from the end, silently finding nothing. That is exactly the case of
   * catching up across a group rekey, where each epoch has its own key and the
   * messages sit behind the cursor the previous epoch just moved.
   */
  async sync(detectionKey: Uint8Array, opts: { maxRounds?: number } = {}): Promise<SyncResult> {
    const maxRounds = opts.maxRounds ?? 20;
    const peers = this.archivePeers();
    const out: SyncResult = { received: 0, accepted: 0, complete: true, peers: peers.length };
    for (const peerId of peers) {
      let cursor = await this.loadCursor(peerId, detectionKey);
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
        await this.saveCursor(peerId, detectionKey, cursor);
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

    // The stamp has to commit to this peer's challenge, and we cannot grind
    // one before it has sent it. It is unsolicited and arrives right after
    // verack, so on a connection we have only just made it may be a tick
    // behind us — wait briefly rather than treat a fresh peer as one with
    // nothing to say.
    const challenge = await this.awaitChallenge(peer);
    if (!challenge) return undefined;

    const req = buildArchiveRequest(
      {
        cursor,
        limit: this.opts.limit,
        precision: this.opts.precision,
        scanBudget: this.opts.scanBudget,
        challenge,
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

  /** The peer's archive challenge, waiting a moment for one that is in flight. */
  private async awaitChallenge(peer: { archiveChallenge: Uint8Array | undefined }): Promise<Uint8Array | undefined> {
    const deadline = this.opts.now() + CHALLENGE_WAIT_MS;
    for (;;) {
      if (peer.archiveChallenge) return peer.archiveChallenge;
      if (this.opts.now() >= deadline) return undefined;
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  private async loadCursor(peerId: string, detectionKey: Uint8Array): Promise<bigint> {
    const raw = await this.o.store.get(NS, cursorKey(peerId, detectionKey));
    if (!raw) return 0n;
    try {
      const r = new Reader(raw);
      if (r.u8() !== 1) return 0n;
      return r.u64();
    } catch {
      return 0n;
    }
  }

  private saveCursor(peerId: string, detectionKey: Uint8Array, cursor: bigint): Promise<void> {
    return this.o.store.put(NS, cursorKey(peerId, detectionKey), new Writer().u8(1).u64(cursor).finish());
  }
}

/**
 * Cursors key on the peer's ADDRESS, not its connection id: an id is unique per
 * connection attempt, so keying on it would lose the cursor on every reconnect
 * and re-download the whole window. They also key on the detection key, so two
 * keys asking the same archive do not share a position in it.
 */
function cursorKey(peerId: string, detectionKey: Uint8Array): string {
  const hash = peerId.lastIndexOf('#');
  const addr = hash === -1 ? peerId : peerId.slice(0, hash);
  // 8 bytes of the key's hash: enough that two keys never collide in one
  // store, and short enough to keep the cursor key readable.
  let tag = '';
  for (const b of sha256(detectionKey).subarray(0, 8)) tag += b.toString(16).padStart(2, '0');
  return `${addr}/${tag}`;
}
