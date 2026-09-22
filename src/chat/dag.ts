/**
 * Causal ordering for a conversation.
 *
 * Every frame cites the ids of the messages its sender had seen — the heads of
 * its view — plus a Lamport counter one greater than the highest it knows.
 *
 * Why not sort by the sender's timestamp:
 *
 *  - **Gaps become detectable.** A cited parent we do not hold is a message we
 *    missed. Without this we never know, and "never know" is how a P2P chat
 *    quietly loses history.
 *  - Edits, reactions and deletes target a content hash rather than a
 *    position, so they are unambiguous even when they arrive first.
 *  - Two people typing at once is a fork, not a conflict, and renders as one.
 *  - Clock skew and lying clocks cannot reorder history. `timestamp` is a
 *    display hint and never a sort key on its own.
 */
import { compareBytes, MAX_PARENTS } from './frame.js';
import { toHex } from '../common/bytes.js';

export interface DagNode {
  id: Uint8Array; // 32
  lamport: bigint;
  timestamp: bigint;
  parents: Uint8Array[];
}

/** A cited parent we have never seen. */
export interface Gap {
  /** The missing message. */
  id: Uint8Array;
  /** Messages that cite it, i.e. the evidence it exists. */
  citedBy: Uint8Array[];
}

/**
 * In-memory view of one conversation's DAG. The persistent copy lives in the
 * `Store`; this is the index the ordering and gap queries run against.
 */
export class ConversationDag {
  private nodes = new Map<string, DagNode>();
  /** child ids by parent id, for the messages we do not hold yet. */
  private missing = new Map<string, Set<string>>();
  private childCount = new Map<string, number>();

  get size(): number {
    return this.nodes.size;
  }

  has(id: Uint8Array): boolean {
    return this.nodes.has(toHex(id));
  }

  get(id: Uint8Array): DagNode | undefined {
    return this.nodes.get(toHex(id));
  }

  all(): DagNode[] {
    return [...this.nodes.values()];
  }

  /** Insert a node. Idempotent, so a duplicate delivery costs nothing. */
  add(node: DagNode): boolean {
    const key = toHex(node.id);
    if (this.nodes.has(key)) return false;
    this.nodes.set(key, node);
    // This id may have been cited before it arrived; it is no longer missing.
    this.missing.delete(key);
    for (const p of node.parents) {
      const pk = toHex(p);
      this.childCount.set(pk, (this.childCount.get(pk) ?? 0) + 1);
      if (!this.nodes.has(pk)) {
        let set = this.missing.get(pk);
        if (!set) {
          set = new Set();
          this.missing.set(pk, set);
        }
        set.add(key);
      }
    }
    return true;
  }

  /**
   * Messages cited as parents that we do not hold. These are exactly the
   * messages worth asking a peer or an archive for.
   */
  gaps(): Gap[] {
    const out: Gap[] = [];
    for (const [id, children] of this.missing) {
      out.push({ id: unhex(id), citedBy: [...children].map(unhex) });
    }
    return out;
  }

  /** Current heads: messages nothing else cites. What the next send parents on. */
  heads(): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const [key, node] of this.nodes) {
      if (!this.childCount.get(key)) out.push(node.id);
    }
    // Deterministic and bounded: newest first, so a truncated parent list keeps
    // the most informative heads. `lamport` carries the ordering the dropped
    // ones would have.
    out.sort((a, b) => {
      const na = this.nodes.get(toHex(a))!;
      const nb = this.nodes.get(toHex(b))!;
      if (na.lamport !== nb.lamport) return na.lamport > nb.lamport ? -1 : 1;
      return compareBytes(a, b);
    });
    return out.slice(0, MAX_PARENTS);
  }

  /** Lamport value a new message should carry: one past everything we know. */
  nextLamport(): bigint {
    let max = 0n;
    for (const n of this.nodes.values()) if (n.lamport > max) max = n.lamport;
    return max + 1n;
  }

  /**
   * Display order: topological, ties broken by Lamport, then timestamp, then
   * id bytes.
   *
   * Fully deterministic — two devices showing the same conversation in
   * different orders is a bug users notice immediately.
   *
   * Missing parents do not block: a message whose parent we lack still sorts
   * by its Lamport value, so a gap leaves a hole rather than hiding everything
   * after it.
   */
  ordered(): DagNode[] {
    const nodes = [...this.nodes.values()];
    const byKey = new Map(nodes.map((n) => [toHex(n.id), n]));
    const indegree = new Map<string, number>();
    const children = new Map<string, string[]>();

    for (const n of nodes) {
      const key = toHex(n.id);
      let deg = 0;
      for (const p of n.parents) {
        const pk = toHex(p);
        if (!byKey.has(pk)) continue; // absent parent: cannot constrain us
        deg++;
        let cs = children.get(pk);
        if (!cs) {
          cs = [];
          children.set(pk, cs);
        }
        cs.push(key);
      }
      indegree.set(key, deg);
    }

    const cmp = (a: DagNode, b: DagNode): number => {
      if (a.lamport !== b.lamport) return a.lamport < b.lamport ? -1 : 1;
      if (a.timestamp !== b.timestamp) return a.timestamp < b.timestamp ? -1 : 1;
      return compareBytes(a.id, b.id);
    };

    const ready = nodes.filter((n) => (indegree.get(toHex(n.id)) ?? 0) === 0).sort(cmp);
    const out: DagNode[] = [];
    while (ready.length > 0) {
      const next = ready.shift()!;
      out.push(next);
      for (const childKey of children.get(toHex(next.id)) ?? []) {
        const left = (indegree.get(childKey) ?? 0) - 1;
        indegree.set(childKey, left);
        if (left === 0) insertSorted(ready, byKey.get(childKey)!, cmp);
      }
    }

    // A cycle is only possible from a forged frame (an id is a hash of its own
    // parents, so an honest one cannot cite a descendant). Append the
    // stragglers in deterministic order rather than dropping them silently.
    if (out.length !== nodes.length) {
      const seen = new Set(out.map((n) => toHex(n.id)));
      out.push(...nodes.filter((n) => !seen.has(toHex(n.id))).sort(cmp));
    }
    return out;
  }
}

function insertSorted(list: DagNode[], node: DagNode, cmp: (a: DagNode, b: DagNode) => number): void {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (cmp(list[mid]!, node) <= 0) lo = mid + 1;
    else hi = mid;
  }
  list.splice(lo, 0, node);
}

function unhex(h: string): Uint8Array {
  return new Uint8Array((h.match(/../g) ?? []).map((p) => parseInt(p, 16)));
}
