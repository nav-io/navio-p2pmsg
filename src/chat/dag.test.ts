import { describe, expect, it } from 'vitest';
import { toHex } from '../common/bytes.js';
import { ConversationDag, type DagNode } from './dag.js';

const id = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const ids = (...ns: number[]): Uint8Array[] => ns.map(id);

function node(n: number, lamport: number, parents: number[] = [], timestamp = 0): DagNode {
  return { id: id(n), lamport: BigInt(lamport), timestamp: BigInt(timestamp), parents: ids(...parents) };
}

const order = (dag: ConversationDag): number[] => dag.ordered().map((n) => n.id[0]!);

describe('ConversationDag', () => {
  it('orders a simple chain', () => {
    const dag = new ConversationDag();
    dag.add(node(3, 3, [2]));
    dag.add(node(1, 1));
    dag.add(node(2, 2, [1]));
    expect(order(dag)).toEqual([1, 2, 3]);
  });

  it('is insertion-order independent', () => {
    // Two devices receiving the same messages in different orders must render
    // the same conversation, or users notice immediately.
    const build = (seq: DagNode[]): number[] => {
      const d = new ConversationDag();
      for (const n of seq) d.add(n);
      return order(d);
    };
    const a = node(1, 1);
    const b = node(2, 2, [1]);
    const c = node(3, 3, [2]);
    const d = node(4, 3, [2]); // concurrent with c
    const expected = build([a, b, c, d]);
    expect(build([d, c, b, a])).toEqual(expected);
    expect(build([c, a, d, b])).toEqual(expected);
    expect(build([b, d, a, c])).toEqual(expected);
  });

  it('never places a message before one it cites', () => {
    const dag = new ConversationDag();
    dag.add(node(9, 9, [5]));
    dag.add(node(5, 5, [1]));
    dag.add(node(1, 1));
    const seq = order(dag);
    expect(seq.indexOf(1)).toBeLessThan(seq.indexOf(5));
    expect(seq.indexOf(5)).toBeLessThan(seq.indexOf(9));
  });

  it('breaks ties deterministically by lamport, then timestamp, then id', () => {
    const dag = new ConversationDag();
    dag.add({ id: id(7), lamport: 5n, timestamp: 100n, parents: [] });
    dag.add({ id: id(2), lamport: 5n, timestamp: 100n, parents: [] });
    dag.add({ id: id(9), lamport: 5n, timestamp: 50n, parents: [] });
    dag.add({ id: id(1), lamport: 4n, timestamp: 999n, parents: [] });
    // lamport 4 first despite the latest timestamp; then lamport 5 ordered by
    // timestamp; then by id bytes.
    expect(order(dag)).toEqual([1, 9, 2, 7]);
  });

  it('reports a cited parent it does not hold as a gap', () => {
    // This is the property the whole design exists for: without it a client
    // cannot tell "nothing was said" from "something was lost".
    const dag = new ConversationDag();
    dag.add(node(5, 5, [4]));
    const gaps = dag.gaps();
    expect(gaps).toHaveLength(1);
    expect(toHex(gaps[0]!.id)).toBe(toHex(id(4)));
    expect(gaps[0]!.citedBy.map((c) => c[0])).toEqual([5]);
  });

  it('clears a gap when the missing message arrives', () => {
    const dag = new ConversationDag();
    dag.add(node(5, 5, [4]));
    expect(dag.gaps()).toHaveLength(1);
    dag.add(node(4, 4));
    expect(dag.gaps()).toHaveLength(0);
    expect(order(dag)).toEqual([4, 5]);
  });

  it('records every citer of the same missing message', () => {
    const dag = new ConversationDag();
    dag.add(node(5, 5, [4]));
    dag.add(node(6, 6, [4]));
    const gaps = dag.gaps();
    expect(gaps).toHaveLength(1);
    expect(gaps[0]!.citedBy.map((c) => c[0]).sort()).toEqual([5, 6]);
  });

  it('still orders messages whose parents are missing', () => {
    // A gap must leave a hole, not hide everything after it.
    const dag = new ConversationDag();
    dag.add(node(1, 1));
    dag.add(node(8, 8, [7])); // 7 never arrives
    expect(order(dag)).toEqual([1, 8]);
  });

  it('tracks heads and bounds them to the parent limit', () => {
    const dag = new ConversationDag();
    dag.add(node(1, 1));
    expect(dag.heads().map((h) => h[0])).toEqual([1]);
    dag.add(node(2, 2, [1]));
    // 1 is now cited, so only 2 is a head.
    expect(dag.heads().map((h) => h[0])).toEqual([2]);

    const wide = new ConversationDag();
    for (let i = 1; i <= 6; i++) wide.add(node(i, i));
    const heads = wide.heads();
    expect(heads).toHaveLength(4); // MAX_PARENTS
    // Newest first, so a truncated list keeps the most informative heads.
    expect(heads.map((h) => h[0])).toEqual([6, 5, 4, 3]);
  });

  it('advances lamport past everything it knows', () => {
    const dag = new ConversationDag();
    expect(dag.nextLamport()).toBe(1n);
    dag.add(node(1, 1));
    dag.add(node(2, 7));
    expect(dag.nextLamport()).toBe(8n);
  });

  it('treats a duplicate as a no-op', () => {
    const dag = new ConversationDag();
    expect(dag.add(node(1, 1))).toBe(true);
    expect(dag.add(node(1, 1))).toBe(false);
    expect(dag.size).toBe(1);
    expect(dag.heads()).toHaveLength(1);
  });

  it('handles a fork and merge', () => {
    const dag = new ConversationDag();
    dag.add(node(1, 1));
    dag.add(node(2, 2, [1]));
    dag.add(node(3, 2, [1])); // concurrent with 2
    dag.add(node(4, 3, [2, 3])); // merge
    const seq = order(dag);
    expect(seq[0]).toBe(1);
    expect(seq[3]).toBe(4);
    expect(seq.slice(1, 3).sort()).toEqual([2, 3]);
    expect(dag.heads().map((h) => h[0])).toEqual([4]);
  });

  it('does not hang on a forged cycle', () => {
    // An honest id is a hash over its own parents, so a cycle cannot occur by
    // accident. A forged frame must not wedge the sort.
    const dag = new ConversationDag();
    dag.add(node(1, 1, [2]));
    dag.add(node(2, 2, [1]));
    expect(dag.ordered()).toHaveLength(2);
  });
});
