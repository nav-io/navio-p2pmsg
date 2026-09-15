/**
 * Minimal persistence interface. The library serialises its own records to
 * bytes; the application decides where they live. Namespaces keep record
 * families apart (e.g. "keys", "contacts", "outbox").
 */
export interface Store {
  get(ns: string, key: string): Promise<Uint8Array | undefined>;
  put(ns: string, key: string, value: Uint8Array): Promise<void>;
  delete(ns: string, key: string): Promise<void>;
  /** All entries in a namespace, optionally restricted to a key prefix. */
  list(ns: string, prefix?: string): Promise<Array<{ key: string; value: Uint8Array }>>;
  /** Flush pending writes (no-op for synchronous backends). */
  flush?(): Promise<void>;
  close?(): Promise<void>;
}

/** Snapshot of every namespace, used by exportState/importState. */
export type StoreSnapshot = Record<string, Record<string, string>>; // ns -> key -> hex

export async function snapshotStore(store: Store, namespaces: string[]): Promise<StoreSnapshot> {
  const out: StoreSnapshot = {};
  for (const ns of namespaces) {
    out[ns] = {};
    for (const { key, value } of await store.list(ns)) out[ns]![key] = hex(value);
  }
  return out;
}

export async function restoreStore(store: Store, snap: StoreSnapshot): Promise<void> {
  for (const [ns, entries] of Object.entries(snap)) {
    for (const [key, value] of Object.entries(entries)) await store.put(ns, key, unhex(value));
  }
}

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
function unhex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
