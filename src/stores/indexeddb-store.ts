import type { Store } from './store.js';

/**
 * Browser store on IndexedDB. One object store, composite key [ns, key].
 * Values are stored as Uint8Array (structured clone keeps them intact).
 */
export class IndexedDBStore implements Store {
  private constructor(private readonly db: IDBDatabase) {}

  static open(name = 'navio-p2pmsg'): Promise<IndexedDBStore> {
    return new Promise((resolve, reject) => {
      const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
      if (!idb) return reject(new Error('IndexedDB not available'));
      const req = idb.open(name, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore('kv', { keyPath: ['ns', 'key'] });
      };
      req.onsuccess = () => resolve(new IndexedDBStore(req.result));
      req.onerror = () => reject(req.error ?? new Error('indexedDB open failed'));
    });
  }

  private tx(mode: IDBTransactionMode): IDBObjectStore {
    return this.db.transaction('kv', mode).objectStore('kv');
  }

  private static wrap<T>(req: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('indexedDB request failed'));
    });
  }

  async get(ns: string, key: string): Promise<Uint8Array | undefined> {
    const row = (await IndexedDBStore.wrap(this.tx('readonly').get([ns, key]))) as
      | { value: Uint8Array }
      | undefined;
    return row ? new Uint8Array(row.value) : undefined;
  }
  async put(ns: string, key: string, value: Uint8Array): Promise<void> {
    await IndexedDBStore.wrap(this.tx('readwrite').put({ ns, key, value: value.slice() }));
  }
  async delete(ns: string, key: string): Promise<void> {
    await IndexedDBStore.wrap(this.tx('readwrite').delete([ns, key]));
  }
  async list(ns: string, prefix = ''): Promise<Array<{ key: string; value: Uint8Array }>> {
    const range = IDBKeyRange.bound([ns, prefix], [ns, prefix + '￿']);
    const rows = (await IndexedDBStore.wrap(this.tx('readonly').getAll(range))) as Array<{
      key: string;
      value: Uint8Array;
    }>;
    return rows.map((r) => ({ key: r.key, value: new Uint8Array(r.value) }));
  }
  async close(): Promise<void> {
    this.db.close();
  }
}
