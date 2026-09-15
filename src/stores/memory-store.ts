import type { Store } from './store.js';

/** In-memory store. Default when the application supplies nothing. */
export class MemoryStore implements Store {
  private data = new Map<string, Map<string, Uint8Array>>();

  private ns(ns: string): Map<string, Uint8Array> {
    let m = this.data.get(ns);
    if (!m) {
      m = new Map();
      this.data.set(ns, m);
    }
    return m;
  }

  async get(ns: string, key: string): Promise<Uint8Array | undefined> {
    const v = this.ns(ns).get(key);
    return v ? v.slice() : undefined;
  }
  async put(ns: string, key: string, value: Uint8Array): Promise<void> {
    this.ns(ns).set(key, value.slice());
  }
  async delete(ns: string, key: string): Promise<void> {
    this.ns(ns).delete(key);
  }
  async list(ns: string, prefix = ''): Promise<Array<{ key: string; value: Uint8Array }>> {
    const out: Array<{ key: string; value: Uint8Array }> = [];
    for (const [key, value] of this.ns(ns)) {
      if (key.startsWith(prefix)) out.push({ key, value: value.slice() });
    }
    return out;
  }
}
