/** Bounded LRU set of envelope keys, held as hex. */
import { toHex } from '../common/bytes.js';

export const DEFAULT_REPLAY_CAPACITY = 65536;

export class ReplayCache {
  private readonly map = new Map<string, true>();

  constructor(public readonly capacity: number = DEFAULT_REPLAY_CAPACITY) {
    if (!(capacity > 0)) throw new Error('capacity must be positive');
  }

  get size(): number {
    return this.map.size;
  }

  has(key: Uint8Array): boolean {
    return this.map.has(toHex(key));
  }

  /** Insert `key`. Returns true if it was NOT already present (i.e. first sighting). */
  add(key: Uint8Array): boolean {
    const k = toHex(key);
    if (this.map.has(k)) {
      // refresh recency
      this.map.delete(k);
      this.map.set(k, true);
      return false;
    }
    this.map.set(k, true);
    while (this.map.size > this.capacity) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
    return true;
  }

  delete(key: Uint8Array): boolean {
    return this.map.delete(toHex(key));
  }

  clear(): void {
    this.map.clear();
  }
}
