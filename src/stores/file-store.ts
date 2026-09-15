import type { Store } from './store.js';
import { MemoryStore } from './memory-store.js';
import { fromHex, toHex } from '../common/bytes.js';

/**
 * Node-only store persisting to a single JSON file. Writes are coalesced and
 * flushed atomically (write temp file, rename). Good enough for a client's
 * keys, contacts and outbox; not a database.
 */
export class FileStore implements Store {
  private mem = new MemoryStore();
  private namespaces = new Set<string>();
  private dirty = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private writing: Promise<void> = Promise.resolve();

  private constructor(
    private readonly path: string,
    private readonly debounceMs: number,
  ) {}

  static async open(path: string, opts: { debounceMs?: number } = {}): Promise<FileStore> {
    const fs = await import('node:fs/promises');
    const store = new FileStore(path, opts.debounceMs ?? 250);
    try {
      const raw = await fs.readFile(path, 'utf8');
      const parsed = JSON.parse(raw) as Record<string, Record<string, string>>;
      for (const [ns, entries] of Object.entries(parsed)) {
        store.namespaces.add(ns);
        for (const [key, hex] of Object.entries(entries)) await store.mem.put(ns, key, fromHex(hex));
      }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
    return store;
  }

  get(ns: string, key: string): Promise<Uint8Array | undefined> {
    return this.mem.get(ns, key);
  }
  async put(ns: string, key: string, value: Uint8Array): Promise<void> {
    this.namespaces.add(ns);
    await this.mem.put(ns, key, value);
    this.schedule();
  }
  async delete(ns: string, key: string): Promise<void> {
    await this.mem.delete(ns, key);
    this.schedule();
  }
  list(ns: string, prefix?: string): Promise<Array<{ key: string; value: Uint8Array }>> {
    return this.mem.list(ns, prefix);
  }

  private schedule(): void {
    this.dirty = true;
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, this.debounceMs);
  }

  async flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.dirty) {
      this.dirty = false;
      this.writing = this.writing.then(() => this.writeNow());
    }
    return this.writing;
  }

  private async writeNow(): Promise<void> {
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    const snap: Record<string, Record<string, string>> = {};
    for (const ns of this.namespaces) {
      snap[ns] = {};
      for (const { key, value } of await this.mem.list(ns)) snap[ns]![key] = toHex(value);
    }
    await fs.mkdir(path.dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(snap), { mode: 0o600 });
    await fs.rename(tmp, this.path);
  }

  async close(): Promise<void> {
    await this.flush();
  }
}
