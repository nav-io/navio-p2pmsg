import { afterAll, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryStore } from './memory-store.js';
import { FileStore } from './file-store.js';
import { restoreStore, snapshotStore } from './store.js';

const dir = mkdtempSync(join(tmpdir(), 'p2pmsg-store-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('MemoryStore', () => {
  it('put/get/list/delete with prefix', async () => {
    const s = new MemoryStore();
    await s.put('a', 'x1', new Uint8Array([1]));
    await s.put('a', 'x2', new Uint8Array([2]));
    await s.put('a', 'y1', new Uint8Array([3]));
    expect(await s.get('a', 'x1')).toEqual(new Uint8Array([1]));
    expect((await s.list('a', 'x')).map((e) => e.key).sort()).toEqual(['x1', 'x2']);
    await s.delete('a', 'x1');
    expect(await s.get('a', 'x1')).toBeUndefined();
    expect(await s.list('b')).toEqual([]);
  });
  it('snapshot/restore', async () => {
    const s = new MemoryStore();
    await s.put('k', 'id', new Uint8Array([9, 8]));
    const snap = await snapshotStore(s, ['k', 'empty']);
    const t = new MemoryStore();
    await restoreStore(t, snap);
    expect(await t.get('k', 'id')).toEqual(new Uint8Array([9, 8]));
  });
});

describe('FileStore', () => {
  it('persists across reopen', async () => {
    const p = join(dir, 'store.json');
    const s = await FileStore.open(p, { debounceMs: 5 });
    await s.put('keys', 'seed', new Uint8Array([0xde, 0xad]));
    await s.put('outbox', 'm1', new Uint8Array([1]));
    await s.delete('outbox', 'm1');
    await s.close();
    const r = await FileStore.open(p);
    expect(await r.get('keys', 'seed')).toEqual(new Uint8Array([0xde, 0xad]));
    expect(await r.get('outbox', 'm1')).toBeUndefined();
  });
});
