import { describe, expect, it } from 'vitest';
import { Contacts } from './contacts.js';
import { MemoryStore } from '../stores/memory-store.js';

describe('contacts', () => {
  it('stores bundles and one-shot reply keys, persists', async () => {
    let now = 1000;
    const store = new MemoryStore();
    const c = new Contacts(store, () => now);
    const id = new Uint8Array(48).fill(1);
    const bundle = { identity: id, prekey: new Uint8Array(48).fill(2), prekeySig: new Uint8Array(96).fill(3) };
    await c.setBundle(bundle);
    await c.setNextKey(id, new Uint8Array(48).fill(4));
    const c2 = new Contacts(store, () => now);
    await c2.load();
    expect(c2.get(id)?.bundle).toEqual(bundle);
    expect(c2.get(id)?.lastSeenAt).toBe(1000);
    expect(await c2.takeNextKey(id)).toEqual(new Uint8Array(48).fill(4));
    expect(await c2.takeNextKey(id)).toBeUndefined();
    await c2.setNextKey(id, new Uint8Array(48).fill(5));
    now += 8 * 24 * 3600 * 1000;
    expect(await c2.takeNextKey(id)).toBeUndefined(); // stale
    await c2.clearBundle(id);
    expect(c2.get(id)?.bundle).toBeUndefined();
    await c2.remove(id);
    expect(c2.all()).toEqual([]);
    expect(await store.list('contacts')).toEqual([]);
  });
});
