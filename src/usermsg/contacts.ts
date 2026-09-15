/**
 * Contact book: what we know about a remote identity — its verified prekey
 * bundle and the single-use reply key it last handed us. Persisted in Store
 * namespace "contacts".
 */
import type { Store } from '../stores/store.js';
import { Reader, Writer } from '../common/serialize.js';
import { toHex } from '../common/bytes.js';
import { type Bundle, parseBundle, serializeBundle } from './bundle.js';

export interface Contact {
  identity: Uint8Array; // 48
  bundle?: Bundle; // verified
  bundleAt?: number; // ms when learned
  /** Reply key the contact sent us most recently; use once then drop. */
  nextKey?: Uint8Array; // 48
  nextKeyAt?: number;
  lastSeenAt?: number;
}

const NS = 'contacts';

export class Contacts {
  private map = new Map<string, Contact>();
  constructor(
    private readonly store: Store,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async load(): Promise<void> {
    for (const { value } of await this.store.list(NS)) {
      const c = decode(value);
      this.map.set(toHex(c.identity), c);
    }
  }

  get(identity: Uint8Array): Contact | undefined {
    return this.map.get(toHex(identity));
  }

  all(): Contact[] {
    return [...this.map.values()];
  }

  private async upsert(identity: Uint8Array, patch: (c: Contact) => void): Promise<Contact> {
    const k = toHex(identity);
    let c = this.map.get(k);
    if (!c) {
      c = { identity: identity.slice() };
      this.map.set(k, c);
    }
    patch(c);
    await this.store.put(NS, k, encode(c));
    return c;
  }

  /** Record a verified bundle (caller verifies prekey_sig first). */
  setBundle(bundle: Bundle): Promise<Contact> {
    return this.upsert(bundle.identity, (c) => {
      c.bundle = bundle;
      c.bundleAt = this.now();
    });
  }

  /** Remember the reply key a contact offered in its latest message. */
  setNextKey(identity: Uint8Array, key: Uint8Array): Promise<Contact> {
    return this.upsert(identity, (c) => {
      c.nextKey = key.slice();
      c.nextKeyAt = this.now();
      c.lastSeenAt = this.now();
    });
  }

  touch(identity: Uint8Array): Promise<Contact> {
    return this.upsert(identity, (c) => {
      c.lastSeenAt = this.now();
    });
  }

  /**
   * Take the one-shot reply key if present (and not older than maxAgeMs),
   * clearing it. Returns undefined when the caller must fall back to the prekey.
   */
  async takeNextKey(identity: Uint8Array, maxAgeMs = 7 * 24 * 3600 * 1000): Promise<Uint8Array | undefined> {
    const c = this.map.get(toHex(identity));
    if (!c?.nextKey) return undefined;
    const key = c.nextKey;
    const fresh = (c.nextKeyAt ?? 0) + maxAgeMs > this.now();
    await this.upsert(identity, (x) => {
      x.nextKey = undefined;
      x.nextKeyAt = undefined;
    });
    return fresh ? key : undefined;
  }

  /** Forget a contact's bundle (e.g. after repeated decrypt failures) so discovery runs again. */
  clearBundle(identity: Uint8Array): Promise<Contact> {
    return this.upsert(identity, (c) => {
      c.bundle = undefined;
      c.bundleAt = undefined;
    });
  }

  async remove(identity: Uint8Array): Promise<void> {
    const k = toHex(identity);
    if (this.map.delete(k)) await this.store.delete(NS, k);
  }
}

function encode(c: Contact): Uint8Array {
  const w = new Writer().u8(1).bytes(c.identity);
  w.u8(c.bundle ? 1 : 0);
  if (c.bundle) w.bytes(serializeBundle(c.bundle)).i64(BigInt(c.bundleAt ?? 0));
  w.u8(c.nextKey ? 1 : 0);
  if (c.nextKey) w.bytes(c.nextKey).i64(BigInt(c.nextKeyAt ?? 0));
  w.i64(BigInt(c.lastSeenAt ?? 0));
  return w.finish();
}

function decode(b: Uint8Array): Contact {
  const r = new Reader(b);
  if (r.u8() !== 1) throw new Error('bad contact record version');
  const c: Contact = { identity: r.bytes(48) };
  if (r.u8() === 1) {
    c.bundle = parseBundle(r.bytes(192));
    c.bundleAt = Number(r.i64());
  }
  if (r.u8() === 1) {
    c.nextKey = r.bytes(48);
    c.nextKeyAt = Number(r.i64());
  }
  const seen = Number(r.i64());
  if (seen) c.lastSeenAt = seen;
  r.assertDone();
  return c;
}
