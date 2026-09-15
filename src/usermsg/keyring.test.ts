import { describe, expect, it } from 'vitest';
import { Keyring, deriveIdentity, derivePrekey, verifyBundle } from './keyring.js';
import { MemoryStore } from '../stores/memory-store.js';
import { signAuthFrame, verifyAuthFrame } from './auth.js';
import { parseAuthFrame } from './frame.js';
import { decodeBundle, encodeBundle } from './bundle.js';
import { isValidPublicKey } from '../bus/bls.js';

const seed = new Uint8Array(32).map((_, i) => i * 7 + 1);

describe('keyring', () => {
  it('derives deterministically and rotates with grace', async () => {
    const store = new MemoryStore();
    const k = await Keyring.open(seed, store);
    expect(k.identity.pub).toEqual(deriveIdentity(seed).pub);
    expect(k.prekey.pub).toEqual(derivePrekey(seed, 0).pub);
    expect(isValidPublicKey(k.identity.pub)).toBe(true);
    expect(k.previousPrekey).toBeUndefined();
    const b = k.bundle();
    expect(verifyBundle(b)).toBe(true);
    expect(verifyBundle({ ...b, prekey: k.identity.pub })).toBe(false);
    expect(verifyBundle(decodeBundle(encodeBundle(b)))).toBe(true);
    await k.rotatePrekey();
    expect(k.epoch).toBe(1);
    expect(k.previousPrekey?.pub).toEqual(derivePrekey(seed, 0).pub);
    expect(k.prekey.pub).toEqual(derivePrekey(seed, 1).pub);
    const k2 = await Keyring.open(seed, store);
    expect(k2.epoch).toBe(1);
    expect(k2.prekey.pub).toEqual(k.prekey.pub);
    expect(k2.previousPrekey?.pub).toEqual(derivePrekey(seed, 0).pub);
  });
  it('different seeds give different identities', () => {
    const other = new Uint8Array(32).fill(9);
    expect(deriveIdentity(other).pub).not.toEqual(deriveIdentity(seed).pub);
  });
});

describe('auth frames', () => {
  it('signs and verifies, binding topic and recipient', async () => {
    const k = await Keyring.open(seed, new MemoryStore());
    const recipient = derivePrekey(new Uint8Array(32).fill(1), 0).pub;
    const bytes = signAuthFrame(
      { msgId: new Uint8Array(16).fill(5), timestamp: 42n, payload: new Uint8Array([1, 2, 3]) },
      k.identity,
      'chat',
      recipient,
    );
    const f = parseAuthFrame(bytes);
    expect(f.sender).toEqual(k.identity.pub);
    expect(verifyAuthFrame(f, 'chat', recipient)).toBe(true);
    expect(verifyAuthFrame(f, 'other', recipient)).toBe(false);
    expect(verifyAuthFrame(f, 'chat', new Uint8Array(48))).toBe(false);
    f.payload = new Uint8Array([9]);
    expect(verifyAuthFrame(f, 'chat', recipient)).toBe(false);
  });
});
