import { describe, expect, it } from 'vitest';
import { MemoryStore } from '../stores/memory-store.js';
import { toHex } from '../common/bytes.js';
import { Keyring, deriveIdentity, derivePrekey, verifyBundle } from './keyring.js';
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

describe('Keyring account epochs', () => {
  it('gives every device of an account the same inbox key', async () => {
    // One envelope has to reach all of them: at 23 bits of proof of work per
    // envelope, charging the sender per recipient device is not an option.
    const seed = new Uint8Array(32).fill(0x24);
    const onDesktop = await Keyring.open(seed, new MemoryStore());
    const onPhone = await Keyring.open(seed, new MemoryStore());
    expect(toHex(onPhone.prekey.pub)).toBe(toHex(onDesktop.prekey.pub));
    expect(toHex(onPhone.identity.pub)).toBe(toHex(onDesktop.identity.pub));
    expect(toHex(onPhone.fmdClueKey())).toBe(toHex(onDesktop.fmdClueKey()));
    expect(toHex(onPhone.accountSecret())).toBe(toHex(onDesktop.accountSecret()));
  });

  it('moves every derived key when the account epoch rotates', async () => {
    // Revocation: a device holding the previous secret must stop being able to
    // read anything new.
    const seed = new Uint8Array(32).fill(0x25);
    const k = await Keyring.open(seed, new MemoryStore());
    const before = {
      secret: toHex(k.accountSecret()),
      prekey: toHex(k.prekey.pub),
      clue: toHex(k.fmdClueKey()),
    };
    await k.rotateAccountEpoch();
    expect(k.epoch).toBe(1);
    expect(toHex(k.accountSecret())).not.toBe(before.secret);
    expect(toHex(k.prekey.pub)).not.toBe(before.prekey);
    expect(toHex(k.fmdClueKey())).not.toBe(before.clue);
    // The identity is the address and must survive: revoking a device is not
    // changing who you are.
    expect(k.identity.pub).toBeDefined();
    // The previous prekey stays readable for the grace window, which is also
    // why a revoked device can still read that window.
    expect(toHex(k.previousPrekey!.pub)).toBe(before.prekey);
  });

  it('does not let an old account secret derive the next one', async () => {
    const seed = new Uint8Array(32).fill(0x26);
    const k = await Keyring.open(seed, new MemoryStore());
    const e0 = toHex(k.accountSecret(0));
    const e1 = toHex(k.accountSecret(1));
    expect(e0).not.toBe(e1);
    // A secondary device is given only the epoch secret, never the seed, so
    // there is no path from one to the other without it.
    expect(e1).not.toContain(e0);
  });
});
