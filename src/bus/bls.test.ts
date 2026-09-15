import { describe, expect, it } from 'vitest';
import { fromHex, randomBytes, toHex, utf8 } from '../common/bytes.js';
import {
  BLS_ORDER,
  BROADCAST_PUBLIC,
  BROADCAST_SECRET,
  ecdh,
  generateSecret,
  isValidPublicKey,
  publicKey,
  scalarFromSeed,
  secretFromBytes,
  signAugmented,
  verifyAugmented,
} from './bls.js';

const G1_GEN = '97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb';

describe('bls keys', () => {
  it('secret 1 -> G1 generator (broadcast key)', () => {
    expect(toHex(BROADCAST_SECRET)).toBe('00'.repeat(31) + '01');
    expect(toHex(BROADCAST_PUBLIC)).toBe(G1_GEN);
    expect(toHex(publicKey(BROADCAST_SECRET))).toBe(G1_GEN);
  });

  it('generateSecret gives 32-byte in-range scalars with 48-byte pubkeys', () => {
    for (let i = 0; i < 5; i++) {
      const sk = generateSecret();
      expect(sk.length).toBe(32);
      expect(() => secretFromBytes(sk)).not.toThrow();
      const pk = publicKey(sk);
      expect(pk.length).toBe(48);
      expect(isValidPublicKey(pk)).toBe(true);
    }
  });

  it('secretFromBytes rejects zero / >= r / wrong length', () => {
    expect(() => secretFromBytes(new Uint8Array(32))).toThrow();
    expect(() => secretFromBytes(new Uint8Array(31))).toThrow();
    const r = BLS_ORDER;
    const rb = new Uint8Array(32);
    let v = r;
    for (let i = 31; i >= 0; i--) {
      rb[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    expect(() => secretFromBytes(rb)).toThrow();
    rb[31] -= 1; // r - 1 is valid
    expect(() => secretFromBytes(rb)).not.toThrow();
  });

  it('isValidPublicKey rejects infinity, garbage and bad lengths', () => {
    const inf = new Uint8Array(48);
    inf[0] = 0xc0;
    expect(isValidPublicKey(inf)).toBe(false);
    expect(isValidPublicKey(new Uint8Array(48))).toBe(false);
    expect(isValidPublicKey(new Uint8Array(47))).toBe(false);
    expect(isValidPublicKey(fromHex(G1_GEN))).toBe(true);
  });

  it('scalarFromSeed is deterministic and in range', () => {
    const seed = randomBytes(32);
    const a = scalarFromSeed(seed);
    expect(a).toEqual(scalarFromSeed(seed));
    expect(() => secretFromBytes(a)).not.toThrow();
    expect(() => secretFromBytes(scalarFromSeed(new Uint8Array(32)))).not.toThrow();
    expect(() => secretFromBytes(scalarFromSeed(new Uint8Array(64).fill(0xff)))).not.toThrow();
  });

  it('ecdh is symmetric', () => {
    const a = generateSecret();
    const b = generateSecret();
    const s1 = ecdh(a, publicKey(b));
    const s2 = ecdh(b, publicKey(a));
    expect(s1.length).toBe(48);
    expect(s1).toEqual(s2);
    // ecdh with the generator returns the public key itself
    expect(ecdh(a, BROADCAST_PUBLIC)).toEqual(publicKey(a));
  });
});

describe('bls signatures (augmented, POP DST)', () => {
  it('sign/verify round trip, 96-byte G2 signature', () => {
    const sk = generateSecret();
    const pk = publicKey(sk);
    const msg = utf8('hello p2pmsg');
    const sig = signAugmented(sk, msg);
    expect(sig.length).toBe(96);
    expect(verifyAugmented(pk, msg, sig)).toBe(true);
    expect(verifyAugmented(pk, utf8('hello p2pmsh'), sig)).toBe(false);
    expect(verifyAugmented(publicKey(generateSecret()), msg, sig)).toBe(false);
    const bad = sig.slice();
    bad[10] ^= 1;
    expect(verifyAugmented(pk, msg, bad)).toBe(false);
    expect(verifyAugmented(pk, msg, sig.subarray(0, 95))).toBe(false);
  });

  it('is deterministic and depends on the augmented pk', () => {
    const sk = generateSecret();
    const msg = utf8('x');
    expect(signAugmented(sk, msg)).toEqual(signAugmented(sk, msg));
    const inf = new Uint8Array(48);
    inf[0] = 0xc0;
    expect(verifyAugmented(inf, msg, signAugmented(sk, msg))).toBe(false);
  });

  it('prekey bundle shape: sig over prekey pub bytes', () => {
    const idSk = generateSecret();
    const preSk = generateSecret();
    const prePub = publicKey(preSk);
    const sig = signAugmented(idSk, prePub);
    expect(verifyAugmented(publicKey(idSk), prePub, sig)).toBe(true);
  });
});
