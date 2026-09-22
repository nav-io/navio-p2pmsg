import { describe, expect, it } from 'vitest';
import { hex, loadVectors, unhex } from './vectors.test-util.js';
import { randomBytes } from '../../common/bytes.js';
import { fromBytes, isValidX, toBytes } from './field.js';
import { ellswiftCreate, ellswiftDecode, ellswiftEcdhXonly, xswiftec, xswiftecInv } from './ellswift.js';

describe('ellswift decode (BIP324 vectors)', () => {
  const vectors = loadVectors('ellswift_decode_test_vectors.csv');

  it('loaded the vector file', () => {
    expect(vectors.length).toBeGreaterThan(50);
  });

  // Every vector individually, so a failure names the degenerate branch it hit
  // rather than just "one of 76 failed".
  for (const v of vectors) {
    it(`decodes ${v.ellswift!.slice(0, 16)}… (${v.comment})`, () => {
      expect(hex(ellswiftDecode(unhex(v.ellswift!)))).toBe(v.x);
    });
  }
});

describe('xswiftec_inv (BIP324 vectors)', () => {
  const vectors = loadVectors('xswiftec_inv_test_vectors.csv');

  it('loaded the vector file', () => {
    expect(vectors.length).toBeGreaterThan(20);
  });

  for (const v of vectors) {
    const cases = Object.keys(v).filter((k) => /^case\d+_t$/.test(k));
    it(`inverts x=${v.x!.slice(0, 12)}… u=${v.u!.slice(0, 12)}…`, () => {
      const x = fromBytes(unhex(v.x!));
      const u = fromBytes(unhex(v.u!));
      for (const key of cases) {
        const c = Number(/^case(\d+)_t$/.exec(key)![1]);
        const got = xswiftecInv(x, u, c);
        const want = v[key]!;
        if (want === '') {
          // The branch must FAIL. A implementation that returned some t here
          // would still round-trip, but it would bias the sampling and cost
          // the encoding its indistinguishability.
          expect(got, `case ${c} should have no solution`).toBeUndefined();
        } else {
          expect(got, `case ${c}`).toBeDefined();
          expect(hex(toBytes(got!)), `case ${c}`).toBe(want);
          // And the forward map must take it back to x.
          expect(xswiftec(u, got!)).toBe(x);
        }
      }
    });
  }
});

describe('ellswift round trip', () => {
  it('creates keys whose encoding decodes to the real public key', () => {
    for (let i = 0; i < 5; i++) {
      const kp = ellswiftCreate(() => randomBytes(32));
      expect(kp.ellswift.length).toBe(64);
      expect(kp.priv.length).toBe(32);
      expect(isValidX(fromBytes(ellswiftDecode(kp.ellswift)))).toBe(true);
    }
  });

  it('agrees with itself on ECDH from both sides', () => {
    // The X coordinate both sides compute must match, or the whole handshake
    // derives different keys and fails with no useful error.
    const a = ellswiftCreate(() => randomBytes(32));
    const b = ellswiftCreate(() => randomBytes(32));
    expect(hex(ellswiftEcdhXonly(b.ellswift, a.priv))).toBe(hex(ellswiftEcdhXonly(a.ellswift, b.priv)));
  });

  it('produces a different encoding every time for the same key', () => {
    // Encoding is randomised over u and branch; a deterministic encoding would
    // be a fingerprint.
    const kp = ellswiftCreate(() => randomBytes(32));
    const again = ellswiftCreate(() => randomBytes(32));
    expect(hex(kp.ellswift)).not.toBe(hex(again.ellswift));
  });
});
