import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { randomBytes } from '../common/bytes.js';
import { Reader } from '../common/serialize.js';
import {
  checkPoW,
  checkTimestamp,
  grindSync,
  hashMeetsTarget,
  POW_HEADER_SIZE,
  type PoWHeader,
  PowMidstate,
  parsePoWHeader,
  powHash,
  serializePoWHeader,
  withNonce,
} from './pow.js';

function randomHeader(nonce = 0n): PoWHeader {
  return {
    version: 1,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    kind: 7,
    sessionEph: randomBytes(48),
    payloadHash: randomBytes(32),
    nonce,
  };
}

describe('hashMeetsTarget (little-endian UintToArith256 semantics)', () => {
  it('bits=8 requires the LAST byte to be zero', () => {
    const h = new Uint8Array(32).fill(0xff);
    h[31] = 0;
    expect(hashMeetsTarget(h, 8)).toBe(true);
    h[31] = 1;
    expect(hashMeetsTarget(h, 8)).toBe(false);
    // leading zero bytes at the front do not help
    const front = new Uint8Array(32).fill(0xff);
    front[0] = 0;
    expect(hashMeetsTarget(front, 8)).toBe(false);
  });

  it('bits=12 requires byte 31 == 0 and the high nibble of byte 30 == 0', () => {
    const h = new Uint8Array(32).fill(0xff);
    h[31] = 0;
    h[30] = 0x0f;
    expect(hashMeetsTarget(h, 12)).toBe(true);
    h[30] = 0x10;
    expect(hashMeetsTarget(h, 12)).toBe(false);
    h[30] = 0x0f;
    h[31] = 0x01;
    expect(hashMeetsTarget(h, 12)).toBe(false);
  });

  it('bits=1 / bits=7 partial-byte boundaries', () => {
    const h = new Uint8Array(32).fill(0xff);
    h[31] = 0x7f;
    expect(hashMeetsTarget(h, 1)).toBe(true);
    expect(hashMeetsTarget(h, 2)).toBe(false);
    h[31] = 0x01;
    expect(hashMeetsTarget(h, 7)).toBe(true);
    expect(hashMeetsTarget(h, 8)).toBe(false);
  });

  it('bits=0 accepts anything; bits>=256 only the zero hash; 40 bits spans 5 bytes', () => {
    expect(hashMeetsTarget(new Uint8Array(32).fill(0xff), 0)).toBe(true);
    expect(hashMeetsTarget(new Uint8Array(32), 256)).toBe(true);
    expect(hashMeetsTarget(new Uint8Array(32), 300)).toBe(true);
    const one = new Uint8Array(32);
    one[0] = 1;
    expect(hashMeetsTarget(one, 256)).toBe(false);
    const h = new Uint8Array(32).fill(0xff);
    for (let i = 27; i < 32; i++) h[i] = 0;
    expect(hashMeetsTarget(h, 40)).toBe(true);
    h[27] = 1;
    expect(hashMeetsTarget(h, 40)).toBe(false);
  });

  it('agrees with a bigint reference implementation', () => {
    const target = (bits: number) => ((1n << 256n) - 1n) >> BigInt(bits);
    const le = (h: Uint8Array) => {
      let n = 0n;
      for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(h[i]!);
      return n;
    };
    for (let t = 0; t < 200; t++) {
      const h = randomBytes(32);
      const zero = Math.floor(Math.random() * 4);
      for (let i = 0; i < zero; i++) h[31 - i] = 0;
      if (Math.random() < 0.5) h[31 - zero] = h[31 - zero]! >>> Math.floor(Math.random() * 8);
      for (const bits of [0, 1, 5, 8, 9, 12, 16, 17, 23, 24, 31, 32, 33]) {
        expect(hashMeetsTarget(h, bits)).toBe(le(h) <= target(bits));
      }
    }
  });
});

describe('PoWHeader serialisation', () => {
  it('is exactly 98 bytes and round-trips', () => {
    const h = randomHeader(0x0123456789abcdefn);
    h.timestamp = -5n;
    const bytes = serializePoWHeader(h);
    expect(bytes.length).toBe(POW_HEADER_SIZE);
    expect(bytes[0]).toBe(1);
    expect(bytes[9]).toBe(7);
    const r = new Reader(bytes);
    const back = parsePoWHeader(r);
    r.assertDone();
    expect(back).toEqual(h);
    // nonce is little-endian u64 at 90..97
    expect(Array.from(bytes.subarray(90))).toEqual([0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
  });

  it('powHash is a single sha256 over the bytes', () => {
    const h = randomHeader(42n);
    expect(powHash(h)).toEqual(sha256(serializePoWHeader(h)));
  });
});

describe('midstate hasher', () => {
  it('matches powHash for random headers and nonces (incl. 64-bit wrap)', () => {
    for (let t = 0; t < 50; t++) {
      const h = randomHeader();
      const mid = new PowMidstate(serializePoWHeader(h));
      for (const nonce of [0n, 1n, 255n, 0x1_0000_0000n - 1n, 0x1_0000_0000n, 0xffff_ffff_ffff_ffffn, BigInt(Math.floor(Math.random() * 2 ** 52))]) {
        expect(mid.hashWithNonce(nonce)).toEqual(powHash(withNonce(h, nonce)));
      }
    }
  });

  it('search with stride visits only the arithmetic progression', () => {
    const h = randomHeader();
    const mid = new PowMidstate(serializePoWHeader(h));
    const n = mid.search(3n, 4, 6, 100_000);
    expect(n).not.toBeNull();
    expect((n! - 3n) % 4n).toBe(0n);
    expect(checkPoW(withNonce(h, n!), 6)).toBe(true);
    // nothing in [3, 3+4k) with k < index should have matched
    for (let x = 3n; x < n!; x += 4n) expect(checkPoW(withNonce(h, x), 6)).toBe(false);
  });
});

describe('grindSync / checkPoW', () => {
  it('finds a nonce for bits 8..16 that checkPoW accepts', () => {
    for (const bits of [8, 10, 12, 14, 16]) {
      const h = randomHeader();
      const nonce = grindSync(h, bits);
      expect(nonce).not.toBeNull();
      const stamped = withNonce(h, nonce!);
      expect(checkPoW(stamped, bits)).toBe(true);
      expect(hashMeetsTarget(powHash(stamped), bits)).toBe(true);
    }
  });

  it('honours maxIters and startNonce', () => {
    const h = randomHeader();
    expect(grindSync(h, 60, { maxIters: 10 })).toBeNull();
    const n = grindSync(h, 4, { startNonce: 1000n })!;
    expect(n).toBeGreaterThanOrEqual(1000n);
  });

  it('measures hash rate', () => {
    const h = randomHeader();
    const mid = new PowMidstate(serializePoWHeader(h));
    const N = 300_000;
    const t0 = performance.now();
    mid.search(0n, 1, 200, N); // unattainable target => exactly N attempts
    const dt = (performance.now() - t0) / 1000;
    const rate = Math.round(N / dt);
    // eslint-disable-next-line no-console
    console.log(`midstate grind: ${rate} H/s`);
    // Loose bound: CI boxes and loaded machines vary wildly; this only guards against a pathological regression.
    expect(rate).toBeGreaterThan(20_000);
  });
});

describe('checkTimestamp', () => {
  it('accepts within +/-120s and rejects outside', () => {
    const h = randomHeader();
    h.timestamp = 1000n;
    expect(checkTimestamp(h, 1000)).toBe(true);
    expect(checkTimestamp(h, 1120)).toBe(true);
    expect(checkTimestamp(h, 880)).toBe(true);
    expect(checkTimestamp(h, 1121)).toBe(false);
    expect(checkTimestamp(h, 879)).toBe(false);
    expect(checkTimestamp(h, 1000n, 0)).toBe(true);
    expect(checkTimestamp(h, 1001n, 0)).toBe(false);
  });

  it('handles extreme attacker-controlled timestamps', () => {
    const h = randomHeader();
    h.timestamp = -(1n << 63n);
    expect(checkTimestamp(h, 0)).toBe(false);
    h.timestamp = (1n << 63n) - 1n;
    expect(checkTimestamp(h, 0)).toBe(false);
  });
});
