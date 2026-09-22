import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { randomBytes } from '../common/bytes.js';
import {
  clueKeyOf,
  extractDetectionKey,
  FMD_CLUE_KEY_SIZE,
  FMD_FLAG_SIZE,
  FMD_GAMMA,
  FMD_POINT_SIZE,
  FMD_SCALAR_SIZE,
  fmdFlag,
  fmdSecretFromSeed,
  fmdTest,
  generateFmdSecret,
  isValidClueKey,
  parseClueKey,
  serializeClueKey,
} from './fmd.js';

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string): Uint8Array =>
  new Uint8Array((h.match(/../g) ?? []).map((p) => parseInt(p, 16)));

describe('fmd', () => {
  it('has the documented wire sizes', () => {
    // Shared with navio-core; a change here is a protocol change.
    expect(FMD_GAMMA).toBe(24);
    expect(FMD_FLAG_SIZE).toBe(83);
    expect(FMD_CLUE_KEY_SIZE).toBe(1152);
    const sk = generateFmdSecret();
    expect(serializeClueKey(clueKeyOf(sk)).length).toBe(FMD_CLUE_KEY_SIZE);
    expect(fmdFlag(clueKeyOf(sk)).length).toBe(FMD_FLAG_SIZE);
  });

  it('always matches its own detection key, at every precision', () => {
    // Correctness: anything less and real messages get dropped.
    const sk = generateFmdSecret();
    const ck = clueKeyOf(sk);
    for (let trial = 0; trial < 2; trial++) {
      const flag = fmdFlag(ck);
      for (let n = 1; n <= FMD_GAMMA; n++) {
        expect(fmdTest(extractDetectionKey(sk, n), flag), `precision ${n}`).toBe(true);
      }
    }
  });

  it('matches other recipients at roughly 2^-n', { timeout: 120_000 }, () => {
    // Fuzziness: the decoys are what make the requester's messages
    // indistinguishable to whoever holds the detection key.
    const mine = generateFmdSecret();
    const theirs = clueKeyOf(generateFmdSecret());
    const dk1 = extractDetectionKey(mine, 1);
    const dk3 = extractDetectionKey(mine, 3);
    // Kept small on purpose: every flag costs gamma+2 group multiplications in
    // pure JS, so a larger sample turns this into a benchmark that fails under
    // machine load rather than a test that fails on a bug.
    const trials = 60;
    let m1 = 0;
    let m3 = 0;
    for (let i = 0; i < trials; i++) {
      const flag = fmdFlag(theirs);
      if (fmdTest(dk1, flag)) m1++;
      if (fmdTest(dk3, flag)) m3++;
    }
    // Expect ~30 at 2^-1 and ~7 at 2^-3. The bounds are deliberately loose:
    // this checks that the rate is in the right ballpark, and a statistical
    // test in a deterministic suite must not be able to fail by luck.
    expect(m1).toBeGreaterThan(10);
    expect(m1).toBeLessThan(50);
    expect(m3).toBeLessThan(30);
    // A match at precision n implies a match at every lower precision.
    expect(m1).toBeGreaterThanOrEqual(m3);
  });

  it('effectively never false-positives at full precision', () => {
    const mine = extractDetectionKey(generateFmdSecret(), FMD_GAMMA);
    const theirs = clueKeyOf(generateFmdSecret());
    for (let i = 0; i < 20; i++) expect(fmdTest(mine, fmdFlag(theirs))).toBe(false);
  });

  it('gives a prefix detection key that does not extend', () => {
    // The x_i are INDEPENDENT. This is the property the compact single-point
    // clue key would have destroyed, and the reason the clue key is 1152 bytes
    // rather than 48 — so pin it.
    const sk = generateFmdSecret();
    const dk4 = extractDetectionKey(sk, 4);
    const dk8 = extractDetectionKey(sk, 8);
    expect(dk4.length).toBe(4 * FMD_SCALAR_SIZE);
    expect(dk8.subarray(0, dk4.length)).toEqual(dk4);
    expect(() => extractDetectionKey(sk, 0)).toThrow();
    expect(() => extractDetectionKey(sk, FMD_GAMMA + 1)).toThrow();
  });

  it('is not malleable', () => {
    // The (y, m) collision binds w to every ciphertext bit, so touching any
    // byte randomises every k_i. Also why the PoW header commits to the flag.
    const sk = generateFmdSecret();
    const dk = extractDetectionKey(sk, FMD_GAMMA);
    const flag = fmdFlag(clueKeyOf(sk));
    expect(fmdTest(dk, flag)).toBe(true);
    for (const i of [0, 47, 48, 79, 80, FMD_FLAG_SIZE - 1]) {
      const mauled = flag.slice();
      mauled[i]! ^= 0x01;
      expect(fmdTest(dk, mauled), `byte ${i}`).toBe(false);
    }
  });

  it('rejects malformed input', () => {
    const sk = generateFmdSecret();
    const dk = extractDetectionKey(sk, 8);
    const flag = fmdFlag(clueKeyOf(sk));

    expect(fmdTest(dk, new Uint8Array(0))).toBe(false);
    expect(fmdTest(dk, new Uint8Array(FMD_FLAG_SIZE - 1))).toBe(false);
    expect(fmdTest(dk, new Uint8Array(FMD_FLAG_SIZE + 1))).toBe(false);
    expect(fmdTest(new Uint8Array(0), flag)).toBe(false);
    expect(fmdTest(new Uint8Array(33), flag)).toBe(false); // not whole scalars
    expect(fmdTest(new Uint8Array((FMD_GAMMA + 1) * FMD_SCALAR_SIZE), flag)).toBe(false);

    // An infinity u makes u^{x_i} infinity for EVERY key, so one flag would
    // match every recipient: free spam into everyone's bucket at once.
    const inf = flag.slice();
    inf.fill(0, 0, FMD_POINT_SIZE);
    inf[0] = 0xc0;
    expect(fmdTest(dk, inf)).toBe(false);

    const garbage = flag.slice();
    garbage.fill(0xff, 0, FMD_POINT_SIZE);
    expect(fmdTest(dk, garbage)).toBe(false);
  });

  it('round trips a clue key and validates its points', () => {
    const sk = generateFmdSecret();
    const bytes = serializeClueKey(clueKeyOf(sk));
    expect(isValidClueKey(bytes)).toBe(true);
    // Value-preserving, not merely byte-preserving: a flag built from the
    // parsed key still matches.
    expect(fmdTest(extractDetectionKey(sk, FMD_GAMMA), fmdFlag(parseClueKey(bytes)))).toBe(true);

    expect(isValidClueKey(new Uint8Array(0))).toBe(false);
    expect(isValidClueKey(new Uint8Array(FMD_CLUE_KEY_SIZE - 1))).toBe(false);
    expect(isValidClueKey(new Uint8Array(FMD_CLUE_KEY_SIZE).fill(0xff))).toBe(false);
    const allInf = new Uint8Array(FMD_CLUE_KEY_SIZE);
    for (let i = 0; i < FMD_GAMMA; i++) allInf[i * FMD_POINT_SIZE] = 0xc0;
    expect(isValidClueKey(allInf)).toBe(false);
  });

  it('derives deterministically from a seed, separated by epoch', () => {
    const seed = new Uint8Array(32).fill(0x11);
    const other = new Uint8Array(32).fill(0x12);
    const a = fmdSecretFromSeed(seed, 0);
    const b = fmdSecretFromSeed(seed, 0);
    expect(serializeClueKey(clueKeyOf(a))).toEqual(serializeClueKey(clueKeyOf(b)));
    // Epoch rotation is what bounds a detection key's lifetime.
    expect(serializeClueKey(clueKeyOf(a))).not.toEqual(serializeClueKey(clueKeyOf(fmdSecretFromSeed(seed, 1))));
    expect(serializeClueKey(clueKeyOf(a))).not.toEqual(serializeClueKey(clueKeyOf(fmdSecretFromSeed(other, 0))));
    expect(fmdTest(extractDetectionKey(a, FMD_GAMMA), fmdFlag(clueKeyOf(b)))).toBe(true);
    // The gamma sub-keys within one key are distinct.
    for (let i = 1; i < FMD_GAMMA; i++) expect(a.x[i]).not.toEqual(a.x[0]);
  });

  it('flags are unlinkable to each other', () => {
    // The ephemeral element is fresh per message, so two flags to the same
    // clue key share nothing.
    const ck = clueKeyOf(generateFmdSecret());
    const a = fmdFlag(ck);
    const b = fmdFlag(ck);
    expect(a).not.toEqual(b);
    expect(a.subarray(0, FMD_POINT_SIZE)).not.toEqual(b.subarray(0, FMD_POINT_SIZE));
  });

  it('agrees with navio-core on fixed vectors', () => {
    // Fixed vectors shared with navio-core (src/test/p2pmsg_fmd_tests.cpp).
    // They pin the two things the two implementations must get byte-identical
    // or they silently stop detecting each other's messages:
    //   1. seed -> secret -> clue key derivation, including the hash inputs and
    //      the big-endian reduction mod r;
    //   2. the flag itself — a flag produced by the node must test here.
    const seed = new Uint8Array(32).fill(0x11);
    const sk = fmdSecretFromSeed(seed, 0);
    const ck = serializeClueKey(clueKeyOf(sk));
    expect(ck.length).toBe(FMD_CLUE_KEY_SIZE);
    expect(hex(sha256(ck))).toBe('777166863266f3322a494e3d0c1a2373c5b44e8ba87c3adb97055be9061e46f4');
    expect(hex(extractDetectionKey(sk, 4))).toBe(
      '204afaea8370e9197fd34c5aea2d5b555137bc9798b1c3a1acc66cd1721a41d4' +
        '3b56bf844020b0b217303b899d55bf74adb03697107e51ac646997ee6fbd4b4c' +
        '5c813e4193da749037945776684208ce0f238e9ebd4548eafac165457fde05b9' +
        '6fdefda48d8c821baa6d0cfd690f727e6840001d852d1c7f3da6609263d43ca3',
    );

    // A flag produced by navio-core for this clue key.
    const coreFlag = unhex(
      'ac7255b4649b5757f90000bb8632686d29015e7023551a100bbadebd2cad52a9' +
        '9a68cd5bab79f73b24560e938ebb3a810225ed4752cdd9d6a7f48eae6038ec01' +
        '14f6be3adee7b294281331e01b8203eb2d2051',
    );
    expect(coreFlag.length).toBe(FMD_FLAG_SIZE);
    expect(fmdTest(extractDetectionKey(sk, FMD_GAMMA), coreFlag)).toBe(true);
    // And it is genuinely discriminating, not matching everything.
    expect(fmdTest(extractDetectionKey(generateFmdSecret(), FMD_GAMMA), coreFlag)).toBe(false);
  });

  it('rejects a random flag against a random key', () => {
    expect(fmdTest(extractDetectionKey(generateFmdSecret(), 8), randomBytes(FMD_FLAG_SIZE))).toBe(false);
  });
});
