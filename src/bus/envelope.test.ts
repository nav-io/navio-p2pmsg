import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { concat, randomBytes } from '../common/bytes.js';
import { generateSecret, publicKey } from './bls.js';
import { encrypt, packetMsgHash } from './ecies.js';
import {
  type Envelope,
  expectedPayloadHash,
  MAX_ENVELOPE_BYTES,
  MAX_FLAG_BYTES,
  parseEnvelope,
  deliveryKey,
  replayKey,
  serializeEnvelope,
} from './envelope.js';
import { FMD_FLAG_SIZE } from './fmd.js';
import { grindSync, payloadHash, POW_VERSION_CURRENT, withNonce } from './pow.js';
import { ReplayCache } from './replay-cache.js';

function makeEnvelope(bodyLen = 10, kind = 7, flag: Uint8Array = new Uint8Array(0)): Envelope {
  const enc = encrypt(publicKey(generateSecret()), randomBytes(bodyLen), new Uint8Array([kind]));
  const pow = {
    version: POW_VERSION_CURRENT,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    kind,
    sessionEph: enc.eph,
    payloadHash: payloadHash(POW_VERSION_CURRENT, packetMsgHash(enc), flag),
    nonce: 0n,
  };
  return { kind, pow, flag, enc };
}

describe('envelope', () => {
  it('round trips: u8 kind || pow(98) || packet', () => {
    const env = makeEnvelope();
    const bytes = serializeEnvelope(env);
    // + 1 for the CompactSize flag length, which is 0 here.
    expect(bytes.length).toBe(1 + 98 + 1 + 48 + 1 + 64 + 16);
    expect(bytes[0]).toBe(7);
    expect(parseEnvelope(bytes)).toEqual(env);
  });

  it('rejects trailing bytes and truncation', () => {
    const bytes = serializeEnvelope(makeEnvelope());
    expect(() => parseEnvelope(concat(bytes, new Uint8Array([0])))).toThrow(/trailing/);
    expect(() => parseEnvelope(bytes.subarray(0, bytes.length - 1))).toThrow();
    expect(() => parseEnvelope(new Uint8Array(0))).toThrow();
  });

  it('rejects > 4096 bytes and accepts exactly 4096', () => {
    expect(() => parseEnvelope(new Uint8Array(MAX_ENVELOPE_BYTES + 1))).toThrow(/too large/);
    // body of 3925 bytes => 4 + 3925 = 3929 ct (unpadded)
    // => 1 kind + 98 pow + 1 flen + 48 eph + 3 compactsize + 3929 + 16 tag = 4096
    const env = makeEnvelope(3925);
    const bytes = serializeEnvelope(env);
    expect(bytes.length).toBe(MAX_ENVELOPE_BYTES);
    expect(parseEnvelope(bytes)).toEqual(env);
  });

  it('carries an optional detection flag, bound by the pow header', () => {
    const flag = randomBytes(FMD_FLAG_SIZE);
    const env = makeEnvelope(10, 7, flag);
    const bytes = serializeEnvelope(env);
    expect(bytes.length).toBe(1 + 98 + 1 + FMD_FLAG_SIZE + 48 + 1 + 64 + 16);
    const parsed = parseEnvelope(bytes);
    expect(parsed.flag).toEqual(flag);
    expect(parsed).toEqual(env);
    // The header commits to the flag, so it cannot be stripped or swapped
    // without redoing the work.
    expect(expectedPayloadHash({ ...env, flag: new Uint8Array(0) })).not.toEqual(env.pow.payloadHash);
    const other = randomBytes(FMD_FLAG_SIZE);
    expect(expectedPayloadHash({ ...env, flag: other })).not.toEqual(env.pow.payloadHash);
    expect(expectedPayloadHash(env)).toEqual(env.pow.payloadHash);
  });

  it('rejects a flag above MAX_FLAG_BYTES', () => {
    const env = makeEnvelope(10, 7, randomBytes(MAX_FLAG_BYTES + 1));
    expect(() => parseEnvelope(serializeEnvelope(env))).toThrow(/flag too large/);
  });

  it('replayKey = sha256(kind || payload_hash), independent of nonce', () => {
    const env = makeEnvelope();
    const expected = sha256(concat(new Uint8Array([env.kind]), env.pow.payloadHash));
    expect(replayKey(env)).toEqual(expected);
    const nonce = grindSync(env.pow, 8)!;
    expect(replayKey({ ...env, pow: withNonce(env.pow, nonce) })).toEqual(expected);
    expect(replayKey({ ...env, kind: 8 })).not.toEqual(expected);
  });

  it('replayKey separates two flags over the same ciphertext', () => {
    // Deliberate: it lets a sender re-flag a retransmission for a recipient
    // whose clue key rotated, and each variant costs a fresh grind.
    const a = makeEnvelope(10, 7, randomBytes(FMD_FLAG_SIZE));
    const b = { ...a, flag: randomBytes(FMD_FLAG_SIZE) };
    b.pow = { ...a.pow, payloadHash: expectedPayloadHash(b) };
    expect(packetMsgHash(a.enc)).toEqual(packetMsgHash(b.enc));
    expect(replayKey(a)).not.toEqual(replayKey(b));
  });

  it('deliveryKey does NOT separate them: to a recipient it is one message', () => {
    // The flag is routing metadata. Anyone who saw an envelope can rewrite it
    // and regrind once, so keying delivery on the wire identity would let a
    // bystander have the same message dispatched again and again.
    const a = makeEnvelope(10, 7, randomBytes(FMD_FLAG_SIZE));
    const reflagged = { ...a, flag: randomBytes(FMD_FLAG_SIZE) };
    reflagged.pow = { ...a.pow, payloadHash: expectedPayloadHash(reflagged) };
    const stripped = { ...a, flag: new Uint8Array(0) };
    stripped.pow = { ...a.pow, payloadHash: expectedPayloadHash(stripped) };
    expect(deliveryKey(reflagged)).toEqual(deliveryKey(a));
    expect(deliveryKey(stripped)).toEqual(deliveryKey(a));
    // A different ciphertext is still a different message.
    expect(deliveryKey(makeEnvelope(10, 7, a.flag))).not.toEqual(deliveryKey(a));
    // And the kind is part of it, as it is for the wire identity.
    expect(deliveryKey({ ...a, kind: 8 })).not.toEqual(deliveryKey(a));
  });
});

describe('ReplayCache', () => {
  it('is a bounded LRU set', () => {
    const c = new ReplayCache(3);
    const keys = [1, 2, 3, 4].map((i) => new Uint8Array([i]));
    expect(c.add(keys[0]!)).toBe(true);
    expect(c.add(keys[0]!)).toBe(false);
    c.add(keys[1]!);
    c.add(keys[2]!);
    expect(c.size).toBe(3);
    c.add(keys[3]!); // evicts key 1
    expect(c.has(keys[0]!)).toBe(false);
    expect(c.has(keys[3]!)).toBe(true);
    expect(c.size).toBe(3);
    // touching key 2 makes key 3 the oldest
    c.add(keys[1]!);
    c.add(new Uint8Array([9]));
    expect(c.has(keys[2]!)).toBe(false);
    expect(c.has(keys[1]!)).toBe(true);
  });
});
