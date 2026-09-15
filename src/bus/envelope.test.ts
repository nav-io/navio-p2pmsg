import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { concat, randomBytes } from '../common/bytes.js';
import { generateSecret, publicKey } from './bls.js';
import { encrypt, packetMsgHash } from './ecies.js';
import { type Envelope, MAX_ENVELOPE_BYTES, parseEnvelope, replayKey, serializeEnvelope } from './envelope.js';
import { grindSync, withNonce } from './pow.js';
import { ReplayCache } from './replay-cache.js';

function makeEnvelope(bodyLen = 10, kind = 7): Envelope {
  const enc = encrypt(publicKey(generateSecret()), randomBytes(bodyLen), new Uint8Array([kind]));
  const pow = {
    version: 1,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    kind,
    sessionEph: enc.eph,
    payloadHash: packetMsgHash(enc),
    nonce: 0n,
  };
  return { kind, pow, enc };
}

describe('envelope', () => {
  it('round trips: u8 kind || pow(98) || packet', () => {
    const env = makeEnvelope();
    const bytes = serializeEnvelope(env);
    expect(bytes.length).toBe(1 + 98 + 48 + 1 + 64 + 16);
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
    // body of 3926 bytes => 4 + 3926 = 3930 ct (unpadded) => 1+98+48+3+3930+16 = 4096
    const env = makeEnvelope(3926);
    const bytes = serializeEnvelope(env);
    expect(bytes.length).toBe(MAX_ENVELOPE_BYTES);
    expect(parseEnvelope(bytes)).toEqual(env);
  });

  it('replayKey = sha256(kind || MsgHash), independent of nonce', () => {
    const env = makeEnvelope();
    const expected = sha256(concat(new Uint8Array([env.kind]), packetMsgHash(env.enc)));
    expect(replayKey(env)).toEqual(expected);
    const nonce = grindSync(env.pow, 8)!;
    expect(replayKey({ ...env, pow: withNonce(env.pow, nonce) })).toEqual(expected);
    expect(replayKey({ ...env, kind: 8 })).not.toEqual(expected);
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
