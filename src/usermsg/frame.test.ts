import { describe, expect, it } from 'vitest';
import {
  AUTH_FRAME_MAX_OVERHEAD,
  authFrameDigest,
  parseAuthFrame,
  parseUserMsgFrame,
  serializeAuthFrame,
  serializeAuthFrameUnsigned,
  serializeUserMsgFrame,
} from './frame.js';
import { decodeBundle, decodeContact, decodeIdentity, encodeBundle, encodeIdentity } from './bundle.js';
import { toHex } from '../common/bytes.js';

describe('UserMsgFrame', () => {
  it('round trips and matches node serialisation', () => {
    const bytes = serializeUserMsgFrame({ topic: 'chat', body: new Uint8Array([1, 2, 3]) });
    // CompactSize(4) "chat" CompactSize(3) 01 02 03
    expect(toHex(bytes)).toBe('0463686174' + '03010203');
    expect(parseUserMsgFrame(bytes)).toEqual({ topic: 'chat', body: new Uint8Array([1, 2, 3]) });
  });
  it('enforces limits', () => {
    expect(() => serializeUserMsgFrame({ topic: '', body: new Uint8Array() })).toThrow();
    expect(() => serializeUserMsgFrame({ topic: 'x'.repeat(65), body: new Uint8Array() })).toThrow();
    expect(() => serializeUserMsgFrame({ topic: 't', body: new Uint8Array(3584) })).toThrow();
    expect(() => parseUserMsgFrame(new Uint8Array([1, 0x61, 0, 0]))).toThrow(/trailing/);
  });
});

describe('AuthFrame', () => {
  const msgId = new Uint8Array(16).fill(7);
  const pk = new Uint8Array(48).fill(1);
  const sig = new Uint8Array(96).fill(2);
  it('round trips all flag combinations', () => {
    const variants = [
      { msgId, timestamp: 5n, payload: new Uint8Array([9]) },
      { msgId, timestamp: -1n, sender: pk, sig, payload: new Uint8Array(0) },
      { msgId, timestamp: 5n, replyPub: pk, payload: new Uint8Array([1, 2]) },
      { msgId, timestamp: 5n, sender: pk, sig, replyPub: pk, chunk: { idx: 2, total: 3 }, payload: new Uint8Array(300) },
    ];
    for (const v of variants) {
      const bytes = serializeAuthFrame(v);
      const back = parseAuthFrame(bytes);
      expect(back).toEqual(v);
    }
  });
  it('signed frame without sig throws; unsigned parse rejects trailing bytes', () => {
    expect(() => serializeAuthFrame({ msgId, timestamp: 0n, sender: pk, payload: new Uint8Array() })).toThrow();
    const bytes = serializeAuthFrame({ msgId, timestamp: 0n, payload: new Uint8Array() });
    expect(() => parseAuthFrame(new Uint8Array([...bytes, 0]))).toThrow();
  });
  it('digest depends on topic, recipient, and frame', () => {
    const f = serializeAuthFrameUnsigned({ msgId, timestamp: 1n, payload: new Uint8Array([1]) });
    const d1 = authFrameDigest('a', pk, f);
    expect(toHex(authFrameDigest('a', pk, f))).toBe(toHex(d1));
    expect(toHex(authFrameDigest('b', pk, f))).not.toBe(toHex(d1));
    expect(toHex(authFrameDigest('a', new Uint8Array(48), f))).not.toBe(toHex(d1));
  });
  it('max overhead constant is accurate', () => {
    const bytes = serializeAuthFrame({
      msgId,
      timestamp: 0n,
      sender: pk,
      sig,
      replyPub: pk,
      chunk: { idx: 0, total: 1 },
      payload: new Uint8Array(3000),
    });
    expect(bytes.length).toBe(3000 + AUTH_FRAME_MAX_OVERHEAD);
  });
});

describe('bundle encodings', () => {
  const identity = new Uint8Array(48).map((_, i) => i);
  const prekey = new Uint8Array(48).map((_, i) => 100 + i);
  const prekeySig = new Uint8Array(96).map((_, i) => 200 - i);
  it('identity bech32m + hex', () => {
    const s = encodeIdentity(identity);
    expect(s.startsWith('navid1')).toBe(true);
    expect(decodeIdentity(s)).toEqual(identity);
    expect(decodeIdentity(s.toUpperCase())).toEqual(identity);
    expect(decodeIdentity(toHex(identity))).toEqual(identity);
    expect(() => decodeIdentity('navmsg1qqq')).toThrow();
  });
  it('bundle bech32m + hex + contact sniffing', () => {
    const s = encodeBundle({ identity, prekey, prekeySig });
    expect(s.startsWith('navmsg1')).toBe(true);
    expect(decodeBundle(s)).toEqual({ identity, prekey, prekeySig });
    const c = decodeContact(s);
    expect(c.identity).toEqual(identity);
    expect(c.bundle?.prekey).toEqual(prekey);
    expect(decodeContact(encodeIdentity(identity)).bundle).toBeUndefined();
  });
});
