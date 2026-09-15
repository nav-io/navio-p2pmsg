import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { concat, randomBytes } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { BROADCAST_PUBLIC, BROADCAST_SECRET, generateSecret, publicKey } from './bls.js';
import {
  decrypt,
  ECIES_TAG_SIZE,
  encrypt,
  packetMsgHash,
  packetWireSize,
  paddedSize,
  parsePacket,
  serializePacket,
  unpad,
} from './ecies.js';

const sk = generateSecret();
const pk = publicKey(sk);
const aad = new Uint8Array([7]);

describe('ecies round trip + padding ladder', () => {
  const cases: Array<[number, number]> = [
    [0, 64],
    [1, 64],
    [60, 64],
    [61, 256],
    [252, 256],
    [253, 1024],
    [1020, 1024],
    [3000, 3072],
    [3580, 3584],
    [3581, 3585],
    [4000, 4004],
  ];
  for (const [len, ct] of cases) {
    it(`len=${len} -> ciphertext ${ct}`, () => {
      const body = randomBytes(len);
      const pkt = encrypt(pk, body, aad);
      expect(pkt.eph.length).toBe(48);
      expect(pkt.tag.length).toBe(ECIES_TAG_SIZE);
      expect(pkt.ciphertext.length).toBe(ct);
      expect(paddedSize(4 + len)).toBe(ct);
      expect(decrypt(sk, pkt, aad)).toEqual(body);
      expect(serializePacket(pkt).length).toBe(packetWireSize(len));
    });
  }
});

describe('ecies failure modes', () => {
  const body = new Uint8Array([1, 2, 3, 4, 5]);

  it('wrong key -> null', () => {
    const pkt = encrypt(pk, body, aad);
    expect(decrypt(generateSecret(), pkt, aad)).toBeNull();
  });

  it('tampered tag / ciphertext / aad -> null', () => {
    const pkt = encrypt(pk, body, aad);
    const t1 = { ...pkt, tag: pkt.tag.slice() };
    t1.tag[0] ^= 1;
    expect(decrypt(sk, t1, aad)).toBeNull();
    const t2 = { ...pkt, ciphertext: pkt.ciphertext.slice() };
    t2.ciphertext[5] ^= 1;
    expect(decrypt(sk, t2, aad)).toBeNull();
    expect(decrypt(sk, pkt, new Uint8Array([8]))).toBeNull();
    expect(decrypt(sk, pkt, new Uint8Array(0))).toBeNull();
  });

  it('eph = infinity encoding (0xc0 || zeros) -> null, and parsePacket accepts it', () => {
    const pkt = encrypt(pk, body, aad);
    const inf = new Uint8Array(48);
    inf[0] = 0xc0;
    expect(decrypt(sk, { ...pkt, eph: inf }, aad)).toBeNull();
    expect(decrypt(BROADCAST_SECRET, { ...pkt, eph: inf }, aad)).toBeNull();
    const parsed = parsePacket(new Reader(serializePacket({ ...pkt, eph: inf })));
    expect(parsed.eph).toEqual(inf);
  });

  it('eph off-curve encoding -> parsePacket throws, decrypt null', () => {
    const pkt = encrypt(pk, body, aad);
    const bad = pkt.eph.slice();
    bad[47] ^= 1; // almost surely off-curve
    let threw = false;
    try {
      parsePacket(new Reader(serializePacket({ ...pkt, eph: bad })));
    } catch {
      threw = true;
    }
    const dec = decrypt(sk, { ...pkt, eph: bad }, aad);
    // either the flipped x is not on the curve (throws) or it decodes to a different point (AEAD fails)
    expect(threw || dec === null).toBe(true);
  });

  it('bad length prefix inside plaintext -> null (unpad validation)', () => {
    // encrypt() can never produce an oversized length prefix; check unpad directly.
    expect(unpad(new Uint8Array([0xff, 0xff, 0xff, 0xff, 1, 2]))).toBeNull();
    expect(unpad(new Uint8Array([2, 0, 0, 0, 9, 8, 0, 0]))).toEqual(new Uint8Array([9, 8]));
    expect(unpad(new Uint8Array([1, 0, 0]))).toBeNull();
  });
});

describe('broadcast key', () => {
  it('BROADCAST_SECRET decrypts what was encrypted to BROADCAST_PUBLIC', () => {
    const body = randomBytes(100);
    const pkt = encrypt(BROADCAST_PUBLIC, body, aad);
    expect(decrypt(BROADCAST_SECRET, pkt, aad)).toEqual(body);
    expect(decrypt(sk, pkt, aad)).toBeNull();
  });
});

describe('packet serialisation', () => {
  it('eph || compactsize(len) || ct || tag, round trip, MsgHash = sha256(bytes)', () => {
    const pkt = encrypt(pk, randomBytes(300), aad);
    const bytes = serializePacket(pkt);
    const expected = new Writer().bytes(pkt.eph).compactSize(pkt.ciphertext.length).bytes(pkt.ciphertext).bytes(pkt.tag).finish();
    expect(bytes).toEqual(expected);
    expect(bytes.length).toBe(48 + 3 + 1024 + 16);
    const r = new Reader(bytes);
    const back = parsePacket(r);
    r.assertDone();
    expect(back).toEqual(pkt);
    expect(packetMsgHash(pkt)).toEqual(sha256(concat(pkt.eph, new Uint8Array([0xfd, 0x00, 0x04]), pkt.ciphertext, pkt.tag)));
  });
});
