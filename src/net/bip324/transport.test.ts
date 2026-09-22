import { describe, expect, it } from 'vitest';
import { hex, loadVectors, unhex } from './vectors.test-util.js';
import { concat } from '../../common/bytes.js';
import { ellswiftDecode, ellswiftEcdhXonly } from './ellswift.js';
import { REKEY_INTERVAL } from './ciphers.js';
import { deriveV2Keys, V2Cipher, v2Ecdh } from './transport.js';

/** The vectors are generated on Bitcoin mainnet, so they pin that magic. */
const BITCOIN_MAGIC = unhex('f9beb4d9');

describe('BIP324 packet encoding (official vectors)', () => {
  const vectors = loadVectors('packet_encoding_test_vectors.csv');

  it('loaded the vector file', () => {
    expect(vectors.length).toBeGreaterThan(3);
  });

  for (const [i, v] of vectors.entries()) {
    it(`vector ${i + 1}: idx=${v.in_idx}, ${v.in_multiply}x contents, initiating=${v.in_initiating}`, () => {
      const priv = unhex(v.in_priv_ours!);
      const ellOurs = unhex(v.in_ellswift_ours!);
      const ellTheirs = unhex(v.in_ellswift_theirs!);
      const initiating = v.in_initiating === '1';

      // The ElligatorSwift decodings feeding ECDH.
      expect(hex(ellswiftDecode(ellOurs))).toBe(v.mid_x_ours);
      expect(hex(ellswiftDecode(ellTheirs))).toBe(v.mid_x_theirs);
      expect(hex(ellswiftEcdhXonly(ellTheirs, priv))).toBe(v.mid_x_shared);

      // The shared secret is the TAGGED hash of both encodings and the ECDH
      // point, not the point itself — binding it to this handshake.
      const secret = v2Ecdh(priv, ellOurs, ellTheirs, initiating);
      expect(hex(secret)).toBe(v.mid_shared_secret);

      const keys = deriveV2Keys(secret, BITCOIN_MAGIC);
      expect(hex(keys.initiatorL)).toBe(v.mid_initiator_l);
      expect(hex(keys.initiatorP)).toBe(v.mid_initiator_p);
      expect(hex(keys.responderL)).toBe(v.mid_responder_l);
      expect(hex(keys.responderP)).toBe(v.mid_responder_p);
      expect(hex(keys.sessionId)).toBe(v.out_session_id);

      const cipher = new V2Cipher(keys, initiating);
      expect(hex(cipher.sendGarbageTerminator)).toBe(v.mid_send_garbage_terminator);
      expect(hex(cipher.recvGarbageTerminator)).toBe(v.mid_recv_garbage_terminator);

      // Burn `in_idx` packets first: this is what exercises the rekey
      // schedule, and vectors with idx > 224 are the only thing that catches
      // an off-by-one in it.
      const idx = Number(v.in_idx);
      for (let n = 0; n < idx; n++) cipher.encryptPacket(new Uint8Array(0));

      const unit = unhex(v.in_contents!);
      const times = Number(v.in_multiply);
      const contents = times === 1 ? unit : concat(...Array.from({ length: times }, () => unit));
      const aad = v.in_aad ? unhex(v.in_aad) : new Uint8Array(0);
      const ignore = v.in_ignore === '1';

      const packet = cipher.encryptPacket(contents, aad, ignore);
      if (v.out_ciphertext) {
        expect(hex(packet)).toBe(v.out_ciphertext);
      } else {
        // Long vectors pin only the tail, so the whole packet need not be
        // carried in the CSV.
        expect(hex(packet).endsWith(v.out_ciphertext_endswith!)).toBe(true);
      }
    });
  }
});

describe('V2Cipher round trip', () => {
  function pair(): { a: V2Cipher; b: V2Cipher } {
    // Both sides derive from the same vector so the test needs no key
    // generation; only the initiating flag differs.
    const v = loadVectors('packet_encoding_test_vectors.csv')[0]!;
    const secretA = v2Ecdh(unhex(v.in_priv_ours!), unhex(v.in_ellswift_ours!), unhex(v.in_ellswift_theirs!), true);
    const keys = deriveV2Keys(secretA, BITCOIN_MAGIC);
    return { a: new V2Cipher(keys, true), b: new V2Cipher(keys, false) };
  }

  it('decrypts what the other side encrypted', () => {
    const { a, b } = pair();
    const contents = new Uint8Array([1, 2, 3, 4, 5]);
    const packet = a.encryptPacket(contents);
    const len = b.decryptLength(packet.subarray(0, 3));
    expect(len).toBe(contents.length);
    const decoded = b.decryptPacket(packet.subarray(3));
    expect(decoded.contents).toEqual(contents);
    expect(decoded.ignore).toBe(false);
  });

  it('carries aad and the ignore bit', () => {
    const { a, b } = pair();
    const aad = new Uint8Array([9, 9, 9]);
    const packet = a.encryptPacket(new Uint8Array([7]), aad, true);
    b.decryptLength(packet.subarray(0, 3));
    const decoded = b.decryptPacket(packet.subarray(3), aad);
    expect(decoded.ignore).toBe(true);
    expect(decoded.contents).toEqual(new Uint8Array([7]));
  });

  it('rejects a tampered packet and a wrong aad', () => {
    {
      const { a, b } = pair();
      const packet = a.encryptPacket(new Uint8Array([1, 2, 3]));
      const mauled = packet.slice();
      mauled[mauled.length - 1]! ^= 1;
      b.decryptLength(mauled.subarray(0, 3));
      expect(() => b.decryptPacket(mauled.subarray(3))).toThrow();
    }
    {
      const { a, b } = pair();
      const packet = a.encryptPacket(new Uint8Array([1, 2, 3]), new Uint8Array([1]));
      b.decryptLength(packet.subarray(0, 3));
      expect(() => b.decryptPacket(packet.subarray(3), new Uint8Array([2]))).toThrow();
    }
  });

  it('stays in sync across a rekey boundary', () => {
    // The ciphers rotate their keys every REKEY_INTERVAL chunks. If the two
    // sides disagree by one, everything works until packet 224 and then dies.
    const { a, b } = pair();
    for (let i = 0; i < REKEY_INTERVAL + 5; i++) {
      const contents = new Uint8Array([i & 0xff, (i >> 8) & 0xff]);
      const packet = a.encryptPacket(contents);
      expect(b.decryptLength(packet.subarray(0, 3)), `packet ${i}`).toBe(contents.length);
      expect(b.decryptPacket(packet.subarray(3)).contents, `packet ${i}`).toEqual(contents);
    }
  });

  it('handles empty contents and the maximum practical size', () => {
    const { a, b } = pair();
    const empty = a.encryptPacket(new Uint8Array(0));
    expect(b.decryptLength(empty.subarray(0, 3))).toBe(0);
    expect(b.decryptPacket(empty.subarray(3)).contents.length).toBe(0);

    const big = new Uint8Array(70_000).map((_, i) => i & 0xff);
    const packet = a.encryptPacket(big);
    expect(b.decryptLength(packet.subarray(0, 3))).toBe(big.length);
    expect(b.decryptPacket(packet.subarray(3)).contents).toEqual(big);
  });
});
