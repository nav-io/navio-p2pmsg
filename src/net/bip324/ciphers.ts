/**
 * The two rekeying ciphers BIP324 builds its packets from.
 *
 * Both rotate their key every `REKEY_INTERVAL` chunks so that compromising a
 * key does not retroactively open the whole session. The schedule is part of
 * the wire format: an off-by-one here produces a connection that works
 * perfectly for 223 packets and then desynchronises, which is exactly the kind
 * of bug unit tests miss and the BIP's own vectors catch.
 */
import { chacha20, chacha20poly1305 } from '@noble/ciphers/chacha';

export const REKEY_INTERVAL = 224;
const CHACHA_BLOCK = 64;

function nonceOf(counterLow: number, counterHigh: number): Uint8Array {
  const n = new Uint8Array(12);
  const v = new DataView(n.buffer);
  v.setUint32(0, counterLow >>> 0, true);
  v.setBigUint64(4, BigInt(counterHigh), true);
  return n;
}

/** One 64-byte ChaCha20 keystream block at an explicit block counter. */
function chachaBlock(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  return chacha20(key, nonce, new Uint8Array(CHACHA_BLOCK), undefined, counter);
}

/**
 * Rekeying stream cipher, used for the 3-byte packet length field.
 *
 * The length is encrypted but NOT authenticated — it has to be readable before
 * the packet it describes has arrived. Authenticity comes from the packet's own
 * tag; a tampered length just makes the next decrypt fail.
 */
export class FSChaCha20 {
  private key: Uint8Array;
  private blockCounter = 0;
  private chunkCounter = 0;
  private keystream = new Uint8Array(0);

  constructor(initialKey: Uint8Array) {
    if (initialKey.length !== 32) throw new Error('FSChaCha20 key must be 32 bytes');
    this.key = initialKey.slice();
  }

  private keystreamBytes(n: number): Uint8Array {
    while (this.keystream.length < n) {
      const nonce = nonceOf(0, Math.floor(this.chunkCounter / REKEY_INTERVAL));
      const block = chachaBlock(this.key, nonce, this.blockCounter);
      const grown = new Uint8Array(this.keystream.length + block.length);
      grown.set(this.keystream, 0);
      grown.set(block, this.keystream.length);
      this.keystream = grown;
      this.blockCounter++;
    }
    const out = this.keystream.slice(0, n);
    this.keystream = this.keystream.slice(n);
    return out;
  }

  /** XOR a chunk with the keystream. Encryption and decryption are the same. */
  crypt(chunk: Uint8Array): Uint8Array {
    const ks = this.keystreamBytes(chunk.length);
    const out = new Uint8Array(chunk.length);
    for (let i = 0; i < chunk.length; i++) out[i] = chunk[i]! ^ ks[i]!;
    if ((this.chunkCounter + 1) % REKEY_INTERVAL === 0) {
      // The new key comes from this cipher's own keystream, and the block
      // counter restarts with it.
      this.key = this.keystreamBytes(32);
      this.blockCounter = 0;
    }
    this.chunkCounter++;
    return out;
  }
}

/**
 * Rekeying AEAD, used for the packet header and contents.
 *
 * A failed `decrypt` leaves this object's counters unusable on purpose: BIP324
 * has no recovery from an authentication failure, and the caller must drop the
 * connection rather than resynchronise.
 */
export class FSChaCha20Poly1305 {
  private key: Uint8Array;
  private packetCounter = 0;

  constructor(initialKey: Uint8Array) {
    if (initialKey.length !== 32) throw new Error('FSChaCha20Poly1305 key must be 32 bytes');
    this.key = initialKey.slice();
  }

  private nonce(): Uint8Array {
    return nonceOf(this.packetCounter % REKEY_INTERVAL, Math.floor(this.packetCounter / REKEY_INTERVAL));
  }

  private advance(nonce: Uint8Array): void {
    if ((this.packetCounter + 1) % REKEY_INTERVAL === 0) {
      // Rekey nonce is the same nonce with the low counter word set to all
      // ones, so it can never collide with a packet nonce.
      const rekeyNonce = nonce.slice();
      rekeyNonce[0] = 0xff;
      rekeyNonce[1] = 0xff;
      rekeyNonce[2] = 0xff;
      rekeyNonce[3] = 0xff;
      this.key = chachaBlock(this.key, rekeyNonce, 1).slice(0, 32);
    }
    this.packetCounter++;
  }

  encrypt(aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const nonce = this.nonce();
    const out = chacha20poly1305(this.key, nonce, aad).encrypt(plaintext);
    this.advance(nonce);
    return out;
  }

  /** Throws on authentication failure; the caller must then close the session. */
  decrypt(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const nonce = this.nonce();
    const out = chacha20poly1305(this.key, nonce, aad).decrypt(ciphertext);
    this.advance(nonce);
    return out;
  }
}
