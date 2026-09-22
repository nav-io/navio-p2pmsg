/**
 * BIP324 v2 transport: key derivation and packet framing.
 *
 * What it buys over v1: the whole link is encrypted and authenticated, and the
 * bytes on the wire have no fixed structure — no magic, no ASCII command
 * names, no recognisable handshake. For this SDK the concrete reason is the
 * archive query, which hands a node our FMD detection key; on a v1 link anyone
 * on the path collects it and can then test our future messages forever.
 */
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { concat, utf8 } from '../../common/bytes.js';
import { FSChaCha20, FSChaCha20Poly1305, REKEY_INTERVAL } from './ciphers.js';
import { ellswiftEcdhXonly } from './ellswift.js';

export { REKEY_INTERVAL };

export const GARBAGE_TERMINATOR_LEN = 16;
export const MAX_GARBAGE_LEN = 4095;
export const LENGTH_FIELD_LEN = 3;
export const HEADER_LEN = 1;
export const AEAD_TAG_LEN = 16;
/** Ignore-bit position in the 1-byte packet header. */
export const IGNORE_BIT = 1 << 7;
/** Largest contents a single packet can carry (3-byte length field). */
export const MAX_CONTENTS_LEN = 2 ** 24 - 1;

const ECDH_TAG = utf8('bip324_ellswift_xonly_ecdh');

/** BIP340-style tagged hash: SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg). */
function taggedHash(tag: Uint8Array, msg: Uint8Array): Uint8Array {
  const t = sha256(tag);
  return sha256(concat(t, t, msg));
}

/**
 * The shared secret both sides derive.
 *
 * The raw ECDH X coordinate is NOT used directly: it is hashed together with
 * both ElligatorSwift encodings, in initiator-first order, so the secret is
 * bound to this specific handshake and neither side can be replayed into a
 * different one.
 */
export function v2Ecdh(
  priv: Uint8Array,
  ellswiftOurs: Uint8Array,
  ellswiftTheirs: Uint8Array,
  initiating: boolean,
): Uint8Array {
  const x = ellswiftEcdhXonly(ellswiftTheirs, priv);
  const ordered = initiating ? concat(ellswiftOurs, ellswiftTheirs, x) : concat(ellswiftTheirs, ellswiftOurs, x);
  return taggedHash(ECDH_TAG, ordered);
}

export interface V2Keys {
  sessionId: Uint8Array;
  initiatorL: Uint8Array;
  initiatorP: Uint8Array;
  responderL: Uint8Array;
  responderP: Uint8Array;
  initiatorGarbageTerminator: Uint8Array;
  responderGarbageTerminator: Uint8Array;
}

/**
 * HKDF-SHA256 over the ECDH secret. The salt carries the network magic, so a
 * handshake cannot be replayed onto a different chain — the literal
 * `bitcoin_v2_shared_secret` is kept as-is, matching navio-core.
 */
export function deriveV2Keys(ecdhSecret: Uint8Array, magic: Uint8Array): V2Keys {
  const salt = concat(utf8('bitcoin_v2_shared_secret'), magic);
  const expand = (info: string, len = 32): Uint8Array => hkdf(sha256, ecdhSecret, salt, utf8(info), len);
  const terminators = expand('garbage_terminators');
  return {
    sessionId: expand('session_id'),
    initiatorL: expand('initiator_L'),
    initiatorP: expand('initiator_P'),
    responderL: expand('responder_L'),
    responderP: expand('responder_P'),
    initiatorGarbageTerminator: terminators.slice(0, GARBAGE_TERMINATOR_LEN),
    responderGarbageTerminator: terminators.slice(GARBAGE_TERMINATOR_LEN),
  };
}

export interface DecodedPacket {
  contents: Uint8Array;
  /** Packets with the ignore bit set are decoy traffic and must be discarded. */
  ignore: boolean;
}

/**
 * The encrypted side of a live v2 connection: four rekeying ciphers, two per
 * direction.
 *
 * Length fields are decrypted eagerly and separately from their packets,
 * because a length has to be read before its packet has fully arrived. That
 * makes the cipher stateful in a way the caller must respect: call
 * `decryptLength` exactly once per packet, then `decryptPacket` with that many
 * bytes.
 */
export class V2Cipher {
  readonly sessionId: Uint8Array;
  readonly sendGarbageTerminator: Uint8Array;
  readonly recvGarbageTerminator: Uint8Array;
  private readonly sendL: FSChaCha20;
  private readonly sendP: FSChaCha20Poly1305;
  private readonly recvL: FSChaCha20;
  private readonly recvP: FSChaCha20Poly1305;

  constructor(keys: V2Keys, initiating: boolean) {
    this.sessionId = keys.sessionId;
    this.sendL = new FSChaCha20(initiating ? keys.initiatorL : keys.responderL);
    this.sendP = new FSChaCha20Poly1305(initiating ? keys.initiatorP : keys.responderP);
    this.recvL = new FSChaCha20(initiating ? keys.responderL : keys.initiatorL);
    this.recvP = new FSChaCha20Poly1305(initiating ? keys.responderP : keys.initiatorP);
    this.sendGarbageTerminator = initiating ? keys.initiatorGarbageTerminator : keys.responderGarbageTerminator;
    this.recvGarbageTerminator = initiating ? keys.responderGarbageTerminator : keys.initiatorGarbageTerminator;
  }

  static create(
    priv: Uint8Array,
    ellswiftOurs: Uint8Array,
    ellswiftTheirs: Uint8Array,
    initiating: boolean,
    magic: Uint8Array,
  ): V2Cipher {
    return new V2Cipher(deriveV2Keys(v2Ecdh(priv, ellswiftOurs, ellswiftTheirs, initiating), magic), initiating);
  }

  /** Encrypted length field ‖ AEAD(header ‖ contents). */
  encryptPacket(contents: Uint8Array, aad: Uint8Array = new Uint8Array(0), ignore = false): Uint8Array {
    if (contents.length > MAX_CONTENTS_LEN) throw new Error('packet contents too large');
    const plaintext = new Uint8Array(HEADER_LEN + contents.length);
    plaintext[0] = ignore ? IGNORE_BIT : 0;
    plaintext.set(contents, HEADER_LEN);
    const body = this.sendP.encrypt(aad, plaintext);
    const lenField = new Uint8Array(LENGTH_FIELD_LEN);
    lenField[0] = contents.length & 0xff;
    lenField[1] = (contents.length >>> 8) & 0xff;
    lenField[2] = (contents.length >>> 16) & 0xff;
    return concat(this.sendL.crypt(lenField), body);
  }

  /**
   * Decrypt a 3-byte length field into a contents length. Advances the length
   * cipher, so it must be called exactly once per inbound packet and in order.
   */
  decryptLength(field: Uint8Array): number {
    if (field.length !== LENGTH_FIELD_LEN) throw new Error('length field must be 3 bytes');
    const p = this.recvL.crypt(field);
    return p[0]! | (p[1]! << 8) | (p[2]! << 16);
  }

  /**
   * Decrypt the body that followed a length field, i.e. `1 + len + 16` bytes.
   * Throws on authentication failure, after which the connection must be
   * dropped — BIP324 has no way to resynchronise.
   */
  decryptPacket(body: Uint8Array, aad: Uint8Array = new Uint8Array(0)): DecodedPacket {
    if (body.length < HEADER_LEN + AEAD_TAG_LEN) throw new Error('packet too short');
    const plaintext = this.recvP.decrypt(aad, body);
    return { contents: plaintext.slice(HEADER_LEN), ignore: (plaintext[0]! & IGNORE_BIT) !== 0 };
  }
}
