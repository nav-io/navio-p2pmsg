/**
 * Group key schedule.
 *
 * Everything a group epoch needs derives from one 32-byte secret:
 *
 *   epoch_secret(e)
 *     ├── group ECIES key   the envelope is encrypted to this, so ONE envelope
 *     │                     and ONE proof of work serve the whole group
 *     ├── group FMD key     so a group message is archivable and every member
 *     │                     can retrieve it after being offline
 *     └── content key       a symmetric layer under the ECIES layer
 *
 * The content key looks redundant against an outsider — the ECIES layer
 * already excludes them. It is load-bearing against a FORMER member who
 * recorded ciphertext while they were in the group: rotating the epoch changes
 * it, and their copy stops being useful for anything new.
 *
 * Encrypting the envelope to a member-only key (rather than publishing on a
 * broadcast topic) is what keeps the topic itself secret. BROADCAST scope
 * encrypts to the generator, so anyone on the bus could read the topic field
 * and watch the group's activity timeline even without the content.
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, utf8 } from '../../common/bytes.js';
import { publicKey, scalarFromSeed } from '../../bus/bls.js';
import { clueKeyOf, type FmdSecretKey, fmdSecretFromSeed, serializeClueKey } from '../../bus/fmd.js';

const SALT = utf8('navio-p2pmsg');

export interface GroupEpochKeys {
  epoch: number;
  epochSecret: Uint8Array; // 32
  /** ECIES target for the envelope; members register it as a session key. */
  eciesSk: Uint8Array; // 32
  eciesPub: Uint8Array; // 48
  fmd: FmdSecretKey;
  clueKey: Uint8Array; // 1152
  /** Symmetric layer under ECIES, so a removed member's recordings go stale. */
  contentKey: Uint8Array; // 32
}

export function randomEpochSecret(): Uint8Array {
  return randomBytes(32);
}

export function deriveGroupEpoch(epochSecret: Uint8Array, epoch: number): GroupEpochKeys {
  if (epochSecret.length !== 32) throw new Error('epoch secret must be 32 bytes');
  const eciesSk = scalarFromSeed(hkdf(sha256, epochSecret, SALT, utf8('group/ecies'), 32));
  const fmdSeed = hkdf(sha256, epochSecret, SALT, utf8('group/fmd'), 32);
  const fmd = fmdSecretFromSeed(fmdSeed, epoch);
  return {
    epoch,
    epochSecret: epochSecret.slice(),
    eciesSk,
    eciesPub: publicKey(eciesSk),
    fmd,
    clueKey: serializeClueKey(clueKeyOf(fmd)),
    contentKey: hkdf(sha256, epochSecret, SALT, utf8('group/content'), 32),
  };
}
