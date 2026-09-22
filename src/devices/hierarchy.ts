/**
 * Multi-device key hierarchy.
 *
 * The constraint that shapes all of this: mainnet proof of work is 23 bits per
 * envelope. Encrypting a separate copy per device — what Signal does —
 * multiplies the SENDER's work by the recipient's device count, and a sender
 * should not pay more because the recipient bought a tablet. So one envelope
 * has to reach every device, which means every device holds the same inbox
 * secret.
 *
 *   mnemonic / root seed (32 B)                 PRIMARY DEVICE ONLY
 *     ├── identity_sk        = HKDF(seed, "identity")
 *     └── account_secret(e)  = HKDF(seed, "account/" ‖ u32le(e))
 *           ├── inbox prekey       what senders encrypt to
 *           ├── FMD root           offline retrieval
 *           └── ratchet_sk(e, j)   deterministic receiving keys
 *
 *   device_sk    per device, random, never leaves it
 *   device_cert  Sign(identity_sk, device_id ‖ device_pub ‖ created_at ‖ caps)
 *
 * Two invariants hold the design together:
 *
 *  1. The root seed never leaves the primary device. A secondary holds
 *     `account_secret(e)` for the epochs it was given and no way to derive
 *     `e+1`, which is what makes revocation possible at all.
 *  2. Only the primary can rotate the account epoch, because rotation needs
 *     the seed. Lose the primary and you recover from the mnemonic.
 *
 * The cost, stated plainly: every device holds the same decryption secret, so
 * compromising any one of them opens the account's incoming mail for that
 * epoch. That is the price of not charging senders per device.
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concat, utf8 } from '../common/bytes.js';
import { Writer } from '../common/serialize.js';
import { generateSecret, publicKey, scalarFromSeed, signAugmented, verifyAugmented } from '../bus/bls.js';
import type { KeyPair } from '../usermsg/keyring.js';

const SALT = utf8('navio-p2pmsg');
const DEVICE_TAG = utf8('navio-p2pmsg/device/v1');
const CERT_TAG = utf8('navio-p2pmsg/device-cert/v1');

export const DEVICE_ID_SIZE = 8;

/** What a device is allowed to do. Advertised in the signed device list. */
export const DeviceCaps = {
  /** Holds the root seed: the only device that can rotate the account epoch. */
  PRIMARY: 1 << 0,
  /** May admit other devices. */
  CAN_PAIR: 1 << 1,
  /** May act as an admin in groups on this account's behalf. */
  CAN_ADMIN_GROUPS: 1 << 2,
} as const;

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

/**
 * The secret shared with every active device for an epoch. Derived from the
 * seed, so a secondary device cannot compute the next one.
 */
export function deriveAccountSecret(seed: Uint8Array, epoch: number): Uint8Array {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  return hkdf(sha256, seed, SALT, concat(utf8('account/'), u32le(epoch)), 32);
}

/** The inbox prekey senders encrypt to. Shared by every device of the account. */
export function deriveInboxPrekey(accountSecret: Uint8Array): KeyPair {
  const sk = scalarFromSeed(hkdf(sha256, accountSecret, SALT, utf8('inbox'), 32));
  return { sk, pub: publicKey(sk) };
}

/** Seed for the account's FMD key. Shared, so any device can retrieve. */
export function deriveFmdSeed(accountSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, accountSecret, SALT, utf8('fmd'), 32);
}

/**
 * The receiver's `j`-th ratchet keypair.
 *
 * Deterministic on purpose: every device of the recipient has to derive the
 * SAME receiving chain, or a message would decrypt on one device and not
 * another. The cost is that the receiving key sequence is fixed for an account
 * epoch rather than random — it stays secret, and it rotates with the epoch.
 */
export function deriveRatchetKey(accountSecret: Uint8Array, j: number): KeyPair {
  const sk = scalarFromSeed(hkdf(sha256, accountSecret, SALT, concat(utf8('ratchet/'), u32le(j)), 32));
  return { sk, pub: publicKey(sk) };
}

/** Stable short id for a device public key. */
export function deviceId(devicePub: Uint8Array): Uint8Array {
  if (devicePub.length !== 48) throw new Error('device pubkey must be 48 bytes');
  return sha256(concat(DEVICE_TAG, devicePub)).slice(0, DEVICE_ID_SIZE);
}

export interface DeviceIdentity {
  /** Per device, random, and it never leaves that device. */
  sk: Uint8Array;
  pub: Uint8Array;
  id: Uint8Array;
}

export function generateDevice(): DeviceIdentity {
  const sk = generateSecret();
  const pub = publicKey(sk);
  return { sk, pub, id: deviceId(pub) };
}

export interface DeviceCertFields {
  devicePub: Uint8Array;
  createdAt: bigint;
  caps: number;
}

/** The bytes a device certificate covers. */
export function deviceCertMessage(f: DeviceCertFields): Uint8Array {
  return concat(
    CERT_TAG,
    new Writer().bytes(deviceId(f.devicePub)).bytes(f.devicePub).i64(f.createdAt).u8(f.caps).finish(),
  );
}

/** Sign a device into the account. Only the identity key can do this. */
export function signDeviceCert(identitySk: Uint8Array, f: DeviceCertFields): Uint8Array {
  return signAugmented(identitySk, deviceCertMessage(f));
}

export function verifyDeviceCert(identityPub: Uint8Array, f: DeviceCertFields, cert: Uint8Array): boolean {
  try {
    return verifyAugmented(identityPub, deviceCertMessage(f), cert);
  } catch {
    return false;
  }
}
