/** Sign / verify AuthFrames under an identity key. */
import { signAugmented, verifyAugmented } from '../bus/bls.js';
import { equal } from '../common/bytes.js';
import {
  type AuthFrame,
  authFrameDigest,
  serializeAuthFrame,
  serializeAuthFrameUnsigned,
} from './frame.js';
import type { KeyPair } from './keyring.js';

/** Fill in sender + sig and return the serialised frame. */
export function signAuthFrame(frame: Omit<AuthFrame, 'sender' | 'sig'>, identity: KeyPair, topic: string, recipient: Uint8Array): Uint8Array {
  const f: AuthFrame = { ...frame, sender: identity.pub };
  const unsigned = serializeAuthFrameUnsigned(f);
  f.sig = signAugmented(identity.sk, authFrameDigest(topic, recipient, unsigned));
  return serializeAuthFrame(f);
}

/**
 * Sign as a SECONDARY device: the frame names the account identity so the
 * receiver knows whose device list to consult, and carries the device key that
 * actually produced the signature.
 *
 * `identityPub` is a public key here — a secondary device holds no identity
 * secret, which is exactly why this path exists.
 */
export function signAuthFrameWithDevice(
  frame: Omit<AuthFrame, 'sender' | 'sig' | 'devicePub'>,
  identityPub: Uint8Array,
  device: KeyPair,
  topic: string,
  recipient: Uint8Array,
): Uint8Array {
  const f: AuthFrame = { ...frame, sender: identityPub, devicePub: device.pub };
  const unsigned = serializeAuthFrameUnsigned(f);
  f.sig = signAugmented(device.sk, authFrameDigest(topic, recipient, unsigned));
  return serializeAuthFrame(f);
}

/**
 * Verify a parsed signed frame against the topic and the recipient key it was
 * addressed to. Unsigned frames return true (nothing to verify); the caller
 * decides whether unsigned is acceptable for that topic.
 */
export function verifyAuthFrame(frame: AuthFrame, topic: string, recipient: Uint8Array): boolean {
  if (!frame.sender) return true;
  if (!frame.sig) return false;
  const unsigned = serializeAuthFrameUnsigned(frame);
  // A device-signed frame verifies under the DEVICE key. That the device
  // belongs to the account is a separate check against the sender's published
  // device list — this function only proves the bytes were signed by the key
  // the frame names.
  const signer = frame.devicePub ?? frame.sender;
  try {
    return verifyAugmented(signer, authFrameDigest(topic, recipient, unsigned), frame.sig);
  } catch {
    return false;
  }
}

export function sameKey(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  return !!a && !!b && equal(a, b);
}
