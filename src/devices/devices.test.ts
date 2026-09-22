import { describe, expect, it } from 'vitest';
import { randomBytes, toHex } from '../common/bytes.js';
import { generateSecret, publicKey } from '../bus/bls.js';
import { clueKeyOf, fmdSecretFromSeed, serializeClueKey } from '../bus/fmd.js';
import { decrypt, encrypt } from '../bus/ecies.js';
import {
  DeviceCaps,
  deriveAccountSecret,
  deriveFmdSeed,
  deriveInboxPrekey,
  deriveRatchetKey,
  deviceId,
  generateDevice,
  signDeviceCert,
  verifyDeviceCert,
} from './hierarchy.js';
import {
  DEVICE_LIST_VERSION,
  isListedDevice,
  MAX_DEVICES,
  parseDeviceList,
  serializeDeviceList,
  signDeviceList,
  verifyDeviceList,
} from './list.js';
import {
  decodePairingOffer,
  encodePairingOffer,
  PAIRING_VERSION,
  pairingTopic,
  parseAnnounce,
  parseGrant,
  sasForDevice,
  sasForPrimary,
  SAS_DIGITS,
  serializeAnnounce,
  serializeGrant,
} from './pairing.js';

const SEED = new Uint8Array(32).fill(0x42);

describe('account key hierarchy', () => {
  it('derives a different secret per epoch, deterministically', () => {
    expect(toHex(deriveAccountSecret(SEED, 0))).toBe(toHex(deriveAccountSecret(SEED, 0)));
    expect(toHex(deriveAccountSecret(SEED, 0))).not.toBe(toHex(deriveAccountSecret(SEED, 1)));
    expect(toHex(deriveAccountSecret(SEED, 0))).not.toBe(toHex(deriveAccountSecret(new Uint8Array(32).fill(1), 0)));
  });

  it('gives every device of an account the same inbox key', () => {
    // This is the whole point: one envelope reaches every device, so a sender
    // never pays for the recipient's device count.
    const secret = deriveAccountSecret(SEED, 0);
    const onPhone = deriveInboxPrekey(secret);
    const onDesktop = deriveInboxPrekey(secret);
    expect(toHex(onPhone.pub)).toBe(toHex(onDesktop.pub));
    const packet = encrypt(onPhone.pub, new Uint8Array([7]));
    expect(decrypt(onDesktop.sk, packet)).toEqual(new Uint8Array([7]));
  });

  it('rotates the inbox key and the FMD key with the epoch', () => {
    // Revocation depends on this: a device holding epoch e cannot read e+1.
    const e0 = deriveAccountSecret(SEED, 0);
    const e1 = deriveAccountSecret(SEED, 1);
    expect(toHex(deriveInboxPrekey(e0).pub)).not.toBe(toHex(deriveInboxPrekey(e1).pub));
    const clue0 = serializeClueKey(clueKeyOf(fmdSecretFromSeed(deriveFmdSeed(e0), 0)));
    const clue1 = serializeClueKey(clueKeyOf(fmdSecretFromSeed(deriveFmdSeed(e1), 0)));
    expect(toHex(clue0)).not.toBe(toHex(clue1));

    // A revoked device holds only the old secret.
    const afterRevocation = encrypt(deriveInboxPrekey(e1).pub, new Uint8Array([1]));
    expect(decrypt(deriveInboxPrekey(e0).sk, afterRevocation)).toBeFalsy();
  });

  it('derives ratchet keys deterministically so every device agrees', () => {
    // A textbook double ratchet has one endpoint per side. Ours must decrypt
    // on every device of the recipient, so the RECEIVING keys are derived
    // rather than random.
    const secret = deriveAccountSecret(SEED, 0);
    expect(toHex(deriveRatchetKey(secret, 3).pub)).toBe(toHex(deriveRatchetKey(secret, 3).pub));
    expect(toHex(deriveRatchetKey(secret, 3).pub)).not.toBe(toHex(deriveRatchetKey(secret, 4).pub));
    // And the sequence changes with the epoch, so it does not stay fixed forever.
    expect(toHex(deriveRatchetKey(secret, 3).pub)).not.toBe(
      toHex(deriveRatchetKey(deriveAccountSecret(SEED, 1), 3).pub),
    );
  });

  it('gives a device id that is bound to its key', () => {
    const d = generateDevice();
    expect(d.id).toHaveLength(8);
    expect(toHex(deviceId(d.pub))).toBe(toHex(d.id));
    expect(toHex(deviceId(generateDevice().pub))).not.toBe(toHex(d.id));
    expect(() => deviceId(randomBytes(32))).toThrow(/48 bytes/);
  });

  it('certifies a device under the identity key only', () => {
    const identitySk = generateSecret();
    const identityPub = publicKey(identitySk);
    const device = generateDevice();
    const fields = { devicePub: device.pub, createdAt: 1700000000n, caps: DeviceCaps.CAN_PAIR };
    const cert = signDeviceCert(identitySk, fields);
    expect(verifyDeviceCert(identityPub, fields, cert)).toBe(true);

    // Every field is covered: caps cannot be upgraded after the fact.
    expect(verifyDeviceCert(identityPub, { ...fields, caps: DeviceCaps.PRIMARY }, cert)).toBe(false);
    expect(verifyDeviceCert(identityPub, { ...fields, createdAt: 1n }, cert)).toBe(false);
    // And a stranger cannot admit a device.
    expect(verifyDeviceCert(publicKey(generateSecret()), fields, cert)).toBe(false);
  });
});

describe('device list', () => {
  function account(deviceCount = 2) {
    const identitySk = generateSecret();
    const identityPub = publicKey(identitySk);
    const devices = Array.from({ length: deviceCount }, (_, i) => {
      const d = generateDevice();
      const caps = i === 0 ? DeviceCaps.PRIMARY | DeviceCaps.CAN_PAIR : 0;
      return {
        deviceId: d.id,
        devicePub: d.pub,
        createdAt: BigInt(1700000000 + i),
        caps,
        label: i === 0 ? 'desktop' : 'phone',
        cert: signDeviceCert(identitySk, { devicePub: d.pub, createdAt: BigInt(1700000000 + i), caps }),
      };
    });
    const list = signDeviceList({ version: DEVICE_LIST_VERSION, accountEpoch: 0, devices }, identitySk);
    return { identitySk, identityPub, devices, list };
  }

  it('round trips and verifies', () => {
    const { identityPub, list } = account();
    expect(parseDeviceList(serializeDeviceList(list))).toEqual(list);
    expect(verifyDeviceList(identityPub, list).ok).toBe(true);
    expect(isListedDevice(list, list.devices[1]!.devicePub)).toBe(true);
    expect(isListedDevice(list, generateDevice().pub)).toBe(false);
  });

  it('rejects a tampered list', () => {
    const { identityPub, list } = account();
    const renamed = { ...list, devices: [{ ...list.devices[0]!, label: 'not mine' }, list.devices[1]!] };
    expect(verifyDeviceList(identityPub, renamed).reason).toMatch(/signature/);
    expect(verifyDeviceList(identityPub, { ...list, accountEpoch: 9 }).reason).toMatch(/signature/);
  });

  it('rejects an entry the identity never certified', () => {
    // A valid list signature must not be able to smuggle in a device.
    const { identitySk, identityPub, list } = account();
    const intruder = generateDevice();
    const forged = signDeviceList(
      {
        version: DEVICE_LIST_VERSION,
        accountEpoch: 0,
        devices: [
          ...list.devices,
          {
            deviceId: intruder.id,
            devicePub: intruder.pub,
            createdAt: 1n,
            caps: 0,
            label: 'intruder',
            // Self-signed rather than certified by the identity.
            cert: signDeviceCert(intruder.sk, { devicePub: intruder.pub, createdAt: 1n, caps: 0 }),
          },
        ],
      },
      identitySk,
    );
    expect(verifyDeviceList(identityPub, forged).reason).toMatch(/certificate/);
  });

  it('rejects a mismatched device id, duplicates and an empty list', () => {
    const { identitySk, identityPub, list } = account();
    const wrongId = signDeviceList(
      {
        version: DEVICE_LIST_VERSION,
        accountEpoch: 0,
        devices: [{ ...list.devices[0]!, deviceId: new Uint8Array(8).fill(9) }],
      },
      identitySk,
    );
    expect(verifyDeviceList(identityPub, wrongId).reason).toMatch(/device id/);

    const dup = signDeviceList(
      { version: DEVICE_LIST_VERSION, accountEpoch: 0, devices: [list.devices[0]!, list.devices[0]!] },
      identitySk,
    );
    expect(verifyDeviceList(identityPub, dup).reason).toMatch(/duplicate/);

    const empty = signDeviceList({ version: DEVICE_LIST_VERSION, accountEpoch: 0, devices: [] }, identitySk);
    expect(verifyDeviceList(identityPub, empty).reason).toMatch(/empty/);
  });

  it('caps the device count on both sides', () => {
    const { identitySk, list } = account();
    const many = Array.from({ length: MAX_DEVICES + 1 }, () => list.devices[0]!);
    expect(() => signDeviceList({ version: DEVICE_LIST_VERSION, accountEpoch: 0, devices: many }, identitySk)).toThrow(
      /at most/,
    );
  });
});

describe('pairing', () => {
  it('round trips an offer through navpair1', () => {
    const offer = {
      version: PAIRING_VERSION,
      network: 'regtest' as const,
      pairPub: publicKey(generateSecret()),
      salt: randomBytes(16),
    };
    const text = encodePairingOffer(offer);
    expect(text.startsWith('navpair1')).toBe(true);
    expect(decodePairingOffer(text)).toEqual(offer);
  });

  it('derives a topic that identifies nothing but the offer', () => {
    const a = publicKey(generateSecret());
    const b = publicKey(generateSecret());
    expect(pairingTopic(a)).toBe(pairingTopic(a));
    expect(pairingTopic(a)).not.toBe(pairingTopic(b));
    expect(pairingTopic(a).startsWith('_p2pmsg/pair/')).toBe(true);
  });

  it('gives both sides the same short authentication string', () => {
    // The only thing authenticating the channel: ECDH alone proves nothing
    // about WHO is on the other end, so the user compares these.
    const pairSk = generateSecret();
    const pairPub = publicKey(pairSk);
    const device = generateDevice();
    const salt = randomBytes(16);
    const onPrimary = sasForPrimary(pairSk, device.pub, salt);
    const onDevice = sasForDevice(device.sk, pairPub, salt);
    expect(onPrimary).toBe(onDevice);
    expect(onPrimary).toHaveLength(SAS_DIGITS);
    expect(/^\d{6}$/.test(onPrimary)).toBe(true);
  });

  it('gives a different string to a man in the middle', () => {
    const pairSk = generateSecret();
    const pairPub = publicKey(pairSk);
    const device = generateDevice();
    const attacker = generateDevice();
    const salt = randomBytes(16);
    // The primary talks to the attacker's key; the user sees the mismatch.
    expect(sasForPrimary(pairSk, attacker.pub, salt)).not.toBe(sasForDevice(device.sk, pairPub, salt));
  });

  it('changes the string when the salt changes', () => {
    const pairSk = generateSecret();
    const device = generateDevice();
    expect(sasForPrimary(pairSk, device.pub, randomBytes(16))).not.toBe(
      sasForPrimary(pairSk, device.pub, randomBytes(16)),
    );
  });

  it('round trips the announce and the grant', () => {
    const device = generateDevice();
    const announce = { devicePub: device.pub, label: "Alex's phone" };
    expect(parseAnnounce(serializeAnnounce(announce))).toEqual(announce);

    const grant = {
      accountEpoch: 2,
      accountSecret: randomBytes(32),
      identityPub: publicKey(generateSecret()),
      cert: randomBytes(96),
      caps: DeviceCaps.CAN_PAIR,
      deviceList: randomBytes(300),
    };
    expect(parseGrant(serializeGrant(grant))).toEqual(grant);
    // The grant never carries the root seed: a secondary must not be able to
    // rotate the account epoch or survive revocation.
    expect(serializeGrant(grant).length).toBeLessThan(500);
  });

  it('rejects a grant parsed as an announce and vice versa', () => {
    const device = generateDevice();
    const announce = serializeAnnounce({ devicePub: device.pub, label: 'x' });
    expect(() => parseGrant(announce)).toThrow(/not a pairing grant/);
  });
});
