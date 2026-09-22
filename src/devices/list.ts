/**
 * The signed device list.
 *
 * A recipient verifies this under the sender's identity key and then accepts
 * per-message signatures from any device on it. A message signed by a device
 * that is NOT listed is surfaced as untrusted — which is exactly the signature
 * an attacker who stole a device would produce after it was revoked.
 */
import { concat, toHex, utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { signAugmented, verifyAugmented } from '../bus/bls.js';
import { DEVICE_ID_SIZE, deviceId, verifyDeviceCert } from './hierarchy.js';

export const DEVICE_LIST_VERSION = 1;
export const MAX_DEVICES = 16;
export const MAX_DEVICE_LABEL_BYTES = 64;

const LIST_TAG = utf8('navio-p2pmsg/device-list/v1');

export interface DeviceEntry {
  deviceId: Uint8Array; // 8
  devicePub: Uint8Array; // 48
  createdAt: bigint;
  caps: number;
  /** User-supplied, e.g. "Alex's phone". */
  label: string;
  cert: Uint8Array; // 96
}

export interface DeviceList {
  version: number;
  accountEpoch: number;
  devices: DeviceEntry[];
  listSig: Uint8Array; // 96
}

function writeUnsigned(w: Writer, l: DeviceList): Writer {
  if (l.devices.length > MAX_DEVICES) throw new Error(`at most ${MAX_DEVICES} devices`);
  w.u8(l.version).u32(l.accountEpoch).compactSize(l.devices.length);
  for (const d of l.devices) {
    if (d.deviceId.length !== DEVICE_ID_SIZE) throw new Error('device id must be 8 bytes');
    if (d.devicePub.length !== 48) throw new Error('device pubkey must be 48 bytes');
    if (d.cert.length !== 96) throw new Error('device cert must be 96 bytes');
    if (utf8(d.label).length > MAX_DEVICE_LABEL_BYTES) throw new Error('device label too long');
    w.bytes(d.deviceId).bytes(d.devicePub).i64(d.createdAt).u8(d.caps).varString(d.label).bytes(d.cert);
  }
  return w;
}

export function deviceListSigningBytes(l: DeviceList): Uint8Array {
  return concat(LIST_TAG, writeUnsigned(new Writer(), l).finish());
}

export function serializeDeviceList(l: DeviceList): Uint8Array {
  if (l.listSig.length !== 96) throw new Error('listSig must be 96 bytes');
  return writeUnsigned(new Writer(), l).bytes(l.listSig).finish();
}

export function parseDeviceList(bytes: Uint8Array): DeviceList {
  const r = new Reader(bytes);
  const version = r.u8();
  const accountEpoch = r.u32();
  const n = r.compactSize();
  if (n > MAX_DEVICES) throw new Error(`at most ${MAX_DEVICES} devices`);
  const devices: DeviceEntry[] = [];
  for (let i = 0; i < n; i++) {
    devices.push({
      deviceId: r.bytes(DEVICE_ID_SIZE).slice(),
      devicePub: r.bytes(48).slice(),
      createdAt: r.i64(),
      caps: r.u8(),
      label: r.varString(),
      cert: r.bytes(96).slice(),
    });
  }
  const listSig = r.bytes(96).slice();
  r.assertDone();
  return { version, accountEpoch, devices, listSig };
}

export function signDeviceList(l: Omit<DeviceList, 'listSig'>, identitySk: Uint8Array): DeviceList {
  const full: DeviceList = { ...l, listSig: new Uint8Array(96) };
  return { ...full, listSig: signAugmented(identitySk, deviceListSigningBytes(full)) };
}

export interface ListValidation {
  ok: boolean;
  reason?: string;
}

/**
 * Check the list signature AND every device certificate. Both matter: the list
 * signature says "this is the current set", each certificate says "this device
 * was admitted by the identity key". A list with a valid signature but a
 * forged entry would otherwise let an attacker add a device.
 */
export function verifyDeviceList(identityPub: Uint8Array, l: DeviceList): ListValidation {
  if (l.version !== DEVICE_LIST_VERSION) return { ok: false, reason: 'unsupported device list version' };
  if (l.devices.length === 0) return { ok: false, reason: 'device list is empty' };
  if (l.devices.length > MAX_DEVICES) return { ok: false, reason: 'too many devices' };

  const seen = new Set<string>();
  for (const d of l.devices) {
    const key = toHex(d.devicePub);
    if (seen.has(key)) return { ok: false, reason: 'duplicate device' };
    seen.add(key);
    // The id is a hash of the pubkey, so a mismatch means someone assembled
    // the entry by hand.
    if (toHex(deviceId(d.devicePub)) !== toHex(d.deviceId)) return { ok: false, reason: 'device id does not match its key' };
    if (!verifyDeviceCert(identityPub, { devicePub: d.devicePub, createdAt: d.createdAt, caps: d.caps }, d.cert)) {
      return { ok: false, reason: 'bad device certificate' };
    }
  }

  if (!verifyAugmented(identityPub, deviceListSigningBytes(l), l.listSig)) {
    return { ok: false, reason: 'bad device list signature' };
  }
  return { ok: true };
}

/** Whether a device may sign messages for this account. */
export function isListedDevice(l: DeviceList, devicePub: Uint8Array): boolean {
  const key = toHex(devicePub);
  return l.devices.some((d) => toHex(d.devicePub) === key);
}
