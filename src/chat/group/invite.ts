/**
 * Group invites.
 *
 * Two flavours, because they have genuinely different security properties and
 * pretending otherwise would be the dangerous part:
 *
 *   key-in-link     the link IS the secret. Anyone holding it joins instantly
 *                   with no admin online — and so does anyone who merely SEES
 *                   it. Hence the expiry, and hence rekeying when an invite is
 *                   revoked, which cuts off anyone who grabbed it but never
 *                   used it.
 *
 *   request-to-join carries no secret, only the group id, the inviter and a
 *                   one-time token. Safe to post somewhere it might be
 *                   forwarded, but an admin has to be online to admit.
 *
 * Applications should default to key-in-link for small private groups and
 * request-to-join for anything that might travel further than intended.
 */
import { bech32m } from '@scure/base';
import { Reader, Writer } from '../../common/serialize.js';
import { signAugmented, verifyAugmented } from '../../bus/bls.js';
import { concat, utf8 } from '../../common/bytes.js';

export const INVITE_HRP = 'navinv';
export const INVITE_VERSION = 1;

export const InviteKind = { KEY_IN_LINK: 1, REQUEST_TO_JOIN: 2 } as const;

export interface GroupInvite {
  version: number;
  kind: number;
  groupId: Uint8Array; // 32
  epoch: number;
  /** Present only for KEY_IN_LINK. */
  epochSecret?: Uint8Array; // 32
  /** Present only for REQUEST_TO_JOIN. */
  token?: Uint8Array; // 16
  expiresAt: bigint;
  inviter: Uint8Array; // 48
  inviterSig: Uint8Array; // 96
}

const INVITE_TAG = utf8('navio-p2pmsg/group/invite/v1');

function writeUnsigned(w: Writer, i: GroupInvite): Writer {
  if (i.groupId.length !== 32) throw new Error('groupId must be 32 bytes');
  if (i.inviter.length !== 48) throw new Error('inviter must be a 48-byte identity');
  w.u8(i.version).u8(i.kind).bytes(i.groupId).u32(i.epoch);
  if (i.kind === InviteKind.KEY_IN_LINK) {
    if (!i.epochSecret || i.epochSecret.length !== 32) throw new Error('key-in-link invite needs a 32-byte secret');
    w.bytes(i.epochSecret);
  } else {
    if (!i.token || i.token.length !== 16) throw new Error('request-to-join invite needs a 16-byte token');
    w.bytes(i.token);
  }
  return w.i64(i.expiresAt).bytes(i.inviter);
}

export function inviteSigningBytes(i: GroupInvite): Uint8Array {
  return concat(INVITE_TAG, writeUnsigned(new Writer(), i).finish());
}

export function serializeInvite(i: GroupInvite): Uint8Array {
  if (i.inviterSig.length !== 96) throw new Error('inviterSig must be 96 bytes');
  return writeUnsigned(new Writer(), i).bytes(i.inviterSig).finish();
}

export function parseInvite(bytes: Uint8Array): GroupInvite {
  const r = new Reader(bytes);
  const version = r.u8();
  if (version !== INVITE_VERSION) throw new Error(`unsupported invite version ${version}`);
  const kind = r.u8();
  const groupId = r.bytes(32).slice();
  const epoch = r.u32();
  const out: GroupInvite = {
    version,
    kind,
    groupId,
    epoch,
    expiresAt: 0n,
    inviter: new Uint8Array(48),
    inviterSig: new Uint8Array(96),
  };
  if (kind === InviteKind.KEY_IN_LINK) out.epochSecret = r.bytes(32).slice();
  else if (kind === InviteKind.REQUEST_TO_JOIN) out.token = r.bytes(16).slice();
  else throw new Error(`unknown invite kind ${kind}`);
  out.expiresAt = r.i64();
  out.inviter = r.bytes(48).slice();
  out.inviterSig = r.bytes(96).slice();
  r.assertDone();
  return out;
}

export function signInvite(i: Omit<GroupInvite, 'inviterSig'>, inviterSk: Uint8Array): GroupInvite {
  const full: GroupInvite = { ...i, inviterSig: new Uint8Array(96) };
  return { ...full, inviterSig: signAugmented(inviterSk, inviteSigningBytes(full)) };
}

/** `navinv1…` */
export function encodeInvite(i: GroupInvite): string {
  return bech32m.encode(INVITE_HRP, bech32m.toWords(serializeInvite(i)), false);
}

export function decodeInvite(s: string): GroupInvite {
  const { prefix, words } = bech32m.decode(s.trim().toLowerCase() as `${string}1${string}`, false);
  if (prefix !== INVITE_HRP) throw new Error(`expected ${INVITE_HRP}1…, got ${prefix}`);
  return parseInvite(new Uint8Array(bech32m.fromWords(words)));
}

export interface InviteCheck {
  ok: boolean;
  reason?: string;
}

/** Signature and expiry. The caller still has to decide whether it trusts the inviter. */
export function checkInvite(i: GroupInvite, nowSeconds: number): InviteCheck {
  if (!verifyAugmented(i.inviter, inviteSigningBytes(i), i.inviterSig)) {
    return { ok: false, reason: 'bad invite signature' };
  }
  if (i.expiresAt !== 0n && BigInt(nowSeconds) > i.expiresAt) return { ok: false, reason: 'invite expired' };
  return { ok: true };
}
