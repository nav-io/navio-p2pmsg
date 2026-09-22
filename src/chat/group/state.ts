/**
 * Group membership state: who is in, what they may do, and a hash chain
 * linking every epoch to the one before it.
 *
 * The chain is the point. An admin that presents divergent histories to
 * different members is otherwise undetectable; with it, a member whose
 * `prevStateHash` does not match the state it holds sees the conflict and can
 * refuse rather than silently pick one.
 */
import { sha256 } from '@noble/hashes/sha256';
import { concat, toHex, utf8 } from '../../common/bytes.js';
import { Reader, Writer } from '../../common/serialize.js';
import { signAugmented, verifyAugmented } from '../../bus/bls.js';

export const GROUP_STATE_VERSION = 1;

export const GroupRole = { MEMBER: 0, ADMIN: 1, OWNER: 2 } as const;
export type GroupRoleValue = (typeof GroupRole)[keyof typeof GroupRole];

/** Rekey is O(n) 1:1 messages, each with its own proof of work. */
export const MAX_GROUP_MEMBERS = 256;
export const MAX_GROUP_ADMINS = 16;
export const MAX_GROUP_NAME_BYTES = 128;
export const MAX_GROUP_TOPIC_BYTES = 512;

export interface GroupMember {
  identity: Uint8Array; // 48
  role: number;
  joinedAt: bigint;
  /** Epoch they joined in; anything earlier is not theirs to read. */
  joinedEpoch: number;
}

export interface GroupState {
  version: number;
  groupId: Uint8Array; // 32
  epoch: number;
  members: GroupMember[];
  name: string;
  topic: string;
  /** Hash of the state this one supersedes; 32 zero bytes at creation. */
  prevStateHash: Uint8Array; // 32
  author: Uint8Array; // 48
  authorSig: Uint8Array; // 96
}

const STATE_TAG = utf8('navio-p2pmsg/group/state/v1');

function writeUnsigned(w: Writer, s: GroupState): Writer {
  if (s.groupId.length !== 32) throw new Error('groupId must be 32 bytes');
  if (s.prevStateHash.length !== 32) throw new Error('prevStateHash must be 32 bytes');
  if (s.author.length !== 48) throw new Error('author must be a 48-byte identity');
  if (s.members.length > MAX_GROUP_MEMBERS) throw new Error(`at most ${MAX_GROUP_MEMBERS} members`);
  if (utf8(s.name).length > MAX_GROUP_NAME_BYTES) throw new Error('group name too long');
  if (utf8(s.topic).length > MAX_GROUP_TOPIC_BYTES) throw new Error('group topic too long');
  w.u8(s.version).bytes(s.groupId).u32(s.epoch).compactSize(s.members.length);
  for (const m of s.members) {
    if (m.identity.length !== 48) throw new Error('member identity must be 48 bytes');
    w.bytes(m.identity).u8(m.role).i64(m.joinedAt).u32(m.joinedEpoch);
  }
  return w.varString(s.name).varString(s.topic).bytes(s.prevStateHash).bytes(s.author);
}

/** The bytes the author signs: everything but the signature itself. */
export function groupStateSigningBytes(s: GroupState): Uint8Array {
  return concat(STATE_TAG, writeUnsigned(new Writer(), s).finish());
}

export function serializeGroupState(s: GroupState): Uint8Array {
  if (s.authorSig.length !== 96) throw new Error('authorSig must be 96 bytes');
  return writeUnsigned(new Writer(), s).bytes(s.authorSig).finish();
}

export function parseGroupState(bytes: Uint8Array): GroupState {
  const r = new Reader(bytes);
  const version = r.u8();
  const groupId = r.bytes(32).slice();
  const epoch = r.u32();
  const n = r.compactSize();
  if (n > MAX_GROUP_MEMBERS) throw new Error(`at most ${MAX_GROUP_MEMBERS} members`);
  const members: GroupMember[] = [];
  for (let i = 0; i < n; i++) {
    members.push({ identity: r.bytes(48).slice(), role: r.u8(), joinedAt: r.i64(), joinedEpoch: r.u32() });
  }
  const name = r.varString();
  const topic = r.varString();
  const prevStateHash = r.bytes(32).slice();
  const author = r.bytes(48).slice();
  const authorSig = r.bytes(96).slice();
  r.assertDone();
  return { version, groupId, epoch, members, name, topic, prevStateHash, author, authorSig };
}

/** Identity of a state, and what the NEXT state cites as `prevStateHash`. */
export function groupStateHash(s: GroupState): Uint8Array {
  return sha256(serializeGroupState(s));
}

export function signGroupState(s: Omit<GroupState, 'authorSig'>, authorSk: Uint8Array): GroupState {
  const full: GroupState = { ...s, authorSig: new Uint8Array(96) };
  return { ...full, authorSig: signAugmented(authorSk, groupStateSigningBytes(full)) };
}

export function memberOf(s: GroupState, identity: Uint8Array): GroupMember | undefined {
  const key = toHex(identity);
  return s.members.find((m) => toHex(m.identity) === key);
}

export function isAdmin(s: GroupState, identity: Uint8Array): boolean {
  const m = memberOf(s, identity);
  return m !== undefined && (m.role === GroupRole.ADMIN || m.role === GroupRole.OWNER);
}

export interface StateValidation {
  ok: boolean;
  reason?: string;
}

/**
 * Check a state on its own terms: signature, limits, and that its author was
 * entitled to produce it.
 *
 * `previous` is the state we already hold. When given, the new state must
 * chain to it and move the epoch forward — that is what makes a divergent
 * history visible instead of silently replacing what we have.
 */
export function validateGroupState(s: GroupState, previous?: GroupState): StateValidation {
  if (s.version !== GROUP_STATE_VERSION) return { ok: false, reason: 'unsupported group state version' };
  if (s.members.length === 0) return { ok: false, reason: 'group has no members' };
  if (s.members.length > MAX_GROUP_MEMBERS) return { ok: false, reason: 'too many members' };
  const admins = s.members.filter((m) => m.role === GroupRole.ADMIN || m.role === GroupRole.OWNER);
  if (admins.length === 0) return { ok: false, reason: 'group has no admin' };
  if (admins.length > MAX_GROUP_ADMINS) return { ok: false, reason: 'too many admins' };

  const seen = new Set<string>();
  for (const m of s.members) {
    const key = toHex(m.identity);
    if (seen.has(key)) return { ok: false, reason: 'duplicate member' };
    seen.add(key);
    if (m.role !== GroupRole.MEMBER && m.role !== GroupRole.ADMIN && m.role !== GroupRole.OWNER) {
      return { ok: false, reason: 'unknown role' };
    }
  }

  if (!verifyAugmented(s.author, groupStateSigningBytes(s), s.authorSig)) {
    return { ok: false, reason: 'bad state signature' };
  }

  if (previous) {
    if (toHex(previous.groupId) !== toHex(s.groupId)) return { ok: false, reason: 'group id mismatch' };
    // The epoch counts KEY generations, not state revisions: a rename or a
    // role change supersedes the previous state without rotating anything.
    // Forward progress is guaranteed by the hash chain below, not by this.
    if (s.epoch < previous.epoch) return { ok: false, reason: 'epoch went backwards' };
    if (toHex(s.prevStateHash) !== toHex(groupStateHash(previous))) {
      // Either we missed an intermediate state or an admin is showing two
      // different histories. Both need a human decision, not a silent merge.
      return { ok: false, reason: 'state does not chain to the one we hold' };
    }
    // The author has to have been entitled to change the PREVIOUS state; a
    // state that promotes its own author would otherwise validate itself.
    if (!isAdmin(previous, s.author)) return { ok: false, reason: 'author is not an admin of the previous state' };
  } else {
    if (!isAdmin(s, s.author)) return { ok: false, reason: 'author is not an admin' };
  }

  return { ok: true };
}
