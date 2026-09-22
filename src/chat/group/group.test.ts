import { describe, expect, it } from 'vitest';
import { randomBytes, toHex } from '../../common/bytes.js';
import { generateSecret, publicKey } from '../../bus/bls.js';
import { extractDetectionKey, FMD_GAMMA, fmdFlag, fmdTest, parseClueKey } from '../../bus/fmd.js';
import { decrypt, encrypt } from '../../bus/ecies.js';
import { deriveGroupEpoch, randomEpochSecret } from './schedule.js';
import {
  GroupRole,
  type GroupState,
  groupStateHash,
  isAdmin,
  memberOf,
  parseGroupState,
  serializeGroupState,
  signGroupState,
  validateGroupState,
} from './state.js';
import { applyGroupOp, requiresRekey } from './ops.js';
import { checkInvite, decodeInvite, encodeInvite, InviteKind, signInvite } from './invite.js';

function identity() {
  const sk = generateSecret();
  return { sk, identity: publicKey(sk) };
}

const GROUP = new Uint8Array(32).fill(5);

function genesis(owner: { sk: Uint8Array; identity: Uint8Array }, members: Uint8Array[] = []): GroupState {
  return signGroupState(
    {
      version: 1,
      groupId: GROUP,
      epoch: 0,
      members: [
        { identity: owner.identity, role: GroupRole.OWNER, joinedAt: 0n, joinedEpoch: 0 },
        ...members.map((m) => ({ identity: m, role: GroupRole.MEMBER, joinedAt: 0n, joinedEpoch: 0 })),
      ],
      name: 'test group',
      topic: '',
      prevStateHash: new Uint8Array(32),
      author: owner.identity,
    },
    owner.sk,
  );
}

describe('group key schedule', () => {
  it('derives an ECIES key, a clue key and a content key from one secret', () => {
    const secret = randomEpochSecret();
    const keys = deriveGroupEpoch(secret, 0);
    expect(keys.eciesPub).toHaveLength(48);
    expect(keys.clueKey).toHaveLength(1152);
    expect(keys.contentKey).toHaveLength(32);

    // One envelope serves the whole group: members decrypt with the group key.
    const packet = encrypt(keys.eciesPub, new Uint8Array([1, 2, 3]));
    expect(decrypt(keys.eciesSk, packet)).toEqual(new Uint8Array([1, 2, 3]));

    // And a group message is archivable: any member can detect its flag.
    const flag = fmdFlag(parseClueKey(keys.clueKey));
    expect(fmdTest(extractDetectionKey(keys.fmd, FMD_GAMMA), flag)).toBe(true);
  });

  it('is deterministic per secret and epoch, and different across both', () => {
    const secret = randomEpochSecret();
    expect(toHex(deriveGroupEpoch(secret, 0).eciesPub)).toBe(toHex(deriveGroupEpoch(secret, 0).eciesPub));
    // The clue key is epoch-scoped, so a rekey retires detection keys with it.
    expect(toHex(deriveGroupEpoch(secret, 0).clueKey)).not.toBe(toHex(deriveGroupEpoch(secret, 1).clueKey));
    expect(toHex(deriveGroupEpoch(secret, 0).eciesPub)).not.toBe(
      toHex(deriveGroupEpoch(randomEpochSecret(), 0).eciesPub),
    );
  });

  it('cuts off a removed member: the new epoch key does not open old or new traffic', () => {
    const oldKeys = deriveGroupEpoch(randomEpochSecret(), 0);
    const newKeys = deriveGroupEpoch(randomEpochSecret(), 1);
    const afterRemoval = encrypt(newKeys.eciesPub, new Uint8Array([9]));
    // The departing member holds only the old secret.
    expect(decrypt(oldKeys.eciesSk, afterRemoval)).toBeFalsy();
  });
});

describe('group state', () => {
  it('round trips and validates', () => {
    const owner = identity();
    const s = genesis(owner);
    expect(parseGroupState(serializeGroupState(s))).toEqual(s);
    expect(validateGroupState(s).ok).toBe(true);
    expect(isAdmin(s, owner.identity)).toBe(true);
    expect(memberOf(s, owner.identity)?.role).toBe(GroupRole.OWNER);
  });

  it('rejects a state whose signature does not match', () => {
    const owner = identity();
    const s = genesis(owner);
    const forged = { ...s, name: 'renamed without permission' };
    expect(validateGroupState(forged).ok).toBe(false);
    expect(validateGroupState(forged).reason).toMatch(/signature/);
  });

  it('rejects a state signed by a non-admin', () => {
    const owner = identity();
    const stranger = identity();
    const s = genesis(owner);
    const forged = signGroupState({ ...s, author: stranger.identity }, stranger.sk);
    expect(validateGroupState(forged).ok).toBe(false);
  });

  it('requires a state to chain to the one we hold', () => {
    // An admin showing two different histories to different members is
    // otherwise undetectable.
    const owner = identity();
    const bob = identity();
    const s0 = genesis(owner);
    const { state: s1 } = applyGroupOp(s0, { kind: 'add', identity: bob.identity }, owner);
    expect(validateGroupState(s1, s0).ok).toBe(true);

    const divergent = signGroupState({ ...s1, prevStateHash: new Uint8Array(32).fill(0xaa) }, owner.sk);
    const res = validateGroupState(divergent, s0);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/chain/);
  });

  it('rejects an author who was not an admin of the previous state', () => {
    // Otherwise a state that promotes its own author would validate itself.
    const owner = identity();
    const bob = identity();
    const s0 = genesis(owner, [bob.identity]);
    const selfPromoting = signGroupState(
      {
        ...s0,
        epoch: 1,
        members: s0.members.map((m) => (toHex(m.identity) === toHex(bob.identity) ? { ...m, role: GroupRole.ADMIN } : m)),
        prevStateHash: groupStateHash(s0),
        author: bob.identity,
      },
      bob.sk,
    );
    expect(validateGroupState(selfPromoting, s0).ok).toBe(false);
  });

  it('rejects a group with no members or no admin, and duplicates', () => {
    const owner = identity();
    const bob = identity();
    const s = genesis(owner);
    expect(validateGroupState(signGroupState({ ...s, members: [] }, owner.sk)).reason).toMatch(/no members/);
    expect(
      validateGroupState(
        signGroupState(
          { ...s, members: [{ identity: bob.identity, role: GroupRole.MEMBER, joinedAt: 0n, joinedEpoch: 0 }] },
          owner.sk,
        ),
      ).reason,
    ).toMatch(/no admin/);
    expect(
      validateGroupState(signGroupState({ ...s, members: [s.members[0]!, s.members[0]!] }, owner.sk)).reason,
    ).toMatch(/duplicate/);
  });
});

describe('group operations', () => {
  it('rekeys on remove and on add, but not on metadata changes', () => {
    expect(requiresRekey({ kind: 'remove', identity: new Uint8Array(48) })).toBe(true);
    expect(requiresRekey({ kind: 'leave', identity: new Uint8Array(48) })).toBe(true);
    expect(requiresRekey({ kind: 'add', identity: new Uint8Array(48) })).toBe(true);
    // Opt out so a new member can read history, when the group wants that.
    expect(requiresRekey({ kind: 'add', identity: new Uint8Array(48), rekey: false })).toBe(false);
    expect(requiresRekey({ kind: 'rename', name: 'x' })).toBe(false);
    expect(requiresRekey({ kind: 'promote', identity: new Uint8Array(48), role: GroupRole.ADMIN })).toBe(false);
  });

  it('adds a member and advances the epoch', () => {
    const owner = identity();
    const bob = identity();
    const s0 = genesis(owner);
    const { state: s1, rekey } = applyGroupOp(s0, { kind: 'add', identity: bob.identity }, owner);
    expect(rekey).toBe(true);
    expect(s1.epoch).toBe(1);
    expect(memberOf(s1, bob.identity)).toBeDefined();
    // Joined in the new epoch: nothing before it is theirs to read.
    expect(memberOf(s1, bob.identity)!.joinedEpoch).toBe(1);
    expect(validateGroupState(s1, s0).ok).toBe(true);
  });

  it('keeps the epoch for a rename and still chains', () => {
    const owner = identity();
    const s0 = genesis(owner);
    const { state: s1, rekey } = applyGroupOp(s0, { kind: 'rename', name: 'new name' }, owner);
    expect(rekey).toBe(false);
    expect(s1.epoch).toBe(0);
    expect(s1.name).toBe('new name');
    expect(validateGroupState(s1, s0).ok).toBe(true);
  });

  it('removes a member and forces a rekey', () => {
    const owner = identity();
    const bob = identity();
    const s0 = genesis(owner, [bob.identity]);
    const { state: s1, rekey } = applyGroupOp(s0, { kind: 'remove', identity: bob.identity }, owner);
    expect(rekey).toBe(true);
    expect(memberOf(s1, bob.identity)).toBeUndefined();
    expect(validateGroupState(s1, s0).ok).toBe(true);
  });

  it('refuses operations the author is not entitled to', () => {
    const owner = identity();
    const bob = identity();
    const carol = identity();
    const s0 = genesis(owner, [bob.identity, carol.identity]);
    expect(() => applyGroupOp(s0, { kind: 'remove', identity: carol.identity }, bob)).toThrow(/admin/);
    expect(() => applyGroupOp(s0, { kind: 'rename', name: 'x' }, bob)).toThrow(/admin/);
    expect(() => applyGroupOp(s0, { kind: 'add', identity: identity().identity }, bob)).toThrow(/admin/);
    // Not a member at all.
    expect(() => applyGroupOp(s0, { kind: 'rename', name: 'x' }, identity())).toThrow(/not a member/);
  });

  it('protects the owner and self-removal', () => {
    const owner = identity();
    const admin = identity();
    const s0 = signGroupState(
      {
        ...genesis(owner, [admin.identity]),
        members: [
          { identity: owner.identity, role: GroupRole.OWNER, joinedAt: 0n, joinedEpoch: 0 },
          { identity: admin.identity, role: GroupRole.ADMIN, joinedAt: 0n, joinedEpoch: 0 },
        ],
      },
      owner.sk,
    );
    expect(() => applyGroupOp(s0, { kind: 'remove', identity: owner.identity }, admin)).toThrow(/owner/);
    expect(() => applyGroupOp(s0, { kind: 'remove', identity: admin.identity }, admin)).toThrow(/leave/);
    expect(() => applyGroupOp(s0, { kind: 'leave', identity: owner.identity }, owner)).toThrow(/owner/);
    // An admin may leave.
    expect(applyGroupOp(s0, { kind: 'leave', identity: admin.identity }, admin).state.members).toHaveLength(1);
  });

  it('promotes and demotes, but never the owner', () => {
    const owner = identity();
    const bob = identity();
    const s0 = genesis(owner, [bob.identity]);
    const { state: s1 } = applyGroupOp(s0, { kind: 'promote', identity: bob.identity, role: GroupRole.ADMIN }, owner);
    expect(memberOf(s1, bob.identity)!.role).toBe(GroupRole.ADMIN);
    expect(() => applyGroupOp(s1, { kind: 'promote', identity: owner.identity, role: GroupRole.MEMBER }, owner)).toThrow(
      /owner/,
    );
  });
});

describe('group invites', () => {
  it('round trips a key-in-link invite through navinv1', () => {
    const inviter = identity();
    const invite = signInvite(
      {
        version: 1,
        kind: InviteKind.KEY_IN_LINK,
        groupId: GROUP,
        epoch: 3,
        epochSecret: randomEpochSecret(),
        expiresAt: 2000000000n,
        inviter: inviter.identity,
      },
      inviter.sk,
    );
    const text = encodeInvite(invite);
    expect(text.startsWith('navinv1')).toBe(true);
    expect(decodeInvite(text)).toEqual(invite);
    expect(checkInvite(invite, 1000).ok).toBe(true);
  });

  it('round trips a request-to-join invite, which carries no secret', () => {
    const inviter = identity();
    const invite = signInvite(
      {
        version: 1,
        kind: InviteKind.REQUEST_TO_JOIN,
        groupId: GROUP,
        epoch: 1,
        token: randomBytes(16),
        expiresAt: 0n,
        inviter: inviter.identity,
      },
      inviter.sk,
    );
    const decoded = decodeInvite(encodeInvite(invite));
    expect(decoded.epochSecret).toBeUndefined();
    expect(decoded.token).toHaveLength(16);
    // Safe to post somewhere it might be forwarded: it grants nothing on its own.
    expect(checkInvite(decoded, 999999).ok).toBe(true);
  });

  it('rejects an expired or tampered invite', () => {
    const inviter = identity();
    const invite = signInvite(
      {
        version: 1,
        kind: InviteKind.KEY_IN_LINK,
        groupId: GROUP,
        epoch: 0,
        epochSecret: randomEpochSecret(),
        expiresAt: 1000n,
        inviter: inviter.identity,
      },
      inviter.sk,
    );
    expect(checkInvite(invite, 2000).reason).toMatch(/expired/);
    expect(checkInvite({ ...invite, epoch: 7 }, 500).reason).toMatch(/signature/);
  });
});
