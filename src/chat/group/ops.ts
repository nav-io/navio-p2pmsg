/**
 * Membership operations and the rekey policy.
 *
 * Rekeying is what makes removal mean anything. Without it a removed member
 * keeps the epoch secret and keeps reading; with it their key stops working on
 * the next message. Rekey on ADD is the default for the mirror-image reason:
 * a new member should not be handed the ability to read what was said before
 * they arrived.
 */
import { toHex } from '../../common/bytes.js';
import {
  type GroupMember,
  GroupRole,
  type GroupState,
  groupStateHash,
  isAdmin,
  memberOf,
  signGroupState,
} from './state.js';

export type GroupOp =
  | { kind: 'add'; identity: Uint8Array; role?: number; rekey?: boolean }
  | { kind: 'remove'; identity: Uint8Array }
  | { kind: 'leave'; identity: Uint8Array }
  | { kind: 'promote'; identity: Uint8Array; role: number }
  | { kind: 'rename'; name: string }
  | { kind: 'setTopic'; topic: string };

export interface ApplyResult {
  state: GroupState;
  /** True when the caller must mint a new epoch secret and distribute it. */
  rekey: boolean;
}

/** Whether an operation forces a new epoch. */
export function requiresRekey(op: GroupOp): boolean {
  switch (op.kind) {
    case 'remove':
    case 'leave':
      // Mandatory: otherwise the departing member reads everything afterwards.
      return true;
    case 'add':
      // Default on, so members join forward-only.
      return op.rekey !== false;
    default:
      // Role and metadata changes reveal nothing new.
      return false;
  }
}

/**
 * Apply `op` to `state` and sign the result as `author`.
 *
 * Throws when the author is not entitled to the change — the same rules every
 * other member will apply when they validate it, so a rejected operation fails
 * here rather than silently splitting the group.
 */
export function applyGroupOp(
  state: GroupState,
  op: GroupOp,
  author: { identity: Uint8Array; sk: Uint8Array },
  now: () => number = () => Date.now(),
): ApplyResult {
  const self = memberOf(state, author.identity);
  if (!self) throw new Error('author is not a member of this group');

  const rekey = requiresRekey(op);
  const members = state.members.map((m) => ({ ...m }));
  let name = state.name;
  let topic = state.topic;

  switch (op.kind) {
    case 'add': {
      requireAdmin(state, author.identity);
      if (memberOf(state, op.identity)) throw new Error('already a member');
      members.push({
        identity: op.identity.slice(),
        role: op.role ?? GroupRole.MEMBER,
        joinedAt: BigInt(Math.floor(now() / 1000)),
        joinedEpoch: state.epoch + 1,
      });
      break;
    }
    case 'remove': {
      requireAdmin(state, author.identity);
      const target = memberOf(state, op.identity);
      if (!target) throw new Error('not a member');
      // The owner anchors the group; removing them would leave a state nobody
      // can chain from.
      if (target.role === GroupRole.OWNER) throw new Error('cannot remove the owner');
      if (toHex(op.identity) === toHex(author.identity)) throw new Error('use leave to remove yourself');
      remove(members, op.identity);
      break;
    }
    case 'leave': {
      if (toHex(op.identity) !== toHex(author.identity)) throw new Error('can only leave as yourself');
      if (self.role === GroupRole.OWNER) throw new Error('the owner must transfer ownership before leaving');
      remove(members, op.identity);
      break;
    }
    case 'promote': {
      requireAdmin(state, author.identity);
      const target = members.find((m) => toHex(m.identity) === toHex(op.identity));
      if (!target) throw new Error('not a member');
      if (op.role === GroupRole.OWNER) throw new Error('ownership transfer is not supported yet');
      if (target.role === GroupRole.OWNER) throw new Error('cannot demote the owner');
      target.role = op.role;
      break;
    }
    case 'rename': {
      requireAdmin(state, author.identity);
      name = op.name;
      break;
    }
    case 'setTopic': {
      requireAdmin(state, author.identity);
      topic = op.topic;
      break;
    }
  }

  const next = signGroupState(
    {
      version: state.version,
      groupId: state.groupId,
      // A rekey is exactly what an epoch bump means, so the two move together.
      epoch: rekey ? state.epoch + 1 : state.epoch,
      members,
      name,
      topic,
      prevStateHash: groupStateHash(state),
      author: author.identity,
    },
    author.sk,
  );
  return { state: next, rekey };
}

function requireAdmin(state: GroupState, identity: Uint8Array): void {
  if (!isAdmin(state, identity)) throw new Error('only an admin may do that');
}

function remove(members: GroupMember[], identity: Uint8Array): void {
  const key = toHex(identity);
  const idx = members.findIndex((m) => toHex(m.identity) === key);
  if (idx >= 0) members.splice(idx, 1);
}
