/**
 * BIP324 message type encoding.
 *
 * v1 spends 12 bytes on an ASCII command name in every message. v2 gives the
 * common types a 1-byte id and falls back to `0x00` followed by the same
 * 12-byte name for everything else.
 *
 * The table must match navio-core's `V2_MESSAGE_IDS` exactly — an id decoded
 * as the wrong type is worse than a parse failure, because it is silent.
 */

/**
 * Index = short id. Index 0 means "12-byte name follows". Entries 1..28 are
 * BIP324's standard assignments; 29 is Navio's own, and 30..32 are unassigned.
 */
const V2_MESSAGE_IDS: readonly string[] = [
  '', // 0: long form
  'addr',
  'block',
  'blocktxn',
  'cmpctblock',
  'feefilter',
  'filteradd',
  'filterclear',
  'filterload',
  'getblocks',
  'getblocktxn',
  'getdata',
  'getheaders',
  'headers',
  'inv',
  'mempool',
  'merkleblock',
  'notfound',
  'ping',
  'pong',
  'sendcmpct',
  'tx',
  'getcfilters',
  'cfilter',
  'getcfheaders',
  'cfheaders',
  'getcfcheckpt',
  'cfcheckpt',
  'addrv2',
  // Navio-specific. Note this is the only way `getoutputdata` is reachable at
  // all: the name is 13 characters, one over v1's COMMAND_SIZE, so it is dead
  // on a v1 link and only a short id can carry it.
  'getoutputdata',
  '',
  '',
  '',
];

const SHORT_ID = new Map<string, number>();
for (let i = 1; i < V2_MESSAGE_IDS.length; i++) {
  const name = V2_MESSAGE_IDS[i]!;
  if (name) SHORT_ID.set(name, i);
}

export const LONG_ID_LEN = 13;

/** Encode a command name as its 1-byte id, or `0x00` + 12 padded ASCII bytes. */
export function encodeMessageType(command: string): Uint8Array {
  const short = SHORT_ID.get(command);
  if (short !== undefined) return new Uint8Array([short]);
  if (command.length > 12) throw new Error(`command "${command}" exceeds 12 bytes and has no short id`);
  const out = new Uint8Array(LONG_ID_LEN);
  for (let i = 0; i < command.length; i++) out[1 + i] = command.charCodeAt(i) & 0x7f;
  return out;
}

export interface DecodedMessageType {
  command: string;
  /** Bytes consumed: 1 for a short id, 13 for the long form. */
  size: number;
}

/**
 * Decode the message type at the start of a packet's contents. Returns
 * undefined for a truncated long form or an unassigned short id — both of
 * which the caller should treat as an unknown message and skip, not as a
 * protocol violation.
 */
export function decodeMessageType(contents: Uint8Array): DecodedMessageType | undefined {
  if (contents.length < 1) return undefined;
  const first = contents[0]!;
  if (first !== 0) {
    const name = V2_MESSAGE_IDS[first];
    if (name === undefined || name === '') return undefined;
    return { command: name, size: 1 };
  }
  if (contents.length < LONG_ID_LEN) return undefined;
  let command = '';
  for (let i = 1; i < LONG_ID_LEN; i++) {
    const b = contents[i]!;
    if (b === 0) break;
    command += String.fromCharCode(b);
  }
  return { command, size: LONG_ID_LEN };
}
