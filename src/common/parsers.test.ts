/**
 * Every parser that reads bytes off the network, swept with input it must
 * reject.
 *
 * Each parser has its own tests for the cases that matter to it. This is the
 * property they all share and none of them state: a parser is handed hostile
 * bytes by definition, so it must always finish, and it must finish by
 * returning or by throwing an Error — never by hanging, and never by handing
 * back a half-parsed value that the caller then treats as real.
 *
 * Truncation is the case worth its own assertion. A parser that reads a count
 * and then a loop of items will happily return the items it managed to read if
 * the loop is not bounded by the input, and the caller cannot tell the
 * difference between "a short list" and "the rest was cut off".
 */
import { describe, expect, it } from 'vitest';
import { randomBytes } from './bytes.js';
import { parseEnvelope, serializeEnvelope } from '../bus/envelope.js';
import { generateSecret, publicKey } from '../bus/bls.js';
import {
  parseAuthFrame,
  parseUserMsgFrame,
  serializeAuthFrame,
  serializeUserMsgFrame,
} from '../usermsg/frame.js';
import {
  parseAnyBundle,
  parseBundle,
  parseExtendedBundle,
  serializeBundle,
  serializeExtendedBundle,
} from '../usermsg/bundle.js';
import { parseAcks, serializeAcks } from '../usermsg/topics.js';
import { parseMirror, serializeMirror } from '../usermsg/mirror.js';
import { parseDeviceList, serializeDeviceList } from '../devices/list.js';
import {
  parseChatFrame,
  parseContactBody,
  parsePaymentBody,
  parseProfileBody,
  parseReceiptBody,
  parseTextBody,
  serializeChatFrame,
  serializeContactBody,
  serializePaymentBody,
  serializeProfileBody,
  serializeReceiptBody,
  serializeTextBody,
  ChatFrameType,
} from '../chat/frame.js';
import { parseGroupState, serializeGroupState } from '../chat/group/state.js';
import {
  parseArchiveRequest,
  parseArchiveResponse,
  serializeArchiveRequest,
  serializeArchiveResponse,
} from '../archive/protocol.js';
import { parseFileMessage, serializeFileMessage, FileOp } from '../stream/file.js';
import { parseSyncMessage, serializeSyncMessage, SyncOp } from '../stream/backfill.js';
import {
  parseStateMessage,
  serializeStateMessage,
  StateOp,
  StateSection,
} from '../stream/statesync.js';
import { parseEphemeral, serializeEphemeral, EphemeralOp, TypingState } from '../stream/ephemeral.js';
import { parseSignal, serializeSignal, SignalOp } from '../stream/signal.js';

const bytes48 = () => randomBytes(48);
/** A real G1 point: the envelope parser checks the ephemeral key is one. */
const point = () => publicKey(generateSecret());
const bytes32 = () => randomBytes(32);

/** A parser, and one valid message for it to chew on. */
interface Case {
  name: string;
  parse: (b: Uint8Array) => unknown;
  valid: Uint8Array;
}

function chatFrame(type: number, body: Uint8Array): Uint8Array {
  return serializeChatFrame({
    version: 1,
    type,
    convId: bytes32(),
    timestamp: 1000n,
    lamport: 3n,
    parents: [bytes32(), bytes32()],
    body,
  });
}

const cases: Case[] = [
  {
    name: 'parseEnvelope',
    parse: parseEnvelope,
    valid: serializeEnvelope({
      kind: 7,
      pow: {
        version: 2,
        timestamp: 1000n,
        kind: 7,
        sessionEph: point(),
        payloadHash: bytes32(),
        nonce: 5n,
      },
      flag: randomBytes(83),
      enc: { eph: point(), ciphertext: randomBytes(200), tag: randomBytes(16) },
    }),
  },
  {
    name: 'parseUserMsgFrame',
    parse: parseUserMsgFrame,
    valid: serializeUserMsgFrame({ topic: 'chat/x', body: randomBytes(64) }),
  },
  {
    name: 'parseAuthFrame',
    parse: parseAuthFrame,
    valid: serializeAuthFrame({
      msgId: randomBytes(16),
      timestamp: 9n,
      sender: bytes48(),
      sig: randomBytes(96),
      replyPub: bytes48(),
      chunk: { idx: 1, total: 4 },
      payload: randomBytes(100),
    }),
  },
  {
    name: 'parseBundle',
    parse: parseBundle,
    valid: serializeBundle({ identity: bytes48(), prekey: bytes48(), prekeySig: randomBytes(96) }),
  },
  {
    name: 'parseExtendedBundle',
    parse: parseExtendedBundle,
    valid: serializeExtendedBundle({
      identity: bytes48(),
      prekey: bytes48(),
      prekeySig: randomBytes(96),
      fmdEpoch: 2,
      fmdClueKey: randomBytes(24 * 48),
      fmdSig: randomBytes(96),
      deviceList: new Uint8Array(0),
    }),
  },
  {
    name: 'parseAnyBundle',
    parse: parseAnyBundle,
    valid: serializeBundle({ identity: bytes48(), prekey: bytes48(), prekeySig: randomBytes(96) }),
  },
  {
    name: 'parseAcks',
    parse: parseAcks,
    valid: serializeAcks([
      { msgId: randomBytes(16), chunkIdx: 0 },
      { msgId: randomBytes(16), chunkIdx: 2 },
    ]),
  },
  {
    name: 'parseMirror',
    parse: parseMirror,
    valid: serializeMirror([
      { recipient: bytes48(), topic: 'msg', timestamp: 4n, payload: randomBytes(20) },
    ]),
  },
  {
    name: 'parseDeviceList',
    parse: parseDeviceList,
    valid: serializeDeviceList({
      version: 1,
      accountEpoch: 3,
      devices: [
        {
          deviceId: randomBytes(8),
          devicePub: bytes48(),
          createdAt: 1000n,
          caps: 1,
          label: 'phone',
          cert: randomBytes(96),
        },
      ],
      listSig: randomBytes(96),
    }),
  },
  {
    name: 'parseChatFrame',
    parse: parseChatFrame,
    valid: chatFrame(ChatFrameType.TEXT, serializeTextBody({ text: 'hi', mentions: [], attachments: [] })),
  },
  {
    name: 'parseTextBody',
    parse: parseTextBody,
    valid: serializeTextBody({ text: 'hello', mentions: [bytes48()], attachments: [] }),
  },
  {
    name: 'parseReceiptBody',
    parse: parseReceiptBody,
    valid: serializeReceiptBody({ heads: [bytes32(), bytes32()] }),
  },
  {
    name: 'parsePaymentBody',
    parse: parsePaymentBody,
    valid: serializePaymentBody({
      op: 1,
      amount: 5n,
      tokenId: '',
      memo: 'x',
      reference: bytes32(),
    }),
  },
  {
    name: 'parseProfileBody',
    parse: parseProfileBody,
    valid: serializeProfileBody({ displayName: 'a', statusText: 'b' }),
  },
  {
    name: 'parseContactBody',
    parse: parseContactBody,
    valid: serializeContactBody({ op: 1, intro: 'hello' }),
  },
  {
    name: 'parseGroupState',
    parse: parseGroupState,
    valid: serializeGroupState({
      version: 1,
      groupId: bytes32(),
      epoch: 1,
      members: [{ identity: bytes48(), role: 2, joinedAt: 500n, joinedEpoch: 0 }],
      name: 'g',
      topic: 't',
      prevStateHash: bytes32(),
      author: bytes48(),
      authorSig: randomBytes(96),
    }),
  },
  {
    name: 'parseArchiveRequest',
    parse: parseArchiveRequest,
    valid: serializeArchiveRequest({
      version: 1,
      stamp: { version: 1, timestamp: 1n, queryHash: bytes32(), nonce: 0n },
      cursor: 0n,
      limit: 10,
      precision: 4,
      scanBudget: 1000,
      challenge: bytes32(),
      detectionKey: randomBytes(4 * 32),
      notBefore: 0n,
    }),
  },
  {
    name: 'parseArchiveResponse',
    parse: parseArchiveResponse,
    valid: serializeArchiveResponse({
      version: 1,
      nextCursor: 9n,
      complete: true,
      items: [{ id: 1n, receivedAt: 2n, envelope: randomBytes(50) }],
    }),
  },
  {
    name: 'parseFileMessage',
    parse: parseFileMessage,
    valid: serializeFileMessage({ op: FileOp.CHUNK, contentHash: bytes32(), offset: 0, bytes: randomBytes(40) }),
  },
  {
    name: 'parseSyncMessage',
    parse: parseSyncMessage,
    valid: serializeSyncMessage({
      op: SyncOp.BATCH,
      convId: bytes32(),
      entries: [{ frame: randomBytes(30), receivedAt: 1, sender: bytes48() }],
    }),
  },
  {
    name: 'parseStateMessage',
    parse: parseStateMessage,
    valid: serializeStateMessage({
      op: StateOp.BATCH,
      section: StateSection.CONTACTS,
      items: [randomBytes(20), randomBytes(5)],
    }),
  },
  {
    name: 'parseEphemeral',
    parse: parseEphemeral,
    valid: serializeEphemeral({ op: EphemeralOp.TYPING, convId: bytes32(), state: TypingState.TYPING }),
  },
  {
    name: 'parseSignal',
    parse: parseSignal,
    valid: serializeSignal({ op: SignalOp.OFFER, sessionId: randomBytes(16), data: 'v=0' }),
  },
];

describe('parser robustness', () => {
  it.each(cases.map((c) => [c.name, c] as const))('%s survives hostile bytes', (_name, c) => {
    // Random bytes at every length up to the valid message, plus a few well
    // past it. Nothing here is expected to parse; what is expected is that
    // deciding takes a bounded amount of time and ends in a value or an Error.
    const lengths = [0, 1, 2, 3, 7, 16, 33, 64, 255, 256, 1024, c.valid.length, c.valid.length + 1];
    for (const len of lengths) {
      for (let attempt = 0; attempt < 8; attempt++) {
        const input = randomBytes(len);
        try {
          c.parse(input);
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
        }
      }
    }
    // A leading byte that is a plausible discriminator is the interesting
    // shape: it gets past the first switch and into the body.
    for (let lead = 0; lead < 8; lead++) {
      const input = randomBytes(48);
      input[0] = lead;
      try {
        c.parse(input);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s rejects a truncated message', (_name, c) => {
    // Every prefix of a valid message. A parser that returns what it managed
    // to read leaves the caller unable to tell a short list from a cut-off
    // one, which is how a message silently loses half its contents.
    for (let n = 0; n < c.valid.length; n++) {
      expect(() => c.parse(c.valid.subarray(0, n))).toThrow();
    }
    // The valid message itself still parses, or the sweep above proves nothing.
    expect(() => c.parse(c.valid)).not.toThrow();
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s rejects trailing bytes', (_name, c) => {
    // Trailing data means the sender and the parser disagree about the shape
    // of the message. Accepting it makes a frame's meaning depend on which
    // implementation read it.
    expect(() => c.parse(new Uint8Array([...c.valid, 0]))).toThrow();
  });
});
