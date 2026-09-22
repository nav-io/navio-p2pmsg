import { describe, expect, it } from 'vitest';
import { randomBytes, toHex, utf8 } from '../common/bytes.js';
import {
  type ChatFrame,
  ChatFrameType,
  chatMessageId,
  ContactOp,
  directConversationId,
  MAX_PARENTS,
  MAX_THUMBNAIL_BYTES,
  parseChatFrame,
  parseContactBody,
  parseEditBody,
  parseProfileBody,
  parseReactionBody,
  parseReceiptBody,
  parseTextBody,
  selfConversationId,
  serializeChatFrame,
  serializeContactBody,
  serializeEditBody,
  serializeProfileBody,
  serializeReactionBody,
  serializeReceiptBody,
  serializeTextBody,
} from './frame.js';

function frame(over: Partial<ChatFrame> = {}): ChatFrame {
  return {
    version: 1,
    type: ChatFrameType.TEXT,
    convId: randomBytes(32),
    timestamp: 1700000000n,
    lamport: 5n,
    parents: [randomBytes(32)],
    body: utf8('hi'),
    ...over,
  };
}

describe('chat frame', () => {
  it('round trips', () => {
    const f = frame({ parents: [randomBytes(32), randomBytes(32)] });
    expect(parseChatFrame(serializeChatFrame(f))).toEqual(f);
  });

  it('round trips with no parents and an empty body', () => {
    const f = frame({ parents: [], body: new Uint8Array(0) });
    expect(parseChatFrame(serializeChatFrame(f))).toEqual(f);
  });

  it('rejects trailing bytes and bad field sizes', () => {
    const bytes = serializeChatFrame(frame());
    expect(() => parseChatFrame(new Uint8Array([...bytes, 0]))).toThrow(/trailing/);
    expect(() => serializeChatFrame(frame({ convId: randomBytes(31) }))).toThrow(/32 bytes/);
    expect(() => serializeChatFrame(frame({ parents: [randomBytes(31)] }))).toThrow(/32 bytes/);
  });

  it('caps the parent list on both sides', () => {
    const many = Array.from({ length: MAX_PARENTS + 1 }, () => randomBytes(32));
    expect(() => serializeChatFrame(frame({ parents: many }))).toThrow(/at most/);
    // And a peer cannot force us to accept more by hand-crafting the bytes.
    const ok = serializeChatFrame(frame({ parents: [randomBytes(32)] }));
    const forged = new Uint8Array(ok);
    forged[1 + 1 + 32 + 8 + 8] = MAX_PARENTS + 1; // the CompactSize parent count
    expect(() => parseChatFrame(forged)).toThrow(/at most/);
  });

  it('gives a content-addressed id that changes with every field', () => {
    // Edits, reactions and deletes target this id, so it has to cover
    // everything — including the parents, which is also why an honest frame
    // can never cite its own descendant.
    const f = frame();
    const base = toHex(chatMessageId(f));
    expect(toHex(chatMessageId({ ...f, timestamp: f.timestamp + 1n }))).not.toBe(base);
    expect(toHex(chatMessageId({ ...f, lamport: 6n }))).not.toBe(base);
    expect(toHex(chatMessageId({ ...f, body: utf8('ho') }))).not.toBe(base);
    expect(toHex(chatMessageId({ ...f, parents: [] }))).not.toBe(base);
    expect(toHex(chatMessageId({ ...f, type: ChatFrameType.EDIT }))).not.toBe(base);
    expect(toHex(chatMessageId(f))).toBe(base);
  });
});

describe('conversation ids', () => {
  it('is the same for both sides of a 1:1 regardless of argument order', () => {
    // Both derive it independently; there is nothing to negotiate.
    const a = randomBytes(48);
    const b = randomBytes(48);
    expect(toHex(directConversationId(a, b))).toBe(toHex(directConversationId(b, a)));
  });

  it('differs per pair, and from the self conversation', () => {
    const a = randomBytes(48);
    const b = randomBytes(48);
    const c = randomBytes(48);
    expect(toHex(directConversationId(a, b))).not.toBe(toHex(directConversationId(a, c)));
    expect(toHex(directConversationId(a, a))).not.toBe(toHex(selfConversationId(a)));
  });

  it('rejects keys that are not identities', () => {
    expect(() => directConversationId(randomBytes(32), randomBytes(48))).toThrow(/48 bytes/);
    expect(() => selfConversationId(randomBytes(32))).toThrow(/48 bytes/);
  });
});

describe('chat bodies', () => {
  it('round trips text with mentions, attachments and a reply', () => {
    const body = {
      text: 'hello 🌍',
      mentions: [randomBytes(48)],
      attachments: [
        {
          contentHash: randomBytes(32),
          size: 123456n,
          mime: 'image/png',
          key: randomBytes(32),
          thumbnail: randomBytes(64),
        },
      ],
      replyTo: randomBytes(32),
    };
    expect(parseTextBody(serializeTextBody(body))).toEqual(body);
  });

  it('round trips text with nothing optional set', () => {
    const body = { text: '', mentions: [], attachments: [] };
    expect(parseTextBody(serializeTextBody(body))).toEqual(body);
  });

  it('rejects an oversized thumbnail', () => {
    // The thumbnail rides the bus so a preview renders before the transfer;
    // unbounded it would eat the envelope budget.
    const body = {
      text: 'x',
      mentions: [],
      attachments: [
        {
          contentHash: randomBytes(32),
          size: 1n,
          mime: 'image/png',
          key: randomBytes(32),
          thumbnail: randomBytes(MAX_THUMBNAIL_BYTES + 1),
        },
      ],
    };
    expect(() => serializeTextBody(body)).toThrow(/thumbnail too large/);
  });

  it('round trips edit, delete, reaction, receipt, profile and contact bodies', () => {
    const edit = { target: randomBytes(32), text: 'fixed' };
    expect(parseEditBody(serializeEditBody(edit))).toEqual(edit);

    const reaction = { target: randomBytes(32), emoji: '👍', add: true };
    expect(parseReactionBody(serializeReactionBody(reaction))).toEqual(reaction);
    const removal = { ...reaction, add: false };
    expect(parseReactionBody(serializeReactionBody(removal))).toEqual(removal);

    const receipt = { heads: [randomBytes(32), randomBytes(32)] };
    expect(parseReceiptBody(serializeReceiptBody(receipt))).toEqual(receipt);
    expect(parseReceiptBody(serializeReceiptBody({ heads: [] }))).toEqual({ heads: [] });

    const profile = { displayName: 'alex', statusText: 'away' };
    expect(parseProfileBody(serializeProfileBody(profile))).toEqual(profile);
    const withAvatar = {
      ...profile,
      avatar: { contentHash: randomBytes(32), size: 9n, mime: 'image/webp', key: randomBytes(32), thumbnail: randomBytes(8) },
    };
    expect(parseProfileBody(serializeProfileBody(withAvatar))).toEqual(withAvatar);

    const contact = { op: ContactOp.REQUEST, intro: 'we met at the thing' };
    expect(parseContactBody(serializeContactBody(contact))).toEqual(contact);
  });

  it('rejects trailing bytes in every body type', () => {
    const cases: Array<[string, Uint8Array, (b: Uint8Array) => unknown]> = [
      ['text', serializeTextBody({ text: 'a', mentions: [], attachments: [] }), parseTextBody],
      ['edit', serializeEditBody({ target: randomBytes(32), text: 'a' }), parseEditBody],
      ['reaction', serializeReactionBody({ target: randomBytes(32), emoji: 'x', add: true }), parseReactionBody],
      ['receipt', serializeReceiptBody({ heads: [] }), parseReceiptBody],
      ['profile', serializeProfileBody({ displayName: 'a', statusText: '' }), parseProfileBody],
      ['contact', serializeContactBody({ op: 1, intro: '' }), parseContactBody],
    ];
    for (const [name, bytes, parse] of cases) {
      expect(() => parse(new Uint8Array([...bytes, 0])), name).toThrow(/trailing/);
    }
  });
});
