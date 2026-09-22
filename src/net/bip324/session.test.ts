import { describe, expect, it } from 'vitest';
import { concat, randomBytes, utf8 } from '../../common/bytes.js';
import { decodeMessageType, encodeMessageType } from './msgids.js';
import { ellswiftCreate, ELLSWIFT_SIZE } from './ellswift.js';
import { GARBAGE_TERMINATOR_LEN, LENGTH_FIELD_LEN, HEADER_LEN, AEAD_TAG_LEN, V2Cipher } from './transport.js';
import { V2Session } from './session.js';

const MAGIC = new Uint8Array([0xfd, 0xbf, 0x9f, 0xfb]); // regtest

/**
 * Minimal responder, test-only. It mirrors the initiator from the other side so
 * the state machine can be driven end to end without a node. It shares this
 * implementation's assumptions, so it proves framing and buffering, NOT
 * conformance — that is what the BIP's packet vectors and the integration test
 * against naviod are for.
 */
class Responder {
  readonly ellswift: Uint8Array;
  private readonly priv: Uint8Array;
  cipher!: V2Cipher;
  private buf: Uint8Array = new Uint8Array(0);
  private garbage: Uint8Array;
  private handshakeDone = false;
  private packets = 0;

  constructor(garbageLen = 17) {
    const kp = ellswiftCreate(() => randomBytes(32));
    this.priv = kp.priv;
    this.ellswift = kp.ellswift;
    this.garbage = randomBytes(garbageLen);
  }

  /** Everything the responder sends, once it has the initiator's key. */
  respond(initiatorEllswift: Uint8Array): Uint8Array {
    this.cipher = V2Cipher.create(this.priv, this.ellswift, initiatorEllswift, false, MAGIC);
    return concat(
      this.ellswift,
      this.garbage,
      this.cipher.sendGarbageTerminator,
      this.cipher.encryptPacket(new Uint8Array(0), this.garbage),
    );
  }

  encode(command: string, payload: Uint8Array): Uint8Array {
    return this.cipher.encryptPacket(concat(encodeMessageType(command), payload));
  }

  /** Consume initiator bytes; returns decoded application messages. */
  feed(data: Uint8Array): { command: string; payload: Uint8Array }[] {
    this.buf = concat(this.buf, data);
    const out: { command: string; payload: Uint8Array }[] = [];
    if (!this.handshakeDone) {
      const term = this.cipher.recvGarbageTerminator;
      const idx = indexOf(this.buf, term);
      if (idx === undefined) return out;
      this.buf = this.buf.slice(idx + GARBAGE_TERMINATOR_LEN);
      this.handshakeDone = true;
    }
    for (;;) {
      if (this.buf.length < LENGTH_FIELD_LEN) break;
      const len = this.cipher.decryptLength(this.buf.slice(0, LENGTH_FIELD_LEN));
      const bodyLen = HEADER_LEN + len + AEAD_TAG_LEN;
      if (this.buf.length < LENGTH_FIELD_LEN + bodyLen) throw new Error('responder: split packet not handled');
      const body = this.buf.slice(LENGTH_FIELD_LEN, LENGTH_FIELD_LEN + bodyLen);
      this.buf = this.buf.slice(LENGTH_FIELD_LEN + bodyLen);
      const p = this.cipher.decryptPacket(body, this.packets === 0 ? this.initiatorGarbage : undefined);
      this.packets++;
      if (this.packets <= 1) continue; // the version packet
      const t = decodeMessageType(p.contents);
      if (t) out.push({ command: t.command, payload: p.contents.slice(t.size) });
    }
    return out;
  }

  initiatorGarbage: Uint8Array = new Uint8Array(0);
}

function indexOf(hay: Uint8Array, needle: Uint8Array): number | undefined {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return undefined;
}

function handshake(garbage: Uint8Array, responderGarbageLen = 17) {
  const session = new V2Session({ magic: MAGIC, randomBytes, garbage });
  const responder = new Responder(responderGarbageLen);
  const first = session.start();
  expect(first.length).toBe(ELLSWIFT_SIZE + garbage.length);
  responder.initiatorGarbage = garbage;
  const reply = responder.respond(first.slice(0, ELLSWIFT_SIZE));
  return { session, responder, reply };
}

describe('V2Session handshake', () => {
  it('completes and exchanges messages in both directions', () => {
    const garbage = randomBytes(64);
    const { session, responder, reply } = handshake(garbage);

    const res = session.receive(reply);
    expect(res.v1Fallback).toBe(false);
    expect(session.currentState).toBe('ready');
    expect(session.sessionId).toHaveLength(32);
    expect(res.send).toBeDefined();
    responder.feed(res.send!);

    // Initiator -> responder.
    const got = responder.feed(session.encode('ping', utf8('hello')));
    expect(got).toHaveLength(1);
    expect(got[0]!.command).toBe('ping');
    expect(got[0]!.payload).toEqual(utf8('hello'));

    // Responder -> initiator, including a long-form command with no short id.
    const back = session.receive(responder.encode('p2pmsg', utf8('envelope')));
    expect(back.messages).toHaveLength(1);
    expect(back.messages[0]!.command).toBe('p2pmsg');
    expect(back.messages[0]!.payload).toEqual(utf8('envelope'));
  });

  it('survives the reply arriving one byte at a time', () => {
    // A real socket splits wherever it likes, and the length cipher must
    // advance exactly once per packet no matter how the bytes are diced.
    const garbage = randomBytes(300);
    const { session, responder, reply } = handshake(garbage, 4095);
    for (const b of reply) {
      const r = session.receive(new Uint8Array([b]));
      if (r.send) responder.feed(r.send);
    }
    expect(session.currentState).toBe('ready');

    const msg = responder.encode('addrv2', utf8('x'));
    let messages: { command: string }[] = [];
    for (const b of msg) messages = messages.concat(session.receive(new Uint8Array([b])).messages);
    expect(messages).toHaveLength(1);
    expect(messages[0]!.command).toBe('addrv2');
  });

  it('handles empty garbage on both sides', () => {
    const { session, responder, reply } = handshake(new Uint8Array(0), 0);
    const res = session.receive(reply);
    expect(session.currentState).toBe('ready');
    responder.feed(res.send!);
    expect(responder.feed(session.encode('pong', new Uint8Array(8)))).toHaveLength(1);
  });

  it('falls back when the peer opens with the v1 prefix', () => {
    const session = new V2Session({ magic: MAGIC, randomBytes });
    session.start();
    const v1 = concat(MAGIC, utf8('version'), new Uint8Array(5), randomBytes(20));
    const res = session.receive(v1);
    expect(res.v1Fallback).toBe(true);
    expect(session.currentState).toBe('v1-fallback');
    // The caller needs every byte, including the ones we consumed to decide.
    expect(res.leftover).toEqual(v1);
  });

  it('waits before deciding when only part of the v1 prefix has arrived', () => {
    const session = new V2Session({ magic: MAGIC, randomBytes });
    session.start();
    const res = session.receive(MAGIC);
    expect(res.v1Fallback).toBe(false);
    expect(session.currentState).toBe('awaiting-key');
  });

  it('refuses v1 when fallback is disabled', () => {
    const session = new V2Session({ magic: MAGIC, randomBytes, allowV1Fallback: false });
    session.start();
    const res = session.receive(concat(MAGIC, utf8('version'), new Uint8Array(5)));
    expect(res.v1Fallback).toBe(false);
    expect(session.currentState).toBe('failed');
  });

  it('fails when no garbage terminator ever appears', () => {
    // Otherwise we would trial-decrypt unbounded attacker-chosen data.
    const { session, responder } = handshake(new Uint8Array(0));
    session.receive(responder.ellswift);
    session.receive(randomBytes(4200));
    expect(session.currentState).toBe('failed');
  });

  it('fails on a tampered packet rather than resynchronising', () => {
    const garbage = randomBytes(8);
    const { session, responder, reply } = handshake(garbage);
    session.receive(reply);
    expect(session.currentState).toBe('ready');
    const msg = responder.encode('ping', utf8('x'));
    msg[msg.length - 1]! ^= 1;
    session.receive(msg);
    expect(session.currentState).toBe('failed');
  });

  it('refuses to encode before the handshake completes', () => {
    const session = new V2Session({ magic: MAGIC, randomBytes });
    expect(() => session.encode('ping', new Uint8Array(0))).toThrow(/not ready/);
  });
});

describe('v2 message ids', () => {
  it('uses short ids where BIP324 assigns them', () => {
    expect(encodeMessageType('ping')).toEqual(new Uint8Array([18]));
    expect(encodeMessageType('pong')).toEqual(new Uint8Array([19]));
    expect(encodeMessageType('addr')).toEqual(new Uint8Array([1]));
    expect(encodeMessageType('addrv2')).toEqual(new Uint8Array([28]));
    // Navio's own assignment. It is the only way this message type is
    // reachable at all: its name is 13 characters, one over v1's limit.
    expect(encodeMessageType('getoutputdata')).toEqual(new Uint8Array([29]));
  });

  it('uses the 13-byte form for everything else', () => {
    for (const cmd of ['version', 'verack', 'sendaddrv2', 'getaddr', 'p2pmsg', 'dp2pmsg', 'getp2pmsgs', 'p2pmsgs']) {
      const enc = encodeMessageType(cmd);
      expect(enc.length, cmd).toBe(13);
      expect(enc[0], cmd).toBe(0);
      expect(decodeMessageType(enc), cmd).toEqual({ command: cmd, size: 13 });
    }
  });

  it('round trips every short id', () => {
    for (const cmd of ['addr', 'block', 'ping', 'pong', 'tx', 'inv', 'addrv2']) {
      expect(decodeMessageType(encodeMessageType(cmd))).toEqual({ command: cmd, size: 1 });
    }
  });

  it('rejects truncated and unassigned ids', () => {
    expect(decodeMessageType(new Uint8Array(0))).toBeUndefined();
    expect(decodeMessageType(new Uint8Array([0, 1, 2]))).toBeUndefined(); // truncated long form
    expect(decodeMessageType(new Uint8Array([31]))).toBeUndefined(); // unassigned
    expect(decodeMessageType(new Uint8Array([200]))).toBeUndefined(); // out of table
  });

  it('refuses a command too long for the long form', () => {
    expect(() => encodeMessageType('thisiswaytoolong')).toThrow(/12 bytes/);
  });
});
