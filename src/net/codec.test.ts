import { describe, expect, it } from 'vitest';
import { concat, fromHex, toHex, utf8 } from '../common/bytes.js';
import {
  CodecError,
  HEADER_SIZE,
  MessageParser,
  ProtocolError,
  checksum,
  decodeCommand,
  encodeCommand,
  encodeHeader,
  encodeMessage,
} from './codec.js';
import { NetworkMagic } from './messages.js';

const magic = NetworkMagic.regtest;

describe('codec', () => {
  it('encodes a header and round-trips it through the parser', () => {
    const payload = utf8('hello world');
    const msg = encodeMessage(magic, 'ping', payload);
    expect(msg.length).toBe(HEADER_SIZE + payload.length);
    expect(toHex(msg.subarray(0, 4))).toBe('fdbf9ffb');
    expect(toHex(msg.subarray(4, 16))).toBe('70696e670000000000000000');
    expect(new DataView(msg.buffer).getUint32(16, true)).toBe(payload.length);
    expect(toHex(msg.subarray(20, 24))).toBe(toHex(checksum(payload)));

    const p = new MessageParser(magic);
    const out = p.feed(msg);
    expect(out).toHaveLength(1);
    expect(out[0]!.command).toBe('ping');
    expect(toHex(out[0]!.payload)).toBe(toHex(payload));
    expect(p.buffered).toBe(0);
  });

  it('checksum of an empty payload is 5df6e0e2', () => {
    expect(toHex(checksum(new Uint8Array(0)))).toBe('5df6e0e2');
    expect(toHex(encodeHeader(magic, 'verack', new Uint8Array(0)))).toBe(
      'fdbf9ffb76657261636b000000000000000000005df6e0e2',
    );
  });

  it('command field validation', () => {
    expect(() => encodeCommand('')).toThrow();
    expect(() => encodeCommand('thirteenchars')).toThrow();
    expect(() => encodeCommand('a b')).toThrow();
    expect(decodeCommand(encodeCommand('dp2pmsg'))).toBe('dp2pmsg');
    expect(decodeCommand(fromHex('76657261636b00ff0000000000'.slice(0, 24)))).toBeNull(); // byte after NUL
    expect(decodeCommand(new Uint8Array(12))).toBeNull();
  });

  it('resyncs on a garbage prefix and reports it', () => {
    const errors: CodecError[] = [];
    const p = new MessageParser(magic, { onError: (e) => errors.push(e) });
    const msg = encodeMessage(magic, 'verack');
    const out = p.feed(concat(fromHex('deadbeef0102030405'), msg));
    expect(out).toHaveLength(1);
    expect(out[0]!.command).toBe('verack');
    expect(errors).toHaveLength(1);
    expect(errors[0]!.message).toMatch(/skipped 9 byte/);
  });

  it('resyncs when garbage contains a partial magic straddling chunks', () => {
    const p = new MessageParser(magic);
    const msg = encodeMessage(magic, 'pong', fromHex('0102030405060708'));
    const stream = concat(fromHex('00fdbf'), msg); // "00 fd bf" then real message "fd bf 9f fb ..."
    const out = [...p.feed(stream.subarray(0, 5)), ...p.feed(stream.subarray(5))];
    expect(out).toHaveLength(1);
    expect(out[0]!.command).toBe('pong');
  });

  it('reassembles a stream fed one byte at a time, multiple messages', () => {
    const p = new MessageParser(magic);
    const a = encodeMessage(magic, 'ping', fromHex('0000000000000001'));
    const b = encodeMessage(magic, 'p2pmsg', new Uint8Array(300).fill(7));
    const c = encodeMessage(magic, 'verack');
    const stream = concat(a, b, c);
    const out = [];
    for (let i = 0; i < stream.length; i++) out.push(...p.feed(stream.subarray(i, i + 1)));
    expect(out.map((m) => m.command)).toEqual(['ping', 'p2pmsg', 'verack']);
    expect(out[1]!.payload.length).toBe(300);
    expect(out[1]!.payload.every((x) => x === 7)).toBe(true);
    expect(p.buffered).toBe(0);
  });

  it('drops a message with a bad checksum, reports it, and continues', () => {
    const errors: CodecError[] = [];
    const p = new MessageParser(magic, { onError: (e) => errors.push(e) });
    const bad = encodeMessage(magic, 'ping', fromHex('0000000000000001'));
    bad[21] ^= 0xff;
    const good = encodeMessage(magic, 'verack');
    const out = p.feed(concat(bad, good));
    expect(out.map((m) => m.command)).toEqual(['verack']);
    expect(errors).toHaveLength(1);
    expect(errors[0]!.command).toBe('ping');
    expect(errors[0]!.message).toMatch(/bad checksum/);
  });

  it('throws ProtocolError for an oversize payload announcement', () => {
    const p = new MessageParser(magic);
    const h = encodeHeader(magic, 'block', new Uint8Array(0));
    new DataView(h.buffer).setUint32(16, 4 * 1024 * 1024 + 1, true);
    expect(() => p.feed(h)).toThrow(ProtocolError);
  });

  it('respects a custom maxPayloadSize', () => {
    const p = new MessageParser(magic, { maxPayloadSize: 10 });
    expect(() => p.feed(encodeMessage(magic, 'x', new Uint8Array(11)))).toThrow(ProtocolError);
    expect(p.feed(encodeMessage(magic, 'x', new Uint8Array(10)))).toHaveLength(1);
  });

  it('does not deliver messages from another network', () => {
    const p = new MessageParser(NetworkMagic.mainnet);
    expect(p.feed(encodeMessage(NetworkMagic.testnet, 'verack'))).toHaveLength(0);
  });
});
