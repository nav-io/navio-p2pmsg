import { describe, expect, it } from 'vitest';
import { randomBytes, toHex } from '../common/bytes.js';
import { loopbackPair } from './transport.js';
import {
  decryptFile,
  encryptFile,
  FileClient,
  FileServer,
  FILE_CHUNK_BYTES,
  parseFileMessage,
  serializeFileMessage,
  FileOp,
} from './file.js';
import { EphemeralOp, EphemeralSignals, parseEphemeral, PresenceState, serializeEphemeral, TypingState } from './ephemeral.js';

describe('file transfer', () => {
  function pair() {
    const [a, b] = loopbackPair();
    const server = new FileServer(a.channel('file'));
    const client = new FileClient(b.channel('file'));
    return { a, b, server, client };
  }

  it('transfers a file and verifies it by content hash', async () => {
    const { server, client } = pair();
    const plaintext = randomBytes(FILE_CHUNK_BYTES * 3 + 123);
    const { ciphertext, key, contentHash } = encryptFile(plaintext);
    server.offer(contentHash, ciphertext);

    const got = await client.fetch(contentHash, { timeoutMs: 10000 });
    expect(toHex(got)).toBe(toHex(ciphertext));
    // The key travels in the chat message, never with the bytes.
    expect(decryptFile(got, key)).toEqual(plaintext);
  });

  it('reports progress as chunks arrive', async () => {
    const { server, client } = pair();
    const { ciphertext, contentHash } = encryptFile(randomBytes(FILE_CHUNK_BYTES * 4));
    server.offer(contentHash, ciphertext);
    const seen: number[] = [];
    await client.fetch(contentHash, { timeoutMs: 10000, onProgress: (p) => seen.push(p.received) });
    expect(seen.length).toBeGreaterThan(1);
    expect(seen[seen.length - 1]).toBe(ciphertext.length);
  });

  it('denies a file it does not hold', async () => {
    const { client } = pair();
    await expect(client.fetch(randomBytes(32), { timeoutMs: 5000 })).rejects.toThrow(/denied/);
  });

  it('rejects bytes that do not match the hash', async () => {
    // Content addressing IS the integrity check: a peer cannot send different
    // bytes and have them accepted.
    const { server, client } = pair();
    const { ciphertext, contentHash } = encryptFile(randomBytes(100));
    const corrupted = ciphertext.slice();
    corrupted[0]! ^= 0xff;
    server.offer(contentHash, corrupted);
    await expect(client.fetch(contentHash, { timeoutMs: 5000 })).rejects.toThrow(/content hash/);
  });

  it('refuses a file key that does not belong to it', () => {
    const { ciphertext } = encryptFile(randomBytes(64));
    expect(() => decryptFile(ciphertext, randomBytes(32))).toThrow();
  });

  it('round trips every file message', () => {
    const hash = randomBytes(32);
    const cases = [
      { op: FileOp.REQUEST, contentHash: hash, offset: 5, length: 10 },
      { op: FileOp.HAVE, contentHash: hash, size: 99 },
      { op: FileOp.CHUNK, contentHash: hash, offset: 16, bytes: randomBytes(20) },
      { op: FileOp.DENY, contentHash: hash, reason: 'nope' },
      { op: FileOp.DONE, contentHash: hash },
    ] as const;
    for (const c of cases) expect(parseFileMessage(serializeFileMessage(c))).toEqual(c);
    expect(() => parseFileMessage(new Uint8Array([99, ...hash]))).toThrow(/unknown file op/);
  });

  it('will not fetch the same file twice at once', async () => {
    const { server, client } = pair();
    const { ciphertext, contentHash } = encryptFile(randomBytes(50));
    server.offer(contentHash, ciphertext);
    const first = client.fetch(contentHash, { timeoutMs: 5000 });
    await expect(client.fetch(contentHash, { timeoutMs: 5000 })).rejects.toThrow(/already fetching/);
    await first;
  });

  it('stops serving a withdrawn file', async () => {
    const { server, client } = pair();
    const { ciphertext, contentHash } = encryptFile(randomBytes(50));
    server.offer(contentHash, ciphertext);
    server.withdraw(contentHash);
    await expect(client.fetch(contentHash, { timeoutMs: 5000 })).rejects.toThrow(/denied/);
  });
});

describe('typing and presence', () => {
  it('delivers typing and presence over the control channel', async () => {
    const [a, b] = loopbackPair();
    const received: unknown[] = [];
    const rx = new EphemeralSignals(b.channel('control'), (m) => received.push(m));
    let clock = 0;
    const tx = new EphemeralSignals(a.channel('control'), () => {}, () => clock, 3000);

    const conv = randomBytes(32);
    tx.typing(conv);
    clock += 5000;
    tx.typing(conv);
    tx.stoppedTyping(conv);
    tx.presence(PresenceState.ONLINE);
    await new Promise((r) => setTimeout(r, 20));

    expect(received).toHaveLength(4);
    rx.close();
    tx.close();
  });

  it('coalesces repeated typing calls', async () => {
    // A keystroke handler calls this on every key; the peer needs a heartbeat,
    // not a packet per character.
    const [a, b] = loopbackPair();
    const received: unknown[] = [];
    new EphemeralSignals(b.channel('control'), (m) => received.push(m));
    let clock = 0;
    const tx = new EphemeralSignals(a.channel('control'), () => {}, () => clock, 3000);
    const conv = randomBytes(32);
    for (let i = 0; i < 20; i++) tx.typing(conv);
    await new Promise((r) => setTimeout(r, 20));
    expect(received).toHaveLength(1);
  });

  it('never throttles "stopped", which would otherwise show forever', async () => {
    const [a, b] = loopbackPair();
    const received: unknown[] = [];
    new EphemeralSignals(b.channel('control'), (m) => received.push(m));
    let clock = 0;
    const tx = new EphemeralSignals(a.channel('control'), () => {}, () => clock, 100000);
    const conv = randomBytes(32);
    tx.typing(conv);
    tx.stoppedTyping(conv);
    await new Promise((r) => setTimeout(r, 20));
    expect(received).toHaveLength(2);
  });

  it('round trips the wire form', () => {
    const conv = randomBytes(32);
    const typing = { op: EphemeralOp.TYPING, convId: conv, state: TypingState.STOPPED } as const;
    expect(parseEphemeral(serializeEphemeral(typing))).toEqual(typing);
    const presence = { op: EphemeralOp.PRESENCE, state: PresenceState.AWAY, since: 1700000000n } as const;
    expect(parseEphemeral(serializeEphemeral(presence))).toEqual(presence);
    expect(() => parseEphemeral(new Uint8Array([9]))).toThrow(/unknown ephemeral op/);
  });
});

describe('loopback transport', () => {
  it('delivers asynchronously, like a real transport', async () => {
    const [a, b] = loopbackPair();
    let got = false;
    b.channel('control').onMessage(() => (got = true));
    a.channel('control').send(new Uint8Array([1]));
    // Code that assumed synchronous delivery would pass here and fail over a
    // socket, so the loopback must not be synchronous either.
    expect(got).toBe(false);
    await new Promise((r) => setTimeout(r, 5));
    expect(got).toBe(true);
  });

  it('closes both ends together', () => {
    const [a, b] = loopbackPair();
    let closed = false;
    b.onClose(() => (closed = true));
    a.close();
    expect(a.closed).toBe(true);
    expect(b.closed).toBe(true);
    expect(closed).toBe(true);
  });
});

describe('stream signalling', () => {
  it('round trips every signal op', async () => {
    const { parseSignal, serializeSignal, SignalOp } = await import('./signal.js');
    const sessionId = randomBytes(16);
    for (const op of [SignalOp.OFFER, SignalOp.ANSWER, SignalOp.CANDIDATE, SignalOp.CLOSE]) {
      const s = { op, sessionId, data: op === SignalOp.CLOSE ? '' : 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n' };
      expect(parseSignal(serializeSignal(s))).toEqual(s);
    }
  });

  it('rejects an unknown op and a bad session id', async () => {
    const { parseSignal, serializeSignal } = await import('./signal.js');
    expect(() => serializeSignal({ op: 9, sessionId: randomBytes(16), data: '' })).toThrow(/unknown signal op/);
    expect(() => serializeSignal({ op: 1, sessionId: randomBytes(8), data: '' })).toThrow(/16 bytes/);
    expect(() => parseSignal(new Uint8Array([9, ...randomBytes(16), 0]))).toThrow(/unknown signal op/);
  });
});
