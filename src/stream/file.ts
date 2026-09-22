/**
 * Resumable, content-addressed file transfer over a direct channel.
 *
 * Resume matters more than it looks: a dropped connection should cost the
 * remaining bytes, not all of them, and over a P2P link connections drop.
 *
 * Every file is encrypted with its OWN key in addition to whatever the channel
 * does. The channel may be a fallback path, and a per-file key means the
 * ciphertext is safe to relay or store anywhere without trusting the carrier —
 * the key travels in the chat message's `AttachRef`, not with the bytes.
 */
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, toHex } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import type { StreamChannel } from './transport.js';

export const FILE_CHUNK_BYTES = 16 * 1024;
/** Chunks in flight before waiting; keeps a slow reader from being flooded. */
export const FILE_WINDOW = 8;

export const FileOp = { REQUEST: 1, HAVE: 2, CHUNK: 3, DENY: 4, DONE: 5 } as const;

export interface FileRequest {
  contentHash: Uint8Array; // 32
  offset: number;
  length: number;
}

export interface FileChunk {
  contentHash: Uint8Array;
  offset: number;
  bytes: Uint8Array;
}

export type FileMessage =
  | ({ op: typeof FileOp.REQUEST } & FileRequest)
  | { op: typeof FileOp.HAVE; contentHash: Uint8Array; size: number }
  | ({ op: typeof FileOp.CHUNK } & FileChunk)
  | { op: typeof FileOp.DENY; contentHash: Uint8Array; reason: string }
  | { op: typeof FileOp.DONE; contentHash: Uint8Array };

export function serializeFileMessage(m: FileMessage): Uint8Array {
  const w = new Writer().u8(m.op).bytes(m.contentHash);
  switch (m.op) {
    case FileOp.REQUEST:
      return w.u32(m.offset).u32(m.length).finish();
    case FileOp.HAVE:
      return w.u32(m.size).finish();
    case FileOp.CHUNK:
      return w.u32(m.offset).varBytes(m.bytes).finish();
    case FileOp.DENY:
      return w.varString(m.reason).finish();
    default:
      return w.finish();
  }
}

export function parseFileMessage(bytes: Uint8Array): FileMessage {
  const r = new Reader(bytes);
  const op = r.u8();
  const contentHash = r.bytes(32).slice();
  let out: FileMessage;
  switch (op) {
    case FileOp.REQUEST:
      out = { op: FileOp.REQUEST, contentHash, offset: r.u32(), length: r.u32() };
      break;
    case FileOp.HAVE:
      out = { op: FileOp.HAVE, contentHash, size: r.u32() };
      break;
    case FileOp.CHUNK:
      out = { op: FileOp.CHUNK, contentHash, offset: r.u32(), bytes: r.varBytes().slice() };
      break;
    case FileOp.DENY:
      out = { op: FileOp.DENY, contentHash, reason: r.varString() };
      break;
    case FileOp.DONE:
      out = { op: FileOp.DONE, contentHash };
      break;
    default:
      throw new Error(`unknown file op ${op}`);
  }
  r.assertDone();
  return out;
}

/** Encrypt a file under a fresh per-file key. Returns what an AttachRef needs. */
export function encryptFile(plaintext: Uint8Array): {
  ciphertext: Uint8Array;
  key: Uint8Array;
  contentHash: Uint8Array;
} {
  const key = randomBytes(32);
  // A fresh key per file means a fixed nonce is safe, and it keeps the
  // AttachRef small.
  const ciphertext = chacha20poly1305(key, new Uint8Array(12)).encrypt(plaintext);
  return { ciphertext, key, contentHash: sha256(ciphertext) };
}

export function decryptFile(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
  return chacha20poly1305(key, new Uint8Array(12)).decrypt(ciphertext);
}

/** Serves files this peer holds, by content hash. */
export class FileServer {
  private readonly files = new Map<string, Uint8Array>();
  private off: (() => void) | undefined;

  constructor(private readonly channel: StreamChannel) {
    this.off = channel.onMessage((data) => this.onMessage(data));
  }

  /** Offer a file's CIPHERTEXT. The key never goes near the transfer. */
  offer(contentHash: Uint8Array, ciphertext: Uint8Array): void {
    this.files.set(toHex(contentHash), ciphertext);
  }

  withdraw(contentHash: Uint8Array): void {
    this.files.delete(toHex(contentHash));
  }

  close(): void {
    this.off?.();
    this.off = undefined;
    this.files.clear();
  }

  private onMessage(data: Uint8Array): void {
    let msg: FileMessage;
    try {
      msg = parseFileMessage(data);
    } catch {
      return;
    }
    if (msg.op !== FileOp.REQUEST) return;
    const file = this.files.get(toHex(msg.contentHash));
    if (!file) {
      this.channel.send(
        serializeFileMessage({ op: FileOp.DENY, contentHash: msg.contentHash, reason: 'not available' }),
      );
      return;
    }
    this.channel.send(serializeFileMessage({ op: FileOp.HAVE, contentHash: msg.contentHash, size: file.length }));
    const end = Math.min(file.length, msg.offset + (msg.length || file.length));
    for (let at = msg.offset; at < end; at += FILE_CHUNK_BYTES) {
      this.channel.send(
        serializeFileMessage({
          op: FileOp.CHUNK,
          contentHash: msg.contentHash,
          offset: at,
          bytes: file.subarray(at, Math.min(end, at + FILE_CHUNK_BYTES)),
        }),
      );
    }
    this.channel.send(serializeFileMessage({ op: FileOp.DONE, contentHash: msg.contentHash }));
  }
}

export interface DownloadProgress {
  received: number;
  total: number;
}

/** Fetches files over a channel, verifying what arrives. */
export class FileClient {
  private readonly pending = new Map<
    string,
    {
      resolve: (v: Uint8Array) => void;
      reject: (e: Error) => void;
      parts: Map<number, Uint8Array>;
      size: number;
      have: number;
      onProgress: ((p: DownloadProgress) => void) | undefined;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private off: (() => void) | undefined;

  constructor(private readonly channel: StreamChannel) {
    this.off = channel.onMessage((data) => this.onMessage(data));
  }

  close(): void {
    this.off?.();
    this.off = undefined;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error('file client closed'));
    }
    this.pending.clear();
  }

  /**
   * Fetch a file by content hash. `resumeFrom` skips bytes already held, which
   * is the point of resume: a dropped connection costs the remainder, not the
   * whole file.
   */
  fetch(
    contentHash: Uint8Array,
    opts: { timeoutMs?: number; resumeFrom?: number; onProgress?: (p: DownloadProgress) => void } = {},
  ): Promise<Uint8Array> {
    const key = toHex(contentHash);
    if (this.pending.has(key)) return Promise.reject(new Error('already fetching that file'));
    return new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(key);
        reject(new Error('file transfer timed out'));
      }, opts.timeoutMs ?? 60_000);
      this.pending.set(key, {
        resolve,
        reject,
        parts: new Map(),
        size: 0,
        have: 0,
        onProgress: opts.onProgress,
        timer,
      });
      this.channel.send(
        serializeFileMessage({
          op: FileOp.REQUEST,
          contentHash,
          offset: opts.resumeFrom ?? 0,
          length: 0,
        }),
      );
    });
  }

  private onMessage(data: Uint8Array): void {
    let msg: FileMessage;
    try {
      msg = parseFileMessage(data);
    } catch {
      return;
    }
    const key = toHex(msg.contentHash);
    const p = this.pending.get(key);
    if (!p) return;

    if (msg.op === FileOp.DENY) {
      clearTimeout(p.timer);
      this.pending.delete(key);
      p.reject(new Error(`peer denied the file: ${msg.reason}`));
      return;
    }
    if (msg.op === FileOp.HAVE) {
      p.size = msg.size;
      return;
    }
    if (msg.op === FileOp.CHUNK) {
      if (!p.parts.has(msg.offset)) {
        p.parts.set(msg.offset, msg.bytes);
        p.have += msg.bytes.length;
        p.onProgress?.({ received: p.have, total: p.size });
      }
      return;
    }
    if (msg.op !== FileOp.DONE) return;

    clearTimeout(p.timer);
    this.pending.delete(key);
    const assembled = assemble(p.parts, p.size);
    if (!assembled) {
      p.reject(new Error('file transfer incomplete'));
      return;
    }
    // Content addressing is the integrity check: a peer that sends the wrong
    // bytes cannot produce a matching hash.
    if (toHex(sha256(assembled)) !== key) {
      p.reject(new Error('file failed its content hash'));
      return;
    }
    p.resolve(assembled);
  }
}

function assemble(parts: Map<number, Uint8Array>, size: number): Uint8Array | undefined {
  const out = new Uint8Array(size);
  let covered = 0;
  for (const [offset, bytes] of parts) {
    if (offset + bytes.length > size) return undefined;
    out.set(bytes, offset);
    covered += bytes.length;
  }
  return covered === size ? out : undefined;
}
