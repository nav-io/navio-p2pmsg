/**
 * Bitcoin P2P message framing.
 *
 *   header (24 bytes) = magic(4) | command(12, NUL-padded ASCII) | length(u32le) | checksum(4)
 *   checksum          = first 4 bytes of SHA256(SHA256(payload))
 */
import { sha256 } from '@noble/hashes/sha256';
import { concat, equal } from '../common/bytes.js';

export const HEADER_SIZE = 24;
export const COMMAND_SIZE = 12;
/** Hard cap on a single payload. Anything larger is a protocol error (the bus never needs > 4 KiB). */
export const MAX_PAYLOAD_SIZE = 4 * 1024 * 1024;

export interface ParsedMessage {
  command: string;
  payload: Uint8Array;
}

/** Fatal framing error: the stream cannot be trusted any more; the caller should disconnect. */
export class ProtocolError extends Error {
  override readonly name = 'ProtocolError';
}

/** Recoverable framing problem (bad checksum, garbage skipped). Reported, then parsing continues. */
export class CodecError extends Error {
  override readonly name = 'CodecError';
  constructor(
    message: string,
    readonly command?: string,
  ) {
    super(message);
  }
}

export function checksum(payload: Uint8Array): Uint8Array {
  return sha256(sha256(payload)).subarray(0, 4);
}

export function encodeCommand(command: string): Uint8Array {
  if (command.length === 0 || command.length > COMMAND_SIZE) {
    throw new Error(`invalid command length: ${JSON.stringify(command)}`);
  }
  const out = new Uint8Array(COMMAND_SIZE);
  for (let i = 0; i < command.length; i++) {
    const c = command.charCodeAt(i);
    if (c < 0x21 || c > 0x7e) throw new Error(`invalid command character: ${JSON.stringify(command)}`);
    out[i] = c;
  }
  return out;
}

/** Decode a 12-byte command field. Returns null if it is malformed (non-ASCII or bytes after the first NUL). */
export function decodeCommand(field: Uint8Array): string | null {
  let s = '';
  let ended = false;
  for (let i = 0; i < COMMAND_SIZE; i++) {
    const c = field[i]!;
    if (c === 0) {
      ended = true;
      continue;
    }
    if (ended || c < 0x21 || c > 0x7e) return null;
    s += String.fromCharCode(c);
  }
  return s.length === 0 ? null : s;
}

export function encodeHeader(magic: Uint8Array, command: string, payload: Uint8Array): Uint8Array {
  if (magic.length !== 4) throw new Error('magic must be 4 bytes');
  const h = new Uint8Array(HEADER_SIZE);
  h.set(magic, 0);
  h.set(encodeCommand(command), 4);
  new DataView(h.buffer).setUint32(16, payload.length, true);
  h.set(checksum(payload), 20);
  return h;
}

export function encodeMessage(
  magic: Uint8Array,
  command: string,
  payload: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return concat(encodeHeader(magic, command, payload), payload);
}

export interface MessageParserOptions {
  /** Override the payload size cap. Default `MAX_PAYLOAD_SIZE`. */
  maxPayloadSize?: number;
  /** Called for recoverable problems (bad checksum, skipped garbage). */
  onError?: (err: CodecError) => void;
}

function indexOf(hay: Uint8Array, needle: Uint8Array, from: number): number {
  const n = needle.length;
  outer: for (let i = from; i + n <= hay.length; i++) {
    for (let j = 0; j < n; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/**
 * Incremental parser over a byte stream. Feed it arbitrary chunks and it
 * returns complete messages. Resynchronises on the next magic when the stream
 * does not start with one; drops messages with a bad checksum (reported via
 * `onError`); throws `ProtocolError` when a header announces an oversize payload.
 */
export class MessageParser {
  private buf: Uint8Array = new Uint8Array(0);
  private readonly maxPayloadSize: number;
  private readonly onError: ((err: CodecError) => void) | undefined;

  constructor(
    readonly magic: Uint8Array,
    opts: MessageParserOptions = {},
  ) {
    if (magic.length !== 4) throw new Error('magic must be 4 bytes');
    this.maxPayloadSize = opts.maxPayloadSize ?? MAX_PAYLOAD_SIZE;
    this.onError = opts.onError;
  }

  /** Bytes currently buffered and not yet consumed. */
  get buffered(): number {
    return this.buf.length;
  }

  feed(chunk: Uint8Array): ParsedMessage[] {
    this.buf = this.buf.length === 0 ? chunk.slice() : concat(this.buf, chunk);
    const out: ParsedMessage[] = [];
    let pos = 0;
    const buf = this.buf;

    for (;;) {
      // Resync: make sure the window starts with the magic.
      if (buf.length - pos >= 4 && !equal(buf.subarray(pos, pos + 4), this.magic)) {
        const next = indexOf(buf, this.magic, pos + 1);
        const skipped = (next < 0 ? buf.length : next) - pos;
        this.report(`skipped ${skipped} byte(s) of garbage before magic`);
        if (next < 0) {
          // Keep the last 3 bytes in case the magic straddles chunks.
          pos = Math.max(pos, buf.length - 3);
          break;
        }
        pos = next;
      }
      if (buf.length - pos < HEADER_SIZE) break;

      const command = decodeCommand(buf.subarray(pos + 4, pos + 16));
      const length = new DataView(buf.buffer, buf.byteOffset + pos + 16, 4).getUint32(0, true);
      if (command === null) {
        this.report('malformed command field; resyncing');
        pos += 1;
        continue;
      }
      if (length > this.maxPayloadSize) {
        this.buf = new Uint8Array(0);
        throw new ProtocolError(`oversized payload for '${command}': ${length} > ${this.maxPayloadSize}`);
      }
      const total = HEADER_SIZE + length;
      if (buf.length - pos < total) break;

      const payload = buf.slice(pos + HEADER_SIZE, pos + total);
      const want = buf.subarray(pos + 20, pos + 24);
      pos += total;
      if (!equal(checksum(payload), want)) {
        this.report(`bad checksum for '${command}'`, command);
        continue;
      }
      out.push({ command, payload });
    }

    this.buf = pos === 0 ? buf : buf.slice(pos);
    return out;
  }

  reset(): void {
    this.buf = new Uint8Array(0);
  }

  private report(msg: string, command?: string): void {
    this.onError?.(new CodecError(msg, command));
  }
}
