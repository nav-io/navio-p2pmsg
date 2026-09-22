/**
 * The BIP324 v2 handshake and framing, as a byte-stream state machine.
 *
 * Outbound (initiator) only: this SDK is a leaf that always dials and never
 * accepts, so the responder half is not implemented rather than implemented
 * and untested.
 *
 * Shape of the handshake, from our side:
 *
 *   ->  ellswift(64) ‖ garbage(0..4095)
 *   <-  ellswift(64) ‖ garbage(0..4095) ‖ terminator(16) ‖ version packet
 *   ->  terminator(16) ‖ version packet
 *
 * There is exactly ONE packet after each terminator. It is the version packet,
 * and its AAD is the sender's own garbage — so a single packet both carries
 * the version and proves the garbage was not tampered with. Sending a separate
 * "garbage authentication" packet as well makes the peer read the extra packet
 * as application data and drop the connection with "invalid message type".
 *
 * We cannot send our terminator until their key arrives, because the keys it
 * is derived from need both halves — hence the 1.5 round trips.
 */
import { concat } from '../../common/bytes.js';
import { decodeMessageType, encodeMessageType } from './msgids.js';
import { ellswiftCreate, ELLSWIFT_SIZE } from './ellswift.js';
import {
  AEAD_TAG_LEN,
  GARBAGE_TERMINATOR_LEN,
  HEADER_LEN,
  LENGTH_FIELD_LEN,
  MAX_GARBAGE_LEN,
  V2Cipher,
} from './transport.js';

/** v1 peers open with `magic ‖ "version" ‖ 0x00*5`. */
const V1_PREFIX_LEN = 16;

export type V2State =
  | 'awaiting-key'
  | 'awaiting-garbage'
  | 'awaiting-version'
  | 'ready'
  | 'v1-fallback'
  | 'failed';

export interface V2Message {
  command: string;
  payload: Uint8Array;
}

export interface V2ReceiveResult {
  /** Application messages decoded from complete packets. */
  messages: V2Message[];
  /** Bytes to write to the socket, if the state machine produced any. */
  send: Uint8Array | undefined;
  /**
   * The peer is speaking v1. `leftover` holds every byte received so far,
   * which the caller must hand to a v1 codec unchanged.
   */
  v1Fallback: boolean;
  leftover: Uint8Array | undefined;
}

export interface V2SessionOptions {
  /** Network message-start bytes; they go into the HKDF salt. */
  magic: Uint8Array;
  randomBytes: (n: number) => Uint8Array;
  /**
   * Fall back to v1 when the peer opens with the v1 prefix. Default true —
   * most of the network is still v1. Set false to require encryption.
   */
  allowV1Fallback?: boolean;
  /** Test hook: fixed garbage instead of random. */
  garbage?: Uint8Array;
}

function randomGarbage(randomBytes: (n: number) => Uint8Array): Uint8Array {
  // Uniform over 0..MAX_GARBAGE_LEN, matching navio-core. The length is the
  // point: a fixed-size prelude would be as recognisable as a magic number.
  const r = randomBytes(2);
  const len = ((r[0]! | (r[1]! << 8)) % (MAX_GARBAGE_LEN + 1)) | 0;
  return randomBytes(len);
}

export class V2Session {
  private readonly opts: Required<Omit<V2SessionOptions, 'garbage'>>;
  private readonly ourGarbage: Uint8Array;
  private readonly priv: Uint8Array;
  private readonly ellswift: Uint8Array;
  private readonly v1Prefix: Uint8Array;

  private buf: Uint8Array = new Uint8Array(0);
  private state: V2State = 'awaiting-key';
  private cipher: V2Cipher | undefined;
  private theirGarbage: Uint8Array = new Uint8Array(0);
  /** Length of the packet currently being assembled, once its field is decrypted. */
  private pendingLength: number | undefined;

  constructor(options: V2SessionOptions) {
    this.opts = {
      magic: options.magic,
      randomBytes: options.randomBytes,
      allowV1Fallback: options.allowV1Fallback ?? true,
    };
    this.v1Prefix = concat(options.magic, new Uint8Array([118, 101, 114, 115, 105, 111, 110, 0, 0, 0, 0, 0]));

    // Regenerate in the vanishing case where our key would open with the v1
    // prefix, which would make an honest peer treat us as a v1 node.
    for (;;) {
      const kp = ellswiftCreate(() => this.opts.randomBytes(32));
      if (!startsWith(kp.ellswift, this.v1Prefix)) {
        this.priv = kp.priv;
        this.ellswift = kp.ellswift;
        break;
      }
    }
    this.ourGarbage = options.garbage ?? randomGarbage(this.opts.randomBytes);
  }

  get currentState(): V2State {
    return this.state;
  }

  /** 32-byte session id, available once the handshake completes. */
  get sessionId(): Uint8Array | undefined {
    return this.cipher?.sessionId;
  }

  /** The bytes to write as soon as the connection opens. */
  start(): Uint8Array {
    return concat(this.ellswift, this.ourGarbage);
  }

  /** Frame an application message. Only valid once `ready`. */
  encode(command: string, payload: Uint8Array): Uint8Array {
    if (this.state !== 'ready' || !this.cipher) throw new Error('v2 session is not ready');
    return this.cipher.encryptPacket(concat(encodeMessageType(command), payload));
  }

  /** Feed inbound bytes and drive the state machine. */
  receive(data: Uint8Array): V2ReceiveResult {
    const out: V2ReceiveResult = { messages: [], send: undefined, v1Fallback: false, leftover: undefined };
    if (this.state === 'failed') return out;
    this.buf = concat(this.buf, data);
    const toSend: Uint8Array[] = [];

    for (;;) {
      if (this.state === 'awaiting-key') {
        if (this.detectV1(out)) return out;
        if (this.buf.length < ELLSWIFT_SIZE) break;
        const theirs = this.buf.slice(0, ELLSWIFT_SIZE);
        this.buf = this.buf.slice(ELLSWIFT_SIZE);
        this.cipher = V2Cipher.create(this.priv, this.ellswift, theirs, /*initiating=*/ true, this.opts.magic);
        // Our terminator, then the version packet. Its AAD is our own garbage,
        // which is what authenticates the garbage we already sent in the
        // clear. Contents are empty: BIP324 reserves them and defines no
        // fields yet.
        toSend.push(
          concat(this.cipher.sendGarbageTerminator, this.cipher.encryptPacket(new Uint8Array(0), this.ourGarbage)),
        );
        this.state = 'awaiting-garbage';
        continue;
      }

      if (this.state === 'awaiting-garbage') {
        const term = this.cipher!.recvGarbageTerminator;
        const idx = indexOfSub(this.buf, term, MAX_GARBAGE_LEN + 1);
        if (idx === undefined) {
          if (this.buf.length > MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN) {
            // No terminator within the maximum garbage: the peer is not
            // speaking v2 with these keys, and continuing would mean trial
            // decrypting arbitrary data.
            return this.fail(out, toSend);
          }
          break;
        }
        this.theirGarbage = this.buf.slice(0, idx);
        this.buf = this.buf.slice(idx + GARBAGE_TERMINATOR_LEN);
        this.state = 'awaiting-version';
        continue;
      }

      // Both handshake packets and application packets are framed the same
      // way; only the AAD and the disposition of the contents differ.
      const packet = this.readPacket();
      if (packet === 'incomplete') break;
      if (packet === 'error') return this.fail(out, toSend);

      if (this.state === 'awaiting-version') {
        // Contents are ignored; the value of this packet is that decrypting it
        // with their garbage as AAD proves the garbage arrived unaltered.
        this.state = 'ready';
        continue;
      }

      if (packet.ignore) continue; // decoy traffic
      const type = decodeMessageType(packet.contents);
      // An unassigned short id is a message from a newer peer, not an attack.
      if (type) out.messages.push({ command: type.command, payload: packet.contents.slice(type.size) });
    }

    if (toSend.length > 0) out.send = concat(...toSend);
    return out;
  }

  /**
   * Read one packet. The length field is decrypted as soon as its 3 bytes
   * arrive and cached, because the length cipher is stateful and must advance
   * exactly once per packet even if the body is still in flight.
   */
  private readPacket(): { contents: Uint8Array; ignore: boolean } | 'incomplete' | 'error' {
    if (this.pendingLength === undefined) {
      if (this.buf.length < LENGTH_FIELD_LEN) return 'incomplete';
      this.pendingLength = this.cipher!.decryptLength(this.buf.slice(0, LENGTH_FIELD_LEN));
      this.buf = this.buf.slice(LENGTH_FIELD_LEN);
    }
    const bodyLen = HEADER_LEN + this.pendingLength + AEAD_TAG_LEN;
    if (this.buf.length < bodyLen) return 'incomplete';
    const body = this.buf.slice(0, bodyLen);
    this.buf = this.buf.slice(bodyLen);
    const aad = this.state === 'awaiting-version' ? this.theirGarbage : undefined;
    this.pendingLength = undefined;
    try {
      return this.cipher!.decryptPacket(body, aad);
    } catch {
      // BIP324 cannot resynchronise after an authentication failure.
      return 'error';
    }
  }

  private detectV1(out: V2ReceiveResult): boolean {
    const n = Math.min(this.buf.length, V1_PREFIX_LEN);
    const matches = startsWith(this.v1Prefix.subarray(0, n), this.buf.subarray(0, n));
    if (!matches) return false;
    if (this.buf.length < V1_PREFIX_LEN) return true; // still ambiguous, wait
    if (!this.opts.allowV1Fallback) {
      this.state = 'failed';
      return true;
    }
    this.state = 'v1-fallback';
    out.v1Fallback = true;
    out.leftover = this.buf;
    this.buf = new Uint8Array(0);
    return true;
  }

  private fail(out: V2ReceiveResult, toSend: Uint8Array[]): V2ReceiveResult {
    this.state = 'failed';
    if (toSend.length > 0) out.send = concat(...toSend);
    return out;
  }
}

function startsWith(haystack: Uint8Array, prefix: Uint8Array): boolean {
  if (haystack.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (haystack[i] !== prefix[i]) return false;
  return true;
}

/** Index of `needle` in `hay`, searching no further than `limit` start offsets. */
function indexOfSub(hay: Uint8Array, needle: Uint8Array, limit: number): number | undefined {
  const last = Math.min(hay.length - needle.length, limit);
  outer: for (let i = 0; i <= last; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return undefined;
}
