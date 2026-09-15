/**
 * Bitcoin-style serialisation primitives (little-endian ints, CompactSize).
 * Matches navio-core's serialize.h for the subset the bus uses.
 */
import { concat } from './bytes.js';

export class Writer {
  private parts: Uint8Array[] = [];

  bytes(b: Uint8Array): this {
    this.parts.push(b);
    return this;
  }
  u8(v: number): this {
    return this.bytes(new Uint8Array([v & 0xff]));
  }
  u16(v: number): this {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    return this.bytes(b);
  }
  u32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    return this.bytes(b);
  }
  i32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setInt32(0, v, true);
    return this.bytes(b);
  }
  u64(v: bigint): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, v), true);
    return this.bytes(b);
  }
  i64(v: bigint): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, v, true);
    return this.bytes(b);
  }
  compactSize(n: number | bigint): this {
    const v = BigInt(n);
    if (v < 0n) throw new Error('negative compactsize');
    if (v < 253n) return this.u8(Number(v));
    if (v <= 0xffffn) return this.u8(253).u16(Number(v));
    if (v <= 0xffffffffn) return this.u8(254).u32(Number(v));
    return this.u8(255).u64(v);
  }
  /** CompactSize length prefix + bytes (std::vector<uint8_t>). */
  varBytes(b: Uint8Array): this {
    return this.compactSize(b.length).bytes(b);
  }
  /** CompactSize length prefix + UTF-8 bytes (std::string). */
  varString(s: string): this {
    return this.varBytes(new TextEncoder().encode(s));
  }
  finish(): Uint8Array {
    return concat(...this.parts);
  }
}

export class Reader {
  pos = 0;
  private view: DataView;
  constructor(public readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  get remaining(): number {
    return this.buf.length - this.pos;
  }
  private need(n: number): void {
    if (this.pos + n > this.buf.length) throw new Error('unexpected end of data');
  }
  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u8(): number {
    this.need(1);
    return this.buf[this.pos++]!;
  }
  u16(): number {
    this.need(2);
    const v = this.view.getUint16(this.pos, true);
    this.pos += 2;
    return v;
  }
  u32(): number {
    this.need(4);
    const v = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  }
  i32(): number {
    this.need(4);
    const v = this.view.getInt32(this.pos, true);
    this.pos += 4;
    return v;
  }
  u64(): bigint {
    this.need(8);
    const v = this.view.getBigUint64(this.pos, true);
    this.pos += 8;
    return v;
  }
  i64(): bigint {
    this.need(8);
    const v = this.view.getBigInt64(this.pos, true);
    this.pos += 8;
    return v;
  }
  compactSize(): number {
    const first = this.u8();
    let v: bigint;
    if (first < 253) v = BigInt(first);
    else if (first === 253) {
      v = BigInt(this.u16());
      if (v < 253n) throw new Error('non-canonical compactsize');
    } else if (first === 254) {
      v = BigInt(this.u32());
      if (v < 0x10000n) throw new Error('non-canonical compactsize');
    } else {
      v = this.u64();
      if (v < 0x100000000n) throw new Error('non-canonical compactsize');
    }
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('compactsize too large');
    return Number(v);
  }
  varBytes(): Uint8Array {
    const n = this.compactSize();
    return this.bytes(n);
  }
  varString(): string {
    return new TextDecoder().decode(this.varBytes());
  }
  /** Throw if any bytes remain (envelope parsing rejects trailing data). */
  assertDone(): void {
    if (this.pos !== this.buf.length) throw new Error('trailing bytes');
  }
}
