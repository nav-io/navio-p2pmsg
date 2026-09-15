import { describe, expect, it } from 'vitest';
import { Reader, Writer } from './serialize.js';
import { toHex } from './bytes.js';

describe('serialize', () => {
  it('compactsize encodes like bitcoin', () => {
    expect(toHex(new Writer().compactSize(0).finish())).toBe('00');
    expect(toHex(new Writer().compactSize(252).finish())).toBe('fc');
    expect(toHex(new Writer().compactSize(253).finish())).toBe('fdfd00');
    expect(toHex(new Writer().compactSize(0x10000).finish())).toBe('fe00000100');
    expect(toHex(new Writer().compactSize(0x100000000n).finish())).toBe('ff0000000001000000');
  });
  it('round trips ints', () => {
    const w = new Writer().u8(1).u16(0x1234).u32(0xdeadbeef).i64(-5n).u64(2n ** 63n).varString('hi');
    const r = new Reader(w.finish());
    expect(r.u8()).toBe(1);
    expect(r.u16()).toBe(0x1234);
    expect(r.u32()).toBe(0xdeadbeef);
    expect(r.i64()).toBe(-5n);
    expect(r.u64()).toBe(2n ** 63n);
    expect(r.varString()).toBe('hi');
    r.assertDone();
  });
  it('rejects non-canonical compactsize', () => {
    expect(() => new Reader(new Uint8Array([0xfd, 0x01, 0x00])).compactSize()).toThrow();
  });
});
