import { describe, expect, it } from 'vitest';
import { randomBytes } from '../common/bytes.js';
import { hashMeetsTarget } from '../bus/pow.js';
import { FMD_GAMMA, FMD_SCALAR_SIZE } from '../bus/fmd.js';
import {
  archiveQueryHash,
  archiveStampBits,
  archiveStampHash,
  buildArchiveRequest,
  MAX_ARCHIVE_LIMIT,
  parseArchiveRequest,
  parseArchiveResponse,
  serializeArchiveRequest,
  serializeArchiveResponse,
} from './protocol.js';

const dk = (n: number) => randomBytes(n * FMD_SCALAR_SIZE);

describe('archive protocol', () => {
  it('round trips a request', () => {
    const req = buildArchiveRequest(
      { cursor: 42n, limit: 100, precision: 4, detectionKey: dk(4), notBefore: 1234n },
      { baseBits: 4, nowSeconds: 1000 },
    );
    const bytes = serializeArchiveRequest(req);
    expect(parseArchiveRequest(bytes)).toEqual(req);
    expect(() => parseArchiveRequest(new Uint8Array([...bytes, 0]))).toThrow(/trailing/);
  });

  it('round trips a response, including the empty case', () => {
    const res = {
      version: 1,
      nextCursor: 99n,
      complete: false,
      items: [
        { id: 1n, receivedAt: 1000n, envelope: randomBytes(120) },
        { id: 7n, receivedAt: 1001n, envelope: randomBytes(4096) },
      ],
    };
    expect(parseArchiveResponse(serializeArchiveResponse(res))).toEqual(res);
    const empty = { version: 1, nextCursor: 0n, complete: true, items: [] };
    expect(parseArchiveResponse(serializeArchiveResponse(empty))).toEqual(empty);
  });

  it('commits the stamp to every query field', () => {
    // Otherwise a peer could pay for a cheap scan and then ask for an
    // expensive one.
    const base = { version: 1, cursor: 42n, limit: 100, precision: 4, detectionKey: dk(4), notBefore: 1234n };
    const h = archiveQueryHash(base);
    expect(archiveQueryHash({ ...base, cursor: 43n })).not.toEqual(h);
    expect(archiveQueryHash({ ...base, limit: 500 })).not.toEqual(h);
    expect(archiveQueryHash({ ...base, precision: 8 })).not.toEqual(h);
    expect(archiveQueryHash({ ...base, notBefore: 0n })).not.toEqual(h);
    const tweaked = base.detectionKey.slice();
    tweaked[0]! ^= 1;
    expect(archiveQueryHash({ ...base, detectionKey: tweaked })).not.toEqual(h);
    expect(archiveQueryHash({ ...base })).toEqual(h);
  });

  it('prices a query by the work it asks for', () => {
    // Must stay identical to ArchiveStampBits in navio-core or every query is
    // rejected as underpowered.
    expect(archiveStampBits(4, 1, 1)).toBe(4);
    expect(archiveStampBits(4, 100, 4)).toBe(4); // exactly the free allowance
    expect(archiveStampBits(4, 200, 4)).toBe(5);
    expect(archiveStampBits(4, 100, 8)).toBe(5);
    expect(archiveStampBits(4, MAX_ARCHIVE_LIMIT, FMD_GAMMA)).toBeGreaterThan(4);
    // Clamped, so a large legitimate query stays feasible on a phone.
    expect(archiveStampBits(4, MAX_ARCHIVE_LIMIT, FMD_GAMMA)).toBeLessThanOrEqual(12);
    expect(archiveStampBits(23, 65535, FMD_GAMMA)).toBeLessThanOrEqual(31);
  });

  it('grinds a stamp that meets its own difficulty', () => {
    const req = buildArchiveRequest(
      { cursor: 0n, limit: 100, precision: 4, detectionKey: dk(4), notBefore: 0n },
      { baseBits: 8, nowSeconds: 1000 },
    );
    const bits = archiveStampBits(8, 100, 4);
    expect(hashMeetsTarget(archiveStampHash(req.stamp), bits)).toBe(true);
    expect(req.stamp.queryHash).toEqual(archiveQueryHash(req));
  });

  it('rejects a detection key that does not match the precision', () => {
    // The key length IS the precision on the wire, so a mismatch would make us
    // pay for one scan and ask for another.
    expect(() =>
      buildArchiveRequest(
        { cursor: 0n, limit: 10, precision: 4, detectionKey: dk(8), notBefore: 0n },
        { baseBits: 1, nowSeconds: 0 },
      ),
    ).toThrow(/precision/);
    expect(() =>
      buildArchiveRequest(
        { cursor: 0n, limit: 10, precision: 0, detectionKey: dk(0), notBefore: 0n },
        { baseBits: 1, nowSeconds: 0 },
      ),
    ).toThrow(/precision/);
    expect(() =>
      buildArchiveRequest(
        { cursor: 0n, limit: 10, precision: FMD_GAMMA + 1, detectionKey: dk(FMD_GAMMA + 1), notBefore: 0n },
        { baseBits: 1, nowSeconds: 0 },
      ),
    ).toThrow(/precision/);
  });
});
