import { describe, expect, it } from 'vitest';
import { randomBytes, toHex, utf8 } from '../common/bytes.js';
import { MemoryStore } from '../stores/memory-store.js';
import {
  generateSeedPhrase,
  isValidSeedPhrase,
  phraseFromSeed,
  seedFromPhrase,
} from './mnemonic.js';
import { decodeExport, exportState, importState } from './export.js';

describe('seed phrases', () => {
  it('generates 24 words that round trip to a 32-byte seed', () => {
    const phrase = generateSeedPhrase();
    expect(phrase.split(' ')).toHaveLength(24);
    const seed = seedFromPhrase(phrase);
    expect(seed).toHaveLength(32);
    expect(phraseFromSeed(seed)).toBe(phrase);
  });

  it('round trips a known seed', () => {
    const seed = new Uint8Array(32).fill(0x42);
    expect(toHex(seedFromPhrase(phraseFromSeed(seed)))).toBe(toHex(seed));
  });

  it('tolerates how people actually retype a phrase', () => {
    // Copied off paper: stray capitals, doubled spaces, a trailing newline.
    const phrase = generateSeedPhrase();
    const messy = `  ${phrase.split(' ').join('  ').toUpperCase()}\n`;
    expect(toHex(seedFromPhrase(messy))).toBe(toHex(seedFromPhrase(phrase)));
  });

  it('rejects a phrase with a bad checksum or the wrong length', () => {
    // BIP39's checksum is what catches a mistyped word, so it must not be
    // skipped.
    const words = generateSeedPhrase().split(' ');
    const swapped = [...words];
    [swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
    expect(isValidSeedPhrase(swapped.join(' '))).toBe(false);
    expect(isValidSeedPhrase(words.slice(0, 12).join(' '))).toBe(false);
    expect(isValidSeedPhrase('not even words at all')).toBe(false);
    expect(() => seedFromPhrase('')).toThrow();
  });

  it('refuses a seed that is not 32 bytes', () => {
    expect(() => phraseFromSeed(randomBytes(16))).toThrow(/32 bytes/);
  });
});

describe('encrypted export', () => {
  async function populated(): Promise<MemoryStore> {
    const store = new MemoryStore();
    await store.put('contacts', 'a', utf8('alice'));
    await store.put('chat', 'msg/1', utf8('hello'));
    await store.put('chatmeta', 'known/x', new Uint8Array([1]));
    return store;
  }

  // Keep the KDF cheap in tests; production uses 600k.
  const fast = { iterations: 1000 };

  it('round trips through a passphrase', async () => {
    const store = await populated();
    const bytes = await exportState(store, 'correct horse battery staple', fast);
    const restored = new MemoryStore();
    await importState(restored, bytes, 'correct horse battery staple');
    expect(await restored.get('contacts', 'a')).toEqual(utf8('alice'));
    expect(await restored.get('chat', 'msg/1')).toEqual(utf8('hello'));
    expect(await restored.get('chatmeta', 'known/x')).toEqual(new Uint8Array([1]));
  });

  it('refuses a wrong passphrase, and says the same thing for a damaged file', async () => {
    // The two are indistinguishable on purpose: telling them apart would tell
    // an attacker whether a guess was close.
    const bytes = await exportState(await populated(), 'right', fast);
    expect(() => decodeExport(bytes, 'wrong')).toThrow(/wrong passphrase or damaged file/);
    const damaged = bytes.slice();
    damaged[damaged.length - 1]! ^= 1;
    expect(() => decodeExport(damaged, 'right')).toThrow(/wrong passphrase or damaged file/);
  });

  it('rejects a file that is not one of ours', async () => {
    expect(() => decodeExport(randomBytes(200), 'x')).toThrow(/not a navio-p2pmsg backup/);
  });

  it('refuses an implausible iteration count rather than grinding on it', async () => {
    // Otherwise a hostile file could make an import spend minutes in the KDF.
    const bytes = await exportState(await populated(), 'pw', fast);
    const tampered = bytes.slice();
    // The u32 iteration count sits right after magic + version + kdf id.
    new DataView(tampered.buffer, tampered.byteOffset).setUint32(EXPORT_HEADER, 9_000_000_000 >>> 0, true);
    expect(() => decodeExport(tampered, 'pw')).toThrow(/implausible/);
  });

  it('requires a passphrase', async () => {
    await expect(exportState(await populated(), '', fast)).rejects.toThrow(/passphrase/);
  });

  it('carries nothing that was not asked for', async () => {
    const store = await populated();
    await store.put('secrets', 'nope', utf8('should not travel'));
    const bytes = await exportState(store, 'pw', { ...fast, namespaces: ['contacts'] });
    const restored = new MemoryStore();
    await importState(restored, bytes, 'pw');
    expect(await restored.get('contacts', 'a')).toEqual(utf8('alice'));
    expect(await restored.get('secrets', 'nope')).toBeUndefined();
  });
});

/** magic(7) + version(1) + kdf(1) */
const EXPORT_HEADER = 9;
