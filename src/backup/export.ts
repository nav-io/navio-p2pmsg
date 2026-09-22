/**
 * Encrypted state export.
 *
 * The mnemonic restores the identity and the address; it cannot restore
 * history, contacts or group membership, because those are not derived from
 * the seed. This is the file that carries them.
 *
 * Encrypted under a passphrase rather than the seed, so the two backups fail
 * independently: a leaked export does not expose the account, and a leaked
 * mnemonic does not expose the history.
 *
 *   magic  "navbak1"
 *   u8     version
 *   u8     kdf id
 *   u32    kdf iterations
 *   u8[16] salt
 *   u8[12] nonce
 *   CompactSize n, u8[n] ciphertext   ChaCha20-Poly1305 over the snapshot
 */
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { type Store, type StoreSnapshot, restoreStore, snapshotStore } from '../stores/store.js';

export const EXPORT_MAGIC = utf8('navbak1');
export const EXPORT_VERSION = 1;
const KDF_PBKDF2_SHA256 = 1;
/**
 * Deliberately high: this guards a file that holds an entire message history,
 * and it is unlocked by a human-chosen passphrase, which is the weakest part
 * of the scheme. The cost is paid once per export or import.
 */
export const DEFAULT_KDF_ITERATIONS = 600_000;

/** Namespaces an export carries. */
export const EXPORT_NAMESPACES = ['keys', 'contacts', 'outbox', 'chat', 'chatmeta', 'archive'];

function deriveKey(passphrase: string, salt: Uint8Array, iterations: number): Uint8Array {
  return pbkdf2(sha256, utf8(passphrase.normalize('NFKD')), salt, { c: iterations, dkLen: 32 });
}

export interface ExportOptions {
  iterations?: number;
  namespaces?: string[];
}

/** Encrypt the store's contents under `passphrase`. */
export async function exportState(store: Store, passphrase: string, opts: ExportOptions = {}): Promise<Uint8Array> {
  if (passphrase.length === 0) throw new Error('a backup passphrase is required');
  const iterations = opts.iterations ?? DEFAULT_KDF_ITERATIONS;
  const snapshot = await snapshotStore(store, opts.namespaces ?? EXPORT_NAMESPACES);
  const plaintext = utf8(JSON.stringify(snapshot));
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const ciphertext = chacha20poly1305(deriveKey(passphrase, salt, iterations), nonce).encrypt(plaintext);
  return new Writer()
    .bytes(EXPORT_MAGIC)
    .u8(EXPORT_VERSION)
    .u8(KDF_PBKDF2_SHA256)
    .u32(iterations)
    .bytes(salt)
    .bytes(nonce)
    .varBytes(ciphertext)
    .finish();
}

/** Decrypt an export. Throws on a wrong passphrase or a damaged file. */
export function decodeExport(bytes: Uint8Array, passphrase: string): StoreSnapshot {
  const r = new Reader(bytes);
  const magic = r.bytes(EXPORT_MAGIC.length);
  for (let i = 0; i < EXPORT_MAGIC.length; i++) {
    if (magic[i] !== EXPORT_MAGIC[i]) throw new Error('not a navio-p2pmsg backup');
  }
  const version = r.u8();
  if (version !== EXPORT_VERSION) throw new Error(`unsupported backup version ${version}`);
  const kdf = r.u8();
  if (kdf !== KDF_PBKDF2_SHA256) throw new Error(`unsupported key derivation ${kdf}`);
  const iterations = r.u32();
  // A hostile file could otherwise ask us to spend minutes deriving a key.
  if (iterations < 1000 || iterations > 10_000_000) throw new Error('implausible iteration count');
  const salt = r.bytes(16).slice();
  const nonce = r.bytes(12).slice();
  const ciphertext = r.varBytes();
  r.assertDone();

  let plaintext: Uint8Array;
  try {
    plaintext = chacha20poly1305(deriveKey(passphrase, salt, iterations), nonce).decrypt(ciphertext);
  } catch {
    // Authentication failure: wrong passphrase, or the file was altered. The
    // two are indistinguishable by design.
    throw new Error('could not decrypt the backup: wrong passphrase or damaged file');
  }
  return JSON.parse(new TextDecoder().decode(plaintext)) as StoreSnapshot;
}

/** Decrypt an export and write it into `store`. */
export async function importState(store: Store, bytes: Uint8Array, passphrase: string): Promise<void> {
  await restoreStore(store, decodeExport(bytes, passphrase));
}
