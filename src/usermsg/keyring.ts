/**
 * Seed-derived long-term keys: a stable identity key and a rotating inbox
 * prekey. Derivation is deterministic from a 32-byte application-supplied
 * seed so a user can recover the same identity on another device.
 *
 *   identity_sk = scalar(HKDF(seed, salt="navio-p2pmsg", info="identity"))
 *   prekey_sk_n = scalar(HKDF(seed, salt="navio-p2pmsg", info="prekey/" + n))
 *
 * `n` (the prekey epoch) is persisted in Store namespace "keys".
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import type { Store } from '../stores/store.js';
import { utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { publicKey, scalarFromSeed, signAugmented, verifyAugmented } from '../bus/bls.js';
import type { Bundle } from './bundle.js';

const SALT = utf8('navio-p2pmsg');
const NS = 'keys';

export interface KeyPair {
  sk: Uint8Array; // 32
  pub: Uint8Array; // 48
}

export function deriveIdentity(seed: Uint8Array): KeyPair {
  const sk = scalarFromSeed(hkdf(sha256, seed, SALT, utf8('identity'), 32));
  return { sk, pub: publicKey(sk) };
}

export function derivePrekey(seed: Uint8Array, epoch: number): KeyPair {
  if (!Number.isInteger(epoch) || epoch < 0) throw new Error('bad prekey epoch');
  const sk = scalarFromSeed(hkdf(sha256, seed, SALT, utf8(`prekey/${epoch}`), 32));
  return { sk, pub: publicKey(sk) };
}

/** Sign a prekey under the identity exactly like naviod: Sign(identity_sk, prekey_pub bytes). */
export function signPrekey(identity: KeyPair, prekeyPub: Uint8Array): Uint8Array {
  return signAugmented(identity.sk, prekeyPub);
}

export function verifyBundle(b: Bundle): boolean {
  try {
    return verifyAugmented(b.identity, b.prekey, b.prekeySig);
  } catch {
    return false;
  }
}

export interface KeyringState {
  epoch: number;
  rotatedAt: number; // ms
}

export class Keyring {
  readonly identity: KeyPair;
  private _prekey: KeyPair;
  private _previous: KeyPair | undefined;
  private state: KeyringState;

  private constructor(
    private readonly seed: Uint8Array,
    private readonly store: Store,
    state: KeyringState,
    private readonly now: () => number,
  ) {
    if (seed.length !== 32) throw new Error('seed must be 32 bytes');
    this.identity = deriveIdentity(seed);
    this.state = state;
    this._prekey = derivePrekey(seed, state.epoch);
    this._previous = state.epoch > 0 ? derivePrekey(seed, state.epoch - 1) : undefined;
  }

  static async open(seed: Uint8Array, store: Store, now: () => number = () => Date.now()): Promise<Keyring> {
    const raw = await store.get(NS, 'state');
    let state: KeyringState = { epoch: 0, rotatedAt: 0 };
    if (raw) {
      const r = new Reader(raw);
      if (r.u8() !== 1) throw new Error('bad keyring state version');
      state = { epoch: r.u32(), rotatedAt: Number(r.i64()) };
    }
    const k = new Keyring(seed, store, state, now);
    if (!raw) await k.persist();
    return k;
  }

  get prekey(): KeyPair {
    return this._prekey;
  }
  /** Previous epoch's prekey, kept for grace-period decryption. */
  get previousPrekey(): KeyPair | undefined {
    return this._previous;
  }
  get epoch(): number {
    return this.state.epoch;
  }
  get rotatedAt(): number {
    return this.state.rotatedAt;
  }

  bundle(): Bundle {
    return {
      identity: this.identity.pub,
      prekey: this._prekey.pub,
      prekeySig: signPrekey(this.identity, this._prekey.pub),
    };
  }

  async rotatePrekey(): Promise<KeyPair> {
    this._previous = this._prekey;
    this.state = { epoch: this.state.epoch + 1, rotatedAt: this.now() };
    this._prekey = derivePrekey(this.seed, this.state.epoch);
    await this.persist();
    return this._prekey;
  }

  private persist(): Promise<void> {
    return this.store.put(NS, 'state', new Writer().u8(1).u32(this.state.epoch).i64(BigInt(this.state.rotatedAt)).finish());
  }
}
