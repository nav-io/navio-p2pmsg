/**
 * Seed-derived long-term keys: a stable identity key and a rotating inbox
 * prekey. Derivation is deterministic from a 32-byte application-supplied
 * seed so a user can recover the same identity on another device.
 *
 *   identity_sk       = scalar(HKDF(seed, salt="navio-p2pmsg", info="identity"))
 *   account_secret(e) = HKDF(seed, salt="navio-p2pmsg", info="account/" ‖ u32le(e))
 *   prekey_sk(e)      = scalar(HKDF(account_secret(e), …, info="inbox"))
 *   fmd_seed(e)       = HKDF(account_secret(e), …, info="fmd")
 *
 * The indirection through an ACCOUNT SECRET is what makes multi-device work.
 * Every device of an account holds `account_secret(e)` and therefore the same
 * inbox key, so one envelope reaches all of them and a sender never pays for
 * the recipient's device count (mainnet proof of work is 23 bits per
 * envelope). Only the primary device holds the seed, so only it can derive
 * `e+1` — which is what makes revoking a device mean anything. See
 * `../devices/hierarchy.js`.
 *
 * The epoch `e` is persisted in Store namespace "keys".
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import type { Store } from '../stores/store.js';
import { utf8 } from '../common/bytes.js';
import { Reader, Writer } from '../common/serialize.js';
import { publicKey, scalarFromSeed, signAugmented, verifyAugmented } from '../bus/bls.js';
import { deriveAccountSecret, deriveFmdSeed, deriveInboxPrekey } from '../devices/hierarchy.js';
import { clueKeyOf, type FmdSecretKey, fmdSecretFromSeed, serializeClueKey } from '../bus/fmd.js';
import { type Bundle, type ExtendedBundle, fmdSigMessage } from './bundle.js';

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
  return deriveInboxPrekey(deriveAccountSecret(seed, epoch));
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

/**
 * Verify the clue key as well as the prekey. A sender MUST do this before
 * flagging: flagging to a substituted clue key hands the retrieval side to
 * whoever substituted it.
 */
export function verifyExtendedBundle(b: ExtendedBundle): boolean {
  if (!verifyBundle(b)) return false;
  try {
    return verifyAugmented(b.identity, fmdSigMessage(b.fmdEpoch, b.fmdClueKey), b.fmdSig);
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
  // Derived lazily: building a clue key is gamma point multiplications, and a
  // client that never flags anything should not pay for it at startup.
  private _fmd: FmdSecretKey | undefined;
  private _clueKey: Uint8Array | undefined;

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

  /**
   * The FMD root secret for the current epoch. Rotating with the prekey is
   * deliberate and matches naviod: a detection key cannot be revoked and keeps
   * matching future flags, so its reach has to be bounded by the epoch.
   */
  get fmd(): FmdSecretKey {
    this._fmd ??= fmdSecretFromSeed(deriveFmdSeed(this.accountSecret()), this.state.epoch);
    return this._fmd;
  }

  /**
   * The secret every device of this account shares for the current epoch.
   *
   * SECRET, and the thing a pairing grant hands a new device. It deliberately
   * does NOT include the seed: a secondary device must not be able to derive
   * the next epoch, or revoking it would achieve nothing.
   */
  accountSecret(epoch = this.state.epoch): Uint8Array {
    return deriveAccountSecret(this.seed, epoch);
  }

  /**
   * Rotate the account epoch: revocation.
   *
   * Every derived key moves — the inbox prekey, the FMD key and the
   * deterministic ratchet keys — so a device holding the previous secret stops
   * being able to read anything new. Only a device with the seed can do this.
   *
   * The previous prekey stays in the grace ring, which means a revoked device
   * can still read that window. Applications should say so when the user
   * revokes rather than implying a clean cut.
   */
  rotateAccountEpoch(): Promise<KeyPair> {
    return this.rotatePrekey();
  }

  /** What a sender needs in order to flag a message to us. 1152 bytes. */
  fmdClueKey(): Uint8Array {
    this._clueKey ??= serializeClueKey(clueKeyOf(this.fmd));
    return this._clueKey;
  }

  /**
   * The account's signed device list, published so peers can verify
   * device-signed frames. Empty until a second device is paired.
   */
  deviceList: Uint8Array = new Uint8Array(0);

  /** The bundle plus the clue key and device list — what discovery answers with. */
  extendedBundle(): ExtendedBundle {
    const clueKey = this.fmdClueKey();
    return {
      ...this.bundle(),
      fmdEpoch: this.state.epoch,
      fmdClueKey: clueKey,
      fmdSig: signAugmented(this.identity.sk, fmdSigMessage(this.state.epoch, clueKey)),
      deviceList: this.deviceList,
    };
  }

  async rotatePrekey(): Promise<KeyPair> {
    this._previous = this._prekey;
    this.state = { epoch: this.state.epoch + 1, rotatedAt: this.now() };
    this._prekey = derivePrekey(this.seed, this.state.epoch);
    // The clue key rotates with the prekey, so detection keys handed out under
    // the previous one stop matching.
    this._fmd = undefined;
    this._clueKey = undefined;
    await this.persist();
    return this._prekey;
  }

  private persist(): Promise<void> {
    return this.store.put(NS, 'state', new Writer().u8(1).u32(this.state.epoch).i64(BigInt(this.state.rotatedAt)).finish());
  }
}
