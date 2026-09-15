/**
 * Bus-level key registry: the keys an inbound envelope is trial-decrypted
 * against, in the same order as navio-core `Transport::HandleJob`:
 *   inbox current -> inbox grace ring -> broadcast key -> session keys.
 *
 * This is NOT the seed-derived usermsg keyring; that layer feeds keys in here.
 */
import { toHex } from '../common/bytes.js';
import { BROADCAST_SECRET, publicKey, secretFromBytes } from './bls.js';
import { type EciesPacket, decrypt } from './ecies.js';

export type RecipientClass = 'inbox' | 'broadcast' | 'session';

export interface TrialDecryptResult {
  recipient: RecipientClass;
  /** Which session key decrypted it (recipient === 'session'). */
  sessionPub?: Uint8Array;
  body: Uint8Array;
}

export interface SessionKeyInfo {
  pub: Uint8Array;
  /** ms since epoch; undefined = no expiry. */
  expiresAt?: number;
}

export interface BusKeysOptions {
  /** Retired inbox keys kept for trial decryption (navio-core `prekey_grace_keys`). Default 1. */
  graceKeys?: number;
  /** Hard cap on registered session keys (navio-core `MAX_SESSION_KEYS`). Default 256. */
  maxSessionKeys?: number;
  /** Clock in ms (tests). */
  now?: () => number;
}

interface SessionEntry {
  sk: Uint8Array;
  pub: Uint8Array;
  expiresAt?: number;
}

export class BusKeys {
  private inboxSk?: Uint8Array;
  private inboxPub?: Uint8Array;
  /** Newest first. */
  private grace: Uint8Array[] = [];
  /** Insertion-ordered (oldest first) by pub hex. */
  private sessions = new Map<string, SessionEntry>();
  readonly graceKeys: number;
  readonly maxSessionKeys: number;
  private readonly now: () => number;

  constructor(opts: BusKeysOptions = {}) {
    this.graceKeys = opts.graceKeys ?? 1;
    this.maxSessionKeys = opts.maxSessionKeys ?? 256;
    this.now = opts.now ?? (() => Date.now());
  }

  /** Current inbox (prekey) public key, if set. */
  get inboxPublic(): Uint8Array | undefined {
    return this.inboxPub;
  }

  /** Install the current inbox secret. `pub` is derived when omitted. */
  setInbox(sk: Uint8Array, pub?: Uint8Array): void {
    this.inboxSk = secretFromBytes(sk);
    this.inboxPub = pub ? new Uint8Array(pub) : publicKey(this.inboxSk);
  }

  /** Push a retired inbox secret onto the grace ring (bounded to `graceKeys`, newest first). */
  addGraceInbox(sk: Uint8Array): void {
    if (this.graceKeys <= 0) return;
    this.grace.unshift(secretFromBytes(sk));
    while (this.grace.length > this.graceKeys) this.grace.pop();
  }

  /** Retire the current inbox key into the grace ring and install `newSk`. */
  rotateInbox(newSk: Uint8Array, newPub?: Uint8Array): void {
    if (this.inboxSk) this.addGraceInbox(this.inboxSk);
    this.setInbox(newSk, newPub);
  }

  /** Register a per-request session key. `ttlMs` <= 0 / undefined = no expiry. Replaces an existing entry for `pub`. */
  addSessionKey(sk: Uint8Array, pub?: Uint8Array, ttlMs?: number): void {
    const secret = secretFromBytes(sk);
    const p = pub ? new Uint8Array(pub) : publicKey(secret);
    const k = toHex(p);
    this.sweep();
    this.sessions.delete(k);
    while (this.sessions.size >= this.maxSessionKeys) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
    const entry: SessionEntry = { sk: secret, pub: p };
    if (ttlMs !== undefined && ttlMs > 0) entry.expiresAt = this.now() + ttlMs;
    this.sessions.set(k, entry);
  }

  removeSessionKey(pub: Uint8Array): boolean {
    return this.sessions.delete(toHex(pub));
  }

  hasSessionKey(pub: Uint8Array): boolean {
    this.sweep();
    return this.sessions.has(toHex(pub));
  }

  /** Live session keys (expired entries are swept), oldest first. */
  sessionKeys(): SessionKeyInfo[] {
    this.sweep();
    const out: SessionKeyInfo[] = [];
    for (const e of this.sessions.values()) {
      const info: SessionKeyInfo = { pub: e.pub };
      if (e.expiresAt !== undefined) info.expiresAt = e.expiresAt;
      out.push(info);
    }
    return out;
  }

  private sweep(): void {
    const t = this.now();
    for (const [k, e] of this.sessions) {
      if (e.expiresAt !== undefined && e.expiresAt <= t) this.sessions.delete(k);
    }
  }

  /**
   * Trial-decrypt `packet` (AAD = kind byte) against inbox current, inbox
   * grace, broadcast, then live session keys. Null if nothing decrypts.
   */
  trialDecrypt(kind: number, packet: EciesPacket): TrialDecryptResult | null {
    const aad = new Uint8Array([kind & 0xff]);
    if (this.inboxSk) {
      const body = decrypt(this.inboxSk, packet, aad);
      if (body) return { recipient: 'inbox', body };
    }
    for (const sk of this.grace) {
      const body = decrypt(sk, packet, aad);
      if (body) return { recipient: 'inbox', body };
    }
    {
      const body = decrypt(BROADCAST_SECRET, packet, aad);
      if (body) return { recipient: 'broadcast', body };
    }
    this.sweep();
    for (const e of this.sessions.values()) {
      const body = decrypt(e.sk, packet, aad);
      if (body) return { recipient: 'session', sessionPub: e.pub, body };
    }
    return null;
  }
}
