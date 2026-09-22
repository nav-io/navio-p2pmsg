/**
 * Seed backup as a BIP39 mnemonic.
 *
 * The seed is the whole account: identity, every account epoch, every derived
 * key. Twenty-four words is what every wallet in this ecosystem already asks
 * people to write down, so it is the phrase users know how to handle.
 *
 * What it restores and what it does not, stated plainly because the difference
 * bites: the mnemonic brings back the IDENTITY and the address, so
 * correspondents can reach you again. It does not bring back history, contacts
 * or group membership — those live in the `Store`, and an encrypted export is
 * the thing that carries them. See `./export.js`.
 */
import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

/** 24 words, i.e. 256 bits — the size of a seed. */
export const MNEMONIC_STRENGTH_BITS = 256;

export function generateSeedPhrase(): string {
  return generateMnemonic(wordlist, MNEMONIC_STRENGTH_BITS);
}

/** The 32-byte seed a phrase encodes. Throws on an invalid phrase. */
export function seedFromPhrase(phrase: string): Uint8Array {
  const normalised = normalisePhrase(phrase);
  if (!validateMnemonic(normalised, wordlist)) throw new Error('invalid seed phrase');
  const entropy = mnemonicToEntropy(normalised, wordlist);
  if (entropy.length !== 32) throw new Error('seed phrase must encode 32 bytes (24 words)');
  return entropy;
}

export function phraseFromSeed(seed: Uint8Array): string {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  return entropyToMnemonic(seed, wordlist);
}

export function isValidSeedPhrase(phrase: string): boolean {
  try {
    seedFromPhrase(phrase);
    return true;
  } catch {
    return false;
  }
}

/**
 * Collapse whitespace and case.
 *
 * People retype these from paper, so a double space or a capital at the start
 * of a line is the common case rather than an error worth refusing.
 */
function normalisePhrase(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/u).join(' ');
}
