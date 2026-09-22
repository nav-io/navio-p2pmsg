/**
 * Loader for the vendored BIP324 CSV vectors. Test-only.
 *
 * The files ship with CRLF line endings, so the last column of every row picks
 * up a trailing carriage return unless it is stripped — which silently breaks
 * comparisons against the last column and nothing else.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DIR = fileURLToPath(new URL('../../../test/vectors/bip324/', import.meta.url));

export function loadVectors(name: string): Record<string, string>[] {
  const text = readFileSync(DIR + name, 'utf8');
  const lines = text.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.length > 0);
  const cols = lines[0]!.split(',');
  return lines.slice(1).map((line) => {
    const cells = line.split(',');
    const row: Record<string, string> = {};
    cols.forEach((c, i) => (row[c] = cells[i] ?? ''));
    return row;
  });
}

export const unhex = (h: string): Uint8Array => new Uint8Array((h.match(/../g) ?? []).map((p) => parseInt(p, 16)));
export const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
