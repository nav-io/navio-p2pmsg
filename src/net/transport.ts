/**
 * Transport abstraction: an ordered, reliable byte stream to one peer.
 * Everything above this interface is `Uint8Array` only and runtime-agnostic.
 */
export interface Transport {
  /** Open the connection. Resolves once bytes can be sent. */
  connect(): Promise<void>;
  /** Close the connection. Idempotent. Triggers the `onClose` callback once. */
  close(): void;
  /** Write bytes to the stream. Throws if not connected. */
  send(bytes: Uint8Array): void;
  /** Register the (single) inbound data callback. */
  onData(cb: (bytes: Uint8Array) => void): void;
  /** Register the (single) close callback. `err` is set when the close was not clean. */
  onClose(cb: (err?: Error) => void): void;
  /** Human-readable remote identifier (`host:port` or URL). */
  readonly remote: string;
}

export type TransportKind = 'tcp' | 'ws';

export interface ParsedPeerAddress {
  kind: TransportKind;
  host: string;
  port: number;
  /** Set for `ws://` / `wss://` addresses: the full URL to dial. */
  url?: string;
}

/**
 * Parse a peer address string. Accepted forms:
 *   `host:port`, `[v6]:port`, `[v6]`, `v6` (bare, no port), `host` (default port),
 *   `ws://host[:port][/path]`, `wss://host[:port][/path]`.
 */
export function parsePeerAddress(s: string, defaultPort: number): ParsedPeerAddress {
  const str = s.trim();
  if (str.length === 0) throw new Error('empty peer address');

  if (/^wss?:\/\//i.test(str)) {
    const u = new URL(str);
    const secure = u.protocol.toLowerCase() === 'wss:';
    const host = u.hostname.startsWith('[') ? u.hostname.slice(1, -1) : u.hostname;
    const port = u.port ? Number(u.port) : secure ? 443 : 80;
    return { kind: 'ws', host, port, url: u.toString() };
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(str)) {
    throw new Error(`unsupported peer address scheme: ${str}`);
  }

  if (str.startsWith('[')) {
    const end = str.indexOf(']');
    if (end < 0) throw new Error(`invalid peer address: ${str}`);
    const host = str.slice(1, end);
    const rest = str.slice(end + 1);
    if (rest === '') return { kind: 'tcp', host, port: defaultPort };
    if (!rest.startsWith(':')) throw new Error(`invalid peer address: ${str}`);
    return { kind: 'tcp', host, port: parsePort(rest.slice(1), str) };
  }

  const colons = str.split(':').length - 1;
  if (colons > 1) {
    // Bare IPv6 literal without port.
    return { kind: 'tcp', host: str, port: defaultPort };
  }
  if (colons === 1) {
    const i = str.lastIndexOf(':');
    return { kind: 'tcp', host: str.slice(0, i), port: parsePort(str.slice(i + 1), str) };
  }
  return { kind: 'tcp', host: str, port: defaultPort };
}

function parsePort(p: string, whole: string): number {
  if (!/^\d{1,5}$/.test(p)) throw new Error(`invalid port in peer address: ${whole}`);
  const n = Number(p);
  if (n < 1 || n > 65535) throw new Error(`invalid port in peer address: ${whole}`);
  return n;
}

/** Canonical `host:port` / `[v6]:port` form used as address-book key. */
export function formatHostPort(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}
