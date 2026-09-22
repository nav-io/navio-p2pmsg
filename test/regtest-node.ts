/**
 * Spawns a real `naviod -regtest` for integration tests. Node-only test helper.
 *
 *   const node = await startRegtestNode();
 *   ... connect to 127.0.0.1:node.port ...
 *   await node.rpc('getblockchaininfo');
 *   await node.stop();
 */
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * The daemon the integration tests run against. Must be built from a branch
 * carrying envelope v2 (navio-core `feat/p2pmsg-envelope-v2-fmd` or later) —
 * the SDK sends PoW header version 2, which a v1 node rejects outright, so an
 * older binary fails every test here with no useful message.
 *
 * Override with $NAVIOD.
 */
export const DEFAULT_NAVIOD = process.env.NAVIOD ?? '/Users/alex/dev/navio-fmd/build/bin/naviod';

export interface RegtestNodeOptions {
  /** Path to the daemon binary. Default `$NAVIOD` or the integration worktree build. */
  binary?: string;
  /** Extra `-flag=value` arguments. Unknown flags (per `-help`) are dropped with a warning. */
  extraArgs?: string[];
  /** Wait this long for the P2P port + RPC warmup. Default 60 s. */
  startTimeoutMs?: number;
  /** Keep the datadir after `stop()` (for debugging). */
  keepDatadir?: boolean;
  /** Stream the daemon's stdout/stderr to the test's stderr. */
  verbose?: boolean;
}

export interface RegtestNode {
  /** P2P listening port on 127.0.0.1. */
  port: number;
  rpcPort: number;
  datadir: string;
  pid: number;
  binary: string;
  /** JSON-RPC call. Throws on an RPC error. */
  rpc<T = unknown>(method: string, params?: unknown[]): Promise<T>;
  /** SIGTERM, wait for exit (SIGKILL after 15 s), remove the datadir. Idempotent. */
  stop(): Promise<void>;
  /** Resolves when the process exits. */
  exited: Promise<number | null>;
}

const BASE_ARGS = [
  '-regtest',
  '-daemon=0',
  '-server=1',
  '-listen=1',
  '-p2pmsg=1',
  '-p2pmsgpowbits=8',
  '-debug=net',
  '-printtoconsole=0',
  '-dnsseed=0',
  '-fixedseeds=0',
  '-listenonion=0',
  '-upnp=0',
  '-natpmp=0',
  '-discover=0',
  '-rpcallowip=127.0.0.1',
  '-rpcbind=127.0.0.1',
];

const RPC_USER = 'user';
const RPC_PASS = 'pass';

const helpCache = new Map<string, Set<string>>();

/** Set of `-flag` names the binary advertises in `-help`. */
export function supportedFlags(binary: string): Set<string> {
  let set = helpCache.get(binary);
  if (set) return set;
  // Point at a scratch datadir: without one the daemon uses the real default
  // and tries to write settings.json there, so two test files probing -help
  // concurrently race and one dies with "Settings file could not be written".
  const tmp = mkdtempSync(join(tmpdir(), 'navio-help-'));
  let help: string;
  try {
    help = execFileSync(binary, ['-help', '-help-debug', `-datadir=${tmp}`], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  set = new Set<string>();
  for (const m of help.matchAll(/^\s{2}(-[a-zA-Z0-9]+)/gm)) set.add(m[1]!);
  helpCache.set(binary, set);
  return set;
}

export function filterArgs(binary: string, args: string[]): string[] {
  const ok = supportedFlags(binary);
  const out: string[] = [];
  for (const a of args) {
    const name = a.split('=')[0]!;
    if (name === '-regtest' || ok.has(name)) out.push(a);
    else process.stderr.write(`[regtest-node] dropping unsupported flag ${a}\n`);
  }
  return out;
}

export async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

function canConnect(port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const s = createConnection({ host: '127.0.0.1', port });
    const done = (ok: boolean) => {
      s.removeAllListeners();
      s.destroy();
      resolve(ok);
    };
    s.setTimeout(timeoutMs, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function startRegtestNode(options: RegtestNodeOptions = {}): Promise<RegtestNode> {
  const binary = options.binary ?? DEFAULT_NAVIOD;
  const [port, rpcPort] = [await getFreePort(), await getFreePort()];
  const datadir = mkdtempSync(join(tmpdir(), 'navio-regtest-'));
  const args = filterArgs(binary, [
    ...BASE_ARGS,
    `-datadir=${datadir}`,
    `-bind=127.0.0.1:${port}`,
    `-port=${port}`,
    `-rpcport=${rpcPort}`,
    `-rpcuser=${RPC_USER}`,
    `-rpcpassword=${RPC_PASS}`,
    ...(options.extraArgs ?? []),
  ]);

  const child: ChildProcess = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  const onOut = (b: Buffer) => {
    const s = b.toString();
    output = (output + s).slice(-8192);
    if (options.verbose) process.stderr.write(s);
  };
  child.stdout?.on('data', onOut);
  child.stderr?.on('data', onOut);
  const exited = new Promise<number | null>((resolve) => {
    child.once('exit', (code) => resolve(code));
    child.once('error', () => resolve(null));
  });
  let exitedFlag = false;
  void exited.then(() => {
    exitedFlag = true;
  });

  const auth = 'Basic ' + Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64');
  let rpcId = 0;
  const rpc = async <T,>(method: string, params: unknown[] = []): Promise<T> => {
    const res = await fetch(`http://127.0.0.1:${rpcPort}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body: JSON.stringify({ jsonrpc: '1.0', id: ++rpcId, method, params }),
    });
    const text = await res.text();
    let body: { result?: T; error?: { code: number; message: string } | null };
    try {
      body = JSON.parse(text) as typeof body;
    } catch {
      throw new Error(`rpc ${method}: HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    if (body.error) throw Object.assign(new Error(`rpc ${method}: ${body.error.message}`), { code: body.error.code });
    return body.result as T;
  };

  let stopped = false;
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    if (!exitedFlag) {
      child.kill('SIGTERM');
      const killer = setTimeout(() => {
        if (!exitedFlag) child.kill('SIGKILL');
      }, 15_000);
      await exited;
      clearTimeout(killer);
    }
    if (!options.keepDatadir) rmSync(datadir, { recursive: true, force: true });
  };

  // Wait for the P2P port, then for RPC to leave warmup.
  const deadline = Date.now() + (options.startTimeoutMs ?? 60_000);
  try {
    while (!(await canConnect(port))) {
      if (exitedFlag) throw new Error(`naviod exited during startup\nargs: ${args.join(' ')}\n${output}`);
      if (Date.now() > deadline) throw new Error(`timeout waiting for naviod P2P port ${port}\n${output}`);
      await sleep(100);
    }
    for (;;) {
      if (exitedFlag) throw new Error(`naviod exited during startup\n${output}`);
      if (Date.now() > deadline) throw new Error(`timeout waiting for naviod RPC on ${rpcPort}\n${output}`);
      try {
        await rpc('getblockchaininfo');
        break;
      } catch (e) {
        const code = (e as { code?: number }).code;
        if (code !== undefined && code !== -28) throw e; // real RPC error (not warmup)
        await sleep(100);
      }
    }
  } catch (e) {
    await stop();
    throw e;
  }

  return { port, rpcPort, datadir, pid: child.pid ?? -1, binary, rpc, stop, exited };
}
