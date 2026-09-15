/**
 * Minimal terminal chat built on navio-p2pmsg. Not part of the library.
 *
 *   npx tsx examples/chat-cli.ts --network regtest --peer 127.0.0.1:18444 --state ./alice.json
 *
 * Commands:  /id  /bundle  /add <navmsg1…|navid1…>  /send <navid1…> <text>  /pub <topic> <text>  /sub <topic>  /quit
 */
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { MessagingClient, FileStore, utf8, fromUtf8 } from '../src/index.js';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i]!.replace(/^--/, ''), process.argv[i + 1] ?? '');

const network = (args.get('network') ?? 'regtest') as 'mainnet' | 'testnet' | 'regtest';
const statePath = args.get('state') ?? './p2pmsg-state.json';
const seedPath = statePath + '.seed';
const seed = existsSync(seedPath) ? new Uint8Array(readFileSync(seedPath)) : randomBytes(32);
if (!existsSync(seedPath)) writeFileSync(seedPath, seed, { mode: 0o600 });

const client = await MessagingClient.create({
  network,
  seed,
  store: await FileStore.open(statePath),
  ...(args.has('peer') ? { peers: args.get('peer')!.split(',') } : {}),
  ...(args.has('powbits') ? { powBits: Number(args.get('powbits')) } : {}),
  ...(args.has('services') ? { services: BigInt(args.get('services')!) } : {}),
});

client.on('peer', (p) => console.log(`[peer] connected ${p.address}`));
client.on('peerclose', (p) => console.log(`[peer] lost ${p.address}`));
client.on('message', (m) => console.log(`\n<${m.from ?? 'anon'}> [${m.topic}] ${fromUtf8(m.payload)}`));
client.on('raw', (m) => console.log(`\n<raw ${m.scope}> [${m.topic}] ${Buffer.from(m.body).toString('hex')}`));
client.on('ack', (a) => console.log(`[ack] delivered to ${a.to}`));
client.on('expired', (e) => console.log(`[expired] ${e.to}`));
client.on('contact', (c) => console.log(`[contact] learned bundle for ${c.identity}`));
client.on('error', (e) => console.log(`[error] ${e.message}`));

await client.connect();
console.log(`identity: ${client.identity}`);

const rl = createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });
rl.prompt();
rl.on('line', async (line) => {
  const [cmd, ...rest] = line.trim().split(' ');
  try {
    switch (cmd) {
      case '/id': console.log(client.identity); break;
      case '/bundle': console.log(client.bundle()); break;
      case '/add': console.log('added', await client.addContact(rest[0]!)); break;
      case '/send': await client.send(rest[0]!, utf8(rest.slice(1).join(' '))); console.log('[sent]'); break;
      case '/pub': await client.publish(rest[0]!, utf8(rest.slice(1).join(' '))); console.log('[published]'); break;
      case '/sub': client.subscribe(rest[0]!, () => {}); console.log('[subscribed]'); break;
      case '/quit': client.close(); process.exit(0);
      default: console.log('commands: /id /bundle /add /send /pub /sub /quit');
    }
  } catch (e) {
    console.log('[error]', (e as Error).message);
  }
  rl.prompt();
});
