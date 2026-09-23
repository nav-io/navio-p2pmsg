import { describe, expect, it } from 'vitest';
import { randomBytes, toHex } from '../common/bytes.js';
import { loopbackPair } from './transport.js';
import {
  ALL_SECTIONS,
  mergeHeads,
  parseGroupSnapshot,
  parseReadSnapshot,
  parseStateMessage,
  serializeGroupSnapshot,
  serializeReadSnapshot,
  serializeStateMessage,
  StateOp,
  StateSection,
  StateSyncClient,
  StateSyncServer,
  STATE_BATCH_SIZE,
  type StateMessage,
  type StateSource,
} from './statesync.js';

function source(over: Partial<StateSource> = {}): StateSource {
  return {
    contacts: () => Promise.resolve([]),
    groups: () => Promise.resolve([]),
    read: () => Promise.resolve([]),
    ...over,
  };
}

function pair(src: StateSource) {
  const [a, b] = loopbackPair();
  const server = new StateSyncServer(a.channel('control'), src);
  const client = new StateSyncClient(b.channel('control'));
  return { server, client };
}

describe('device state sync', () => {
  it('carries contacts, groups and read state', async () => {
    const { client } = pair(
      source({
        contacts: () => Promise.resolve([randomBytes(50)]),
        groups: () => Promise.resolve([{ state: randomBytes(80), secrets: [{ epoch: 2, secret: randomBytes(32) }] }]),
        read: () => Promise.resolve([{ convId: randomBytes(32), heads: [randomBytes(32), randomBytes(32)] }]),
      }),
    );
    const res = await client.fetch({ timeoutMs: 10000 });
    expect(res.contacts).toHaveLength(1);
    expect(res.groups[0]!.secrets[0]!.epoch).toBe(2);
    expect(res.read[0]!.heads).toHaveLength(2);
    expect(res.malformed).toBe(0);
  });

  it('asks for only the sections it is missing', async () => {
    let asked = 0;
    const { client } = pair(
      source({
        contacts: () => {
          asked |= StateSection.CONTACTS;
          return Promise.resolve([randomBytes(10)]);
        },
        groups: () => {
          asked |= StateSection.GROUPS;
          return Promise.resolve([]);
        },
        read: () => {
          asked |= StateSection.READ;
          return Promise.resolve([]);
        },
      }),
    );
    await client.fetch({ sections: StateSection.CONTACTS, timeoutMs: 10000 });
    expect(asked).toBe(StateSection.CONTACTS);
  });

  it('batches a long list and still completes', async () => {
    const many = Array.from({ length: STATE_BATCH_SIZE * 3 + 7 }, () => randomBytes(40));
    const { client } = pair(source({ contacts: () => Promise.resolve(many) }));
    const res = await client.fetch({ timeoutMs: 20000 });
    expect(res.contacts).toHaveLength(many.length);
  });

  it('counts an item it cannot parse instead of guessing at it', async () => {
    const { client } = pair(source({ read: () => Promise.resolve([]) }));
    // Hand-built batch with a truncated read snapshot.
    const [a, b] = loopbackPair();
    const c2 = new StateSyncClient(b.channel('control'));
    const pending = c2.fetch({ timeoutMs: 10000 });
    a.channel('control').send(
      serializeStateMessage({ op: StateOp.BATCH, section: StateSection.READ, items: [new Uint8Array(5)] }),
    );
    a.channel('control').send(serializeStateMessage({ op: StateOp.DONE }));
    const res = await pending;
    expect(res.malformed).toBe(1);
    expect(res.read).toHaveLength(0);
    void client;
  });

  it('surfaces a denial and refuses two fetches at once', async () => {
    const { client } = pair(source({ groups: () => Promise.reject(new Error('store is gone')) }));
    const first = client.fetch({ timeoutMs: 10000 });
    await expect(client.fetch({ timeoutMs: 10000 })).rejects.toThrow(/already in flight/);
    await expect(first).rejects.toThrow(/store is gone/);
  });

  it('times out with nothing on the other end', async () => {
    const [, b] = loopbackPair();
    const client = new StateSyncClient(b.channel('control'));
    await expect(client.fetch({ timeoutMs: 400 })).rejects.toThrow(/timed out/);
  });

  it('round trips every state message and item', () => {
    const msgs: StateMessage[] = [
      { op: StateOp.REQUEST, sections: ALL_SECTIONS },
      { op: StateOp.BATCH, section: StateSection.GROUPS, items: [randomBytes(9)] },
      { op: StateOp.DONE },
      { op: StateOp.DENY, reason: 'nope' },
    ];
    for (const m of msgs) expect(parseStateMessage(serializeStateMessage(m))).toEqual(m);
    expect(() => parseStateMessage(new Uint8Array([77]))).toThrow(/unknown state op/);

    const g = { state: randomBytes(30), secrets: [{ epoch: 0, secret: randomBytes(32) }] };
    expect(parseGroupSnapshot(serializeGroupSnapshot(g))).toEqual(g);
    const r = { convId: randomBytes(32), heads: [randomBytes(32)] };
    expect(parseReadSnapshot(serializeReadSnapshot(r))).toEqual(r);
  });

  it('merges read heads as a union, so nothing becomes unread', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(mergeHeads([a], [b]).map(toHex).sort()).toEqual([toHex(a), toHex(b)].sort());
    // Idempotent: syncing twice does not grow the set.
    expect(mergeHeads([a, b], [b])).toHaveLength(2);
  });
});
