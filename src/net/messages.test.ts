import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../common/bytes.js';
import { Writer } from '../common/serialize.js';
import { encodeMessage } from './codec.js';
import {
  Bip155Network,
  DefaultPorts,
  NetworkMagic,
  PROTOCOL_VERSION,
  ServiceFlags,
  bytesToIp,
  decodeAddr,
  decodeAddrV2,
  decodePing,
  decodeVersion,
  encodeAddr,
  encodeAddrV2,
  encodePing,
  encodeVersion,
  hasService,
  ipToBytes,
  type VersionMessage,
} from './messages.js';

describe('constants', () => {
  it('network magic and ports', () => {
    expect(toHex(NetworkMagic.mainnet)).toBe('bd5fc300');
    expect(toHex(NetworkMagic.testnet)).toBe('2467d2c1');
    expect(toHex(NetworkMagic.regtest)).toBe('fdbf9ffb');
    expect(DefaultPorts).toEqual({ mainnet: 48470, testnet: 33670, regtest: 18444 });
    expect(PROTOCOL_VERSION).toBe(70016);
  });

  it('service flags', () => {
    expect(ServiceFlags.NODE_NETWORK).toBe(1n);
    expect(ServiceFlags.NODE_P2PMSG).toBe(0x1000000n);
    expect(ServiceFlags.NODE_P2PMSG_LEAF).toBe(0x2000000n);
    expect(hasService(ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG, ServiceFlags.NODE_P2PMSG)).toBe(true);
    expect(hasService(ServiceFlags.NODE_NETWORK, ServiceFlags.NODE_P2PMSG)).toBe(false);
  });

  it('known answer: verack on regtest', () => {
    expect(toHex(encodeMessage(NetworkMagic.regtest, 'verack'))).toBe(
      'fdbf9ffb76657261636b000000000000000000005df6e0e2',
    );
  });
});

describe('ip helpers', () => {
  it('IPv4 is mapped to ::ffff:a.b.c.d', () => {
    expect(toHex(ipToBytes('127.0.0.1'))).toBe('00000000000000000000ffff7f000001');
    expect(bytesToIp(fromHex('00000000000000000000ffff7f000001'))).toBe('127.0.0.1');
    expect(bytesToIp(fromHex('c0a80101'))).toBe('192.168.1.1');
  });

  it('IPv6 round trips', () => {
    for (const [txt, hex] of [
      ['::', '00000000000000000000000000000000'],
      ['::1', '00000000000000000000000000000001'],
      ['2001:db8::1', '20010db8000000000000000000000001'],
      ['fe80::1:2:3:4', 'fe800000000000000001000200030004'],
      ['1:2:3:4:5:6:7:8', '00010002000300040005000600070008'],
      ['2001:db8:0:0:1::', '20010db8000000000001000000000000'],
    ] as const) {
      expect(toHex(ipToBytes(txt))).toBe(hex);
      expect(bytesToIp(fromHex(hex))).toBe(txt);
    }
    expect(toHex(ipToBytes('[::1]'))).toBe('00000000000000000000000000000001');
    expect(toHex(ipToBytes('::ffff:1.2.3.4'))).toBe('00000000000000000000ffff01020304');
    expect(bytesToIp(fromHex('00000000000000000000ffff01020304'))).toBe('1.2.3.4');
    expect(() => ipToBytes('nope')).toThrow();
    expect(() => ipToBytes('1:2:3')).toThrow();
    expect(() => ipToBytes('::1::2')).toThrow();
  });
});

describe('version', () => {
  const v: VersionMessage = {
    version: PROTOCOL_VERSION,
    services: ServiceFlags.NODE_P2PMSG_LEAF,
    timestamp: 1_700_000_000n,
    addrRecv: { services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG, host: '10.0.0.7', port: 48470 },
    addrFrom: { services: ServiceFlags.NODE_P2PMSG_LEAF, host: '2001:db8::1', port: 0 },
    nonce: 0x0123456789abcdefn,
    userAgent: '/navio-p2pmsg:0.1.0/',
    startHeight: 0,
    relay: false,
  };

  it('encode → decode round trip', () => {
    const bytes = encodeVersion(v);
    expect(bytes.length).toBe(4 + 8 + 8 + 26 + 26 + 8 + 1 + v.userAgent.length + 4 + 1);
    expect(decodeVersion(bytes)).toEqual(v);
  });

  it('wire layout', () => {
    const bytes = encodeVersion(v);
    expect(toHex(bytes.subarray(0, 4))).toBe('80110100'); // 70016 LE
    expect(toHex(bytes.subarray(4, 12))).toBe('0000000200000000'); // services LE (1<<25)
    expect(toHex(bytes.subarray(12, 20))).toBe('00f1536500000000'); // timestamp LE (0x6553f100)
    // addr_recv: services(8) ip(16) port BE(2)
    expect(toHex(bytes.subarray(20, 28))).toBe('0100000100000000');
    expect(toHex(bytes.subarray(28, 44))).toBe('00000000000000000000ffff0a000007');
    expect(toHex(bytes.subarray(44, 46))).toBe('bd56'); // 48470 BE
    expect(toHex(bytes.subarray(72, 80))).toBe('efcdab8967452301'); // nonce LE
    expect(bytes[bytes.length - 1]).toBe(0); // relay
  });

  it('tolerates truncated legacy version payloads', () => {
    const bytes = encodeVersion(v);
    const short = bytes.subarray(0, 4 + 8 + 8 + 26); // up to addr_recv
    const d = decodeVersion(short);
    expect(d.version).toBe(70016);
    expect(d.userAgent).toBe('');
    expect(d.relay).toBe(true);
  });
});

describe('ping/pong', () => {
  it('u64 nonce', () => {
    expect(toHex(encodePing(1n))).toBe('0100000000000000');
    expect(decodePing(fromHex('efcdab8967452301'))).toBe(0x0123456789abcdefn);
    expect(decodePing(new Uint8Array(0))).toBeNull();
  });
});

describe('addr', () => {
  it('legacy addr round trip', () => {
    const addrs = [
      { host: '1.2.3.4', port: 48470, services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_P2PMSG, time: 1_700_000_000 },
      { host: '2001:db8::2', port: 33670, services: ServiceFlags.NODE_NETWORK, time: 1_700_000_001 },
    ];
    const bytes = encodeAddr(addrs);
    expect(bytes.length).toBe(1 + 2 * 30);
    expect(decodeAddr(bytes)).toEqual(addrs);
  });

  it('addrv2 decode of a hand-built BIP155 payload', () => {
    const w = new Writer();
    w.compactSize(4);
    // #1 IPv4 with services as multi-byte compactsize (NODE_NETWORK | NODE_P2PMSG = 0x01000001)
    w.u32(1_700_000_000);
    w.u8(0xfe).u32(0x01000001);
    w.u8(Bip155Network.IPV4);
    w.varBytes(fromHex('c0a80101'));
    w.u8(0xbd).u8(0x56); // 48470 BE
    // #2 IPv6
    w.u32(1_700_000_001);
    w.compactSize(1); // NODE_NETWORK
    w.u8(Bip155Network.IPV6);
    w.varBytes(fromHex('20010db8000000000000000000000001'));
    w.u8(0x83).u8(0x86); // 33670 BE
    // #3 TorV3 – must be skipped
    w.u32(1_700_000_002);
    w.compactSize(1);
    w.u8(Bip155Network.TORV3);
    w.varBytes(new Uint8Array(32).fill(0xaa));
    w.u8(0x00).u8(0x50);
    // #4 unknown network id 42 with odd length – skipped too
    w.u32(1_700_000_003);
    w.compactSize(0);
    w.u8(42);
    w.varBytes(new Uint8Array(7));
    w.u8(0x00).u8(0x01);

    const out = decodeAddrV2(w.finish());
    expect(out).toEqual([
      { host: '192.168.1.1', port: 48470, services: 0x01000001n, time: 1_700_000_000 },
      { host: '2001:db8::1', port: 33670, services: 1n, time: 1_700_000_001 },
    ]);
  });

  it('addrv2 encode → decode round trip', () => {
    const addrs = [
      { host: '5.6.7.8', port: 18444, services: ServiceFlags.NODE_P2PMSG, time: 1 },
      { host: 'fe80::1', port: 1, services: 0n, time: 2 },
    ];
    const bytes = encodeAddrV2(addrs);
    // count(1) + [time4 + svc5 (0xfe u32) + net1 + len1 + 4 + port2] + [time4 + svc1 + net1 + len1 + 16 + port2]
    expect(bytes.length).toBe(1 + 17 + 25);
    expect(decodeAddrV2(bytes)).toEqual(addrs);
  });

  it('rejects oversize addr lists', () => {
    expect(() => decodeAddrV2(new Writer().compactSize(1001).finish())).toThrow(/too large/);
  });
});
