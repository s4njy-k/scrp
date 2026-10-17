import { describe, expect, it } from 'vitest';
import { classifyAddress, classifyHostname } from '../../src/gateway/policy.js';

describe('egress destination policy (§13)', () => {
  it.each([
    ['127.0.0.1'], ['10.1.2.3'], ['172.16.0.5'], ['192.168.1.1'], ['169.254.169.254'], ['100.64.1.1'], ['0.0.0.0'],
    ['224.0.0.1'], ['255.255.255.255'], ['192.0.2.10'], ['198.18.0.1'], ['240.0.0.1'], ['168.63.129.16'], ['100.100.100.200'],
    ['::1'], ['::'], ['fe80::1'], ['fc00::1'], ['fd00:ec2::254'], ['ff02::1'], ['::ffff:127.0.0.1'], ['::ffff:10.0.0.1'],
    ['::ffff:8.8.8.8'], ['64:ff9b::a00:1'], ['2002:a00:1::1'], ['2001:db8::1'], ['2001:0:4136:e378::1'],
  ])('denies %s', (addr) => {
    expect(classifyAddress(addr).allowed).toBe(false);
  });

  it.each([['8.8.8.8'], ['1.1.1.1'], ['93.184.215.14'], ['2606:4700:4700::1111']])('allows public %s', (addr) => {
    expect(classifyAddress(addr).allowed).toBe(true);
  });

  it('applies configured extra deny ranges', () => {
    expect(classifyAddress('8.8.8.8', ['8.8.8.0/24']).allowed).toBe(false);
  });

  it('refuses internal-looking hostnames before DNS', () => {
    for (const h of ['localhost', 'db.localhost', 'metadata.google.internal', 'printer.local', 'router']) {
      expect(classifyHostname(h).ok).toBe(false);
    }
    expect(classifyHostname('example.com').ok).toBe(true);
  });
});
