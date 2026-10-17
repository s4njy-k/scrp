/**
 * Public-destination policy for the egress gateway (blueprint §13).
 *
 * Denies loopback, private, link-local, CGNAT, reserved, multicast, documentation,
 * benchmarking, cloud metadata and IPv4-mapped/embedded IPv6 forms of those
 * addresses. A destination is permitted only when EVERY resolved address is
 * public; the gateway then connects to the checked address itself (pinning),
 * so DNS rebinding between check and connect cannot change the destination.
 */
import ipaddr from 'ipaddr.js';

/** Explicit extra denials beyond range classification. */
const EXTRA_DENY_CIDRS: [string, number][] = [
  ['0.0.0.0', 8],
  ['100.64.0.0', 10],       // CGNAT (also classified, kept explicit)
  ['192.0.0.0', 24],        // IETF protocol assignments
  ['192.0.2.0', 24],        // TEST-NET-1
  ['198.18.0.0', 15],       // benchmarking
  ['198.51.100.0', 24],     // TEST-NET-2
  ['203.0.113.0', 24],      // TEST-NET-3
  ['240.0.0.0', 4],         // reserved
  ['168.63.129.16', 32],    // Azure platform/wire server (publicly routable address)
  ['100.100.100.200', 32],  // Alibaba Cloud metadata
];

const EXTRA_DENY_V6: [string, number][] = [
  ['fd00:ec2::254', 128],   // AWS IMDS over IPv6 (ULA, also classified)
  ['64:ff9b::', 96],        // NAT64 well-known prefix (embeds IPv4)
  ['64:ff9b:1::', 48],      // local-use NAT64
  ['2002::', 16],           // 6to4 (embeds IPv4)
  ['2001::', 32],           // Teredo
  ['2001:db8::', 32],       // documentation
  ['100::', 64],            // discard-only
];

export type AddressVerdict = { allowed: true; normalised: string; family: 4 | 6 } | { allowed: false; normalised: string; reason: string };

export function classifyAddress(address: string, extraDeny: string[] = []): AddressVerdict {
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = ipaddr.parse(address);
  } catch {
    return { allowed: false, normalised: address, reason: 'unparseable_address' };
  }
  if (parsed.kind() === 'ipv6') {
    const v6 = parsed as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) {
      const inner = classifyAddress(v6.toIPv4Address().toString(), extraDeny);
      return inner.allowed
        ? { allowed: false, normalised: v6.toNormalizedString(), reason: 'ipv4_mapped_ipv6_not_permitted' }
        : { ...inner, normalised: v6.toNormalizedString(), reason: `ipv4_mapped:${inner.reason}` };
    }
    const range = v6.range();
    if (range !== 'unicast') return { allowed: false, normalised: v6.toNormalizedString(), reason: `ipv6_${range}` };
    for (const [net, bits] of EXTRA_DENY_V6) {
      if (v6.match(ipaddr.IPv6.parse(net), bits)) return { allowed: false, normalised: v6.toNormalizedString(), reason: `ipv6_denied_prefix:${net}/${bits}` };
    }
    for (const cidr of extraDeny) {
      const [net, bits] = ipaddr.parseCIDR(cidr);
      if (net.kind() === 'ipv6' && v6.match([net, bits])) return { allowed: false, normalised: v6.toNormalizedString(), reason: `configured_deny:${cidr}` };
    }
    return { allowed: true, normalised: v6.toNormalizedString(), family: 6 };
  }
  const v4 = parsed as ipaddr.IPv4;
  const range = v4.range();
  if (range !== 'unicast') return { allowed: false, normalised: v4.toString(), reason: `ipv4_${range}` };
  for (const [net, bits] of EXTRA_DENY_CIDRS) {
    if (v4.match(ipaddr.IPv4.parse(net), bits)) return { allowed: false, normalised: v4.toString(), reason: `ipv4_denied_range:${net}/${bits}` };
  }
  for (const cidr of extraDeny) {
    const [net, bits] = ipaddr.parseCIDR(cidr);
    if (net.kind() === 'ipv4' && v4.match([net, bits])) return { allowed: false, normalised: v4.toString(), reason: `configured_deny:${cidr}` };
  }
  return { allowed: true, normalised: v4.toString(), family: 4 };
}

/** Hostname sanity before DNS: refuse names that only make sense internally. */
export function classifyHostname(host: string): { ok: true } | { ok: false; reason: string } {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h) return { ok: false, reason: 'empty_host' };
  if (h.length > 253) return { ok: false, reason: 'host_too_long' };
  if (h === 'localhost' || h.endsWith('.localhost')) return { ok: false, reason: 'localhost_name' };
  if (h.endsWith('.internal') || h.endsWith('.local') || h.endsWith('.lan') || h.endsWith('.home.arpa') || h.endsWith('.intranet')) {
    return { ok: false, reason: 'internal_name' };
  }
  if (!h.includes('.')) return { ok: false, reason: 'single_label_name' };
  if (!/^[a-z0-9.-]+$/.test(h)) return { ok: false, reason: 'non_ascii_or_invalid_host' };
  return { ok: true };
}
