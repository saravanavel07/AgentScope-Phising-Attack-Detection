import dns from 'node:dns/promises';
import net from 'node:net';

export interface SafeTargetResult {
  allowed: boolean;
  reason?: string;
  resolvedIps: string[];
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const oct = Number(part);
    if (oct < 0 || oct > 255) return null;
    num = (num << 8) | oct;
  }
  return num >>> 0;
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.trim().toLowerCase();

  if (net.isIPv4(normalized)) {
    const val = ipv4ToInt(normalized);
    if (val === null) return true;

    const ranges: Array<[number, number]> = [
      [0x00000000, 0x00ffffff], // 0.0.0.0/8 (Current network)
      [0x0a000000, 0x0affffff], // 10.0.0.0/8 (Private)
      [0x64400000, 0x647fffff], // 100.64.0.0/10 (Carrier-grade NAT)
      [0x7f000000, 0x7fffffff], // 127.0.0.0/8 (Loopback)
      [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 (Link-local / Cloud metadata)
      [0xac100000, 0xac1fffff], // 172.16.0.0/12 (Private)
      [0xc0000000, 0xc00000ff], // 192.0.0.0/24 (IETF protocol)
      [0xc0000200, 0xc00002ff], // 192.0.2.0/24 (TEST-NET-1)
      [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16 (Private)
      [0xc6120000, 0xc613ffff], // 198.18.0.0/15 (Benchmarking)
      [0xc6336400, 0xc63364ff], // 198.51.100.0/24 (TEST-NET-2)
      [0xcb007100, 0xcb0071ff], // 203.0.113.0/24 (TEST-NET-3)
      [0xe0000000, 0xffffffff], // 224.0.0.0/4+ (Multicast / Reserved)
    ];

    return ranges.some(([start, end]) => val >= start && val <= end);
  }

  if (net.isIPv6(normalized)) {
    if (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('ff')
    ) {
      return true;
    }
    if (normalized.startsWith('::ffff:')) {
      const mapped = normalized.slice(7);
      if (net.isIPv4(mapped)) {
        return isPrivateOrReservedIp(mapped);
      }
    }
    return false;
  }

  return true;
}

export async function validateOutboundHost(hostname: string): Promise<SafeTargetResult> {
  const cleanHost = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (
    !cleanHost ||
    cleanHost === 'localhost' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal')
  ) {
    return {
      allowed: false,
      reason: 'Target points to a local or internal hostname and was blocked from outbound probing.',
      resolvedIps: [],
    };
  }

  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      return {
        allowed: false,
        reason: 'Target IP address falls within a private, loopback, or reserved range.',
        resolvedIps: [cleanHost],
      };
    }
    return { allowed: true, resolvedIps: [cleanHost] };
  }

  try {
    const records = await Promise.race([
      dns.lookup(cleanHost, { all: true, verbatim: true }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('DNS lookup timeout')), 3000)
      ),
    ]);

    const ips = records.map((r) => r.address);
    if (ips.length === 0) {
      return { allowed: false, reason: 'Domain did not resolve to any IP address.', resolvedIps: [] };
    }

    for (const ip of ips) {
      if (isPrivateOrReservedIp(ip)) {
        return {
          allowed: false,
          reason: `Domain resolved to a restricted internal IP (${ip}); outbound probe blocked.`,
          resolvedIps: ips,
        };
      }
    }

    return { allowed: true, resolvedIps: ips };
  } catch {
    return {
      allowed: false,
      reason: 'Domain could not be resolved via DNS.',
      resolvedIps: [],
    };
  }
}
