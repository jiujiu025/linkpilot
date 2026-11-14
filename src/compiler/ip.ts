/**
 * 极简 IPv4 工具
 *
 * 编译器只处理 IPv4：V1 明确关闭 IPv6（docs/design/03 §5），
 * 所以这里不引入完整 IP 库，只做校验、/32 归一化和 /30 对端地址推导。
 */

export function parseIpv4(input: string): number | null {
  const parts = input.trim().split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = (value << 8) + octet;
  }
  return value >>> 0;
}

export function formatIpv4(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join('.');
}

export function isIpv4(input: string): boolean {
  return parseIpv4(input) !== null;
}

export function isIpv6(input: string): boolean {
  return input.includes(':');
}

/** 接受 a.b.c.d 或 a.b.c.d/nn，返回规范化的网络与掩码位数 */
export function parseCidr(input: string): { network: number; prefix: number } | null {
  const [addr, prefixRaw] = input.split('/');
  if (addr === undefined) return null;
  const ip = parseIpv4(addr);
  if (ip === null) return null;
  if (prefixRaw === undefined) return { network: ip, prefix: 32 };
  if (!/^\d{1,2}$/.test(prefixRaw)) return null;
  const prefix = Number(prefixRaw);
  if (prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, prefix };
}

export function cidrOverlaps(a: string, b: string): boolean {
  const ca = parseCidr(a);
  const cb = parseCidr(b);
  if (!ca || !cb) return false;
  const minPrefix = Math.min(ca.prefix, cb.prefix);
  const mask = minPrefix === 0 ? 0 : (0xffffffff << (32 - minPrefix)) >>> 0;
  return ((ca.network & mask) >>> 0) === ((cb.network & mask) >>> 0);
}

/**
 * 由 tun 地址推导「对端」地址。
 * 客户端 DNS 被 DNAT 到这个地址，报文才会进入 tun，被 hijack-dns 规则截获；
 * 指向 tun 自身的报文只到 INPUT，截不到。
 */
export function tunPeerAddress(tunCidr: string): string | null {
  const cidr = parseCidr(tunCidr);
  if (!cidr || cidr.prefix > 30) return null;
  // 点对点段：网络地址 +1 归设备，+2 作为 DNS 黑洞对端
  return formatIpv4((cidr.network + 2) >>> 0);
}
