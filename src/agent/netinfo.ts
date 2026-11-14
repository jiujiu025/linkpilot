/**
 * 设备侧网络信息读取（只读）
 *
 * 两件事：
 * 1. 由源 IP 反查 MAC —— 门户登录时，客户端会自报 IP，但绝不接受它自报 MAC。
 * 2. 由 MAC 找 IP —— 预授权设备（编码器/NVR）没有浏览器，只能按 MAC 认领。
 *
 * 全部只读 /proc 与 dnsmasq 租约文件，不执行任何写操作。
 */
import fs from 'node:fs';
import { hashMacAddress } from '../core/crypto.ts';

/** /proc/net/arp 一行：IP address  HW type  Flags  HW address  Mask  Device */
export function parseArpTable(text: string): { ip: string; mac: string }[] {
  const out: { ip: string; mac: string }[] = [];
  for (const line of text.split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const [ip, , flags, mac] = cols;
    // 0x2 = ATF_COM（条目有效），0x0 的条目是占位，MAC 全 0
    if (!ip || !mac || mac === '00:00:00:00:00:00') continue;
    if (flags === '0x0') continue;
    out.push({ ip, mac: mac.toLowerCase() });
  }
  return out;
}

/** dnsmasq 租约：<expiry> <mac> <ip> <hostname> <clientid> */
export function parseDhcpLeases(text: string): { mac: string; ip: string; hostname: string }[] {
  const out: { mac: string; ip: string; hostname: string }[] = [];
  for (const line of text.split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 3) continue;
    const [, mac, ip, hostname] = cols;
    if (!mac || !ip) continue;
    out.push({ mac: mac.toLowerCase(), ip, hostname: hostname && hostname !== '*' ? hostname : '' });
  }
  return out;
}

function readFile(file: string): string {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

export function readArpTable(file = '/proc/net/arp'): { ip: string; mac: string }[] {
  return parseArpTable(readFile(file));
}

export function readDhcpLeases(file = '/tmp/dhcp.leases'): { mac: string; ip: string; hostname: string }[] {
  return parseDhcpLeases(readFile(file));
}

/**
 * 由源 IP 得到设备身份。
 *
 * ARP 表里查不到时（例如客户端刚上线、或跨网段），退化为按 IP 生成稳定标识：
 * 宁可让「同一 IP 的会话」可用，也不要因为拿不到 MAC 就拒绝登录——
 * 那样用户会看到「账号密码都对，就是登不上」。
 */
export function identityForIp(ip: string, arp = readArpTable()): { macHash: string; mac: string | null } {
  const hit = arp.find((entry) => entry.ip === ip);
  if (hit) return { macHash: hashMacAddress(hit.mac), mac: hit.mac };
  return { macHash: hashMacAddress(`ip:${ip}`), mac: null };
}

/** 预授权设备：按 MAC 摘要找当前 IP，找不到就等下一轮（它还没连上） */
export function ipForMacHash(macHash: string, leases = readDhcpLeases()): string | null {
  const hit = leases.find((lease) => hashMacAddress(lease.mac) === macHash);
  return hit?.ip ?? null;
}
