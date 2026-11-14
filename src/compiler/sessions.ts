/**
 * 会话模式的数据面表达
 *
 * 核心约束：改一个用户的线路时，不能重编译、更不能重启 sing-box。
 * 所以编译期只产出「每条线路一个集合 + 一个 tproxy 规则」的固定骨架，
 * 运行期登录/登出只改集合元素，毫秒级生效，其他人完全无感。
 *
 * 集合与规则的命名必须与 nftables.ts 生成的骨架严格一致，
 * 两边任何一处改名都会导致「登录成功但流量被丢」，因此集中在这里定义。
 */
import type { LinePort } from './plan.ts';

export type SessionEntry = {
  srcIp: string;
  lineId: string;
  accountId: string;
  macHash: string;
};

/** 线路 → 集合名；只允许 [a-z0-9_]，避免把非法字符带进 nft 脚本 */
export function sessionSetName(lineId: string): string {
  const safe = lineId
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '_')
    .slice(0, 24);
  return `sess_${safe}`;
}

export const AUTHED_SET = 'authed_v4';

/**
 * 生成运行期的会话更新脚本。
 *
 * 用法：agent 在门户登录/登出/到期后写这个文件并 `nft -f` 执行。
 * 先 flush 后 add，保证同一账号的旧 IP 一定被清掉——否则换 IP 后
 * 会出现「一个账号占着两个源地址」，等于一账号两台设备。
 */
export function renderSessionsNft(input: { linePorts: LinePort[]; sessions: SessionEntry[] }): string {
  const byLine = new Map<string, string[]>();
  for (const linePort of input.linePorts) byLine.set(linePort.lineId, []);
  for (const session of input.sessions) {
    const list = byLine.get(session.lineId);
    if (!list) continue; // 线路不在本次编译里：忽略，不生成孤儿元素
    list.push(session.srcIp);
  }

  const lines: string[] = ['#!/usr/sbin/nft -f', '# 由 LinkPilot Agent 运行期生成：会话表', ''];
  for (const [lineId, ips] of byLine) {
    const set = sessionSetName(lineId);
    lines.push(`flush set inet linkpilot ${set}`);
    if (ips.length > 0) {
      const unique = [...new Set(ips)].sort();
      lines.push(`add element inet linkpilot ${set} { ${unique.join(', ')} }`);
    }
  }
  lines.push(`flush set inet linkpilot ${AUTHED_SET}`);
  const all = [...new Set(input.sessions.map((s) => s.srcIp))].sort();
  if (all.length > 0) {
    lines.push(`add element inet linkpilot ${AUTHED_SET} { ${all.join(', ')} }`);
  }
  lines.push('');
  return lines.join('\n');
}

/** 同一源 IP 不允许同时属于两条线路，否则数据面结果取决于规则顺序 */
export function assertUniqueSources(sessions: SessionEntry[]): void {
  const seen = new Map<string, string>();
  for (const session of sessions) {
    const prev = seen.get(session.srcIp);
    if (prev && prev !== session.lineId) {
      throw new Error(`源地址 ${session.srcIp} 同时属于线路 ${prev} 与 ${session.lineId}`);
    }
    seen.set(session.srcIp, session.lineId);
  }
}
