/**
 * nftables 规则集生成器
 *
 * 这一层是产品的「防泄露底线」：不管上层策略怎么变，转发链的默认动作永远是 drop。
 * 只有两条路能出公网：
 *   1. 已授权设备 → lp-tun（进入代理链路）
 *   2. 设备自身的出站（OUTPUT，运行 sing-box 与 Agent）
 * 其余一律拒绝，包括「代理挂了就退回直连」这种最常见的泄露路径。
 */
import type { DesiredState } from '../core/schema.ts';
import { isIpv4 } from './ip.ts';
import { AUTHED_SET, sessionSetName } from './sessions.ts';
import { TPROXY_MARK, type CompilePlan } from './plan.ts';
import { dnsHijackTarget } from './singbox.ts';

function setBlock(name: string, type: string, elements: string[], comment: string): string {
  const lines = [
    `\tset ${name} {`,
    `\t\ttype ${type}`,
    `\t\tflags interval`,
    `\t\tauto-merge`,
  ];
  if (elements.length > 0) lines.push(`\t\telements = { ${elements.join(', ')} }`);
  lines.push(`\t\tcomment "${comment}"`);
  lines.push('\t}');
  return lines.join('\n');
}

export type NftablesBuildInput = {
  plan: CompilePlan;
  state: DesiredState;
  now?: number;
};

export function buildNftables({ plan, state, now }: NftablesBuildInput): string {
  const lan = state.lan;
  const dnsTarget = dnsHijackTarget(state);
  const authorized = plan.authorizedClientIps.filter(isIpv4);
  const pending = plan.pendingClientIps.filter(isIpv4);

  const parts: string[] = [];
  parts.push('#!/usr/sbin/nft -f');
  parts.push('# ------------------------------------------------------------------');
  parts.push('# 由 LinkPilot 策略编译器生成，禁止手工修改');
  parts.push(`# 设备: ${state.deviceId}`);
  parts.push(`# 配置版本: r${state.revision}`);
  parts.push(`# 生成时间: ${new Date(now ?? Date.now()).toISOString()}`);
  parts.push('# 语义: 转发链默认 drop；已授权设备只能经 tun 出网；未授权设备只能访问门户；IPv6 全阻断');
  parts.push('# ------------------------------------------------------------------');
  parts.push('');
  parts.push('table inet linkpilot');
  parts.push('delete table inet linkpilot');
  parts.push('');
  parts.push('table inet linkpilot {');

  parts.push(setBlock('authorized_v4', 'ipv4_addr', authorized, '已授权设备，唯一允许出公网集合'));
  parts.push(setBlock('pending_v4', 'ipv4_addr', pending, '未授权/待授权设备'));
  // 会话模式：每条线路一个集合，运行期由门户写入；编译期必然为空
  if (plan.sessionMode) {
    for (const linePort of plan.linePorts) {
      parts.push(setBlock(sessionSetName(linePort.lineId), 'ipv4_addr', [], `线路 ${linePort.lineId} 的在线会话`));
    }
    parts.push(setBlock(AUTHED_SET, 'ipv4_addr', [], '所有已登录会话的源地址（运行期维护）'));
  }
  const portalPorts = [...new Set([lan.portalPort, lan.controlPort])].sort((a, b) => a - b).join(', ');
  const tproxyPorts = plan.linePorts.map((lp) => lp.port).join(', ');

  // 会话模式：tproxy 分流（prerouting/mangle）
  if (plan.sessionMode) {
    parts.push('');
    parts.push('\tchain tproxy_in {');
    parts.push('\t\t# ---- 会话分流：按源地址把流量交给对应线路的入站 ----');
    parts.push('\t\ttype filter hook prerouting priority mangle; policy accept;');
    parts.push('\t\t# 同网段互访不进代理：客户端之间的流量必须在二层/本地直通，不能被劫进 sing-box');
    parts.push(`\t\tiifname "${lan.lanInterface}" ip daddr ${lan.cidr} accept`);
    parts.push('\t\t# DHCP 必须绕开代理，否则客户端拿不到地址');
    parts.push(`\t\tiifname "${lan.lanInterface}" udp dport { 67, 68 } accept`);
    parts.push(`\t\t# 发往网关本机的门户/控制口不进代理，否则登录页自己都打不开`);
    parts.push(
      `\t\tiifname "${lan.lanInterface}" ip daddr ${lan.gateway} tcp dport { ${portalPorts} } accept`,
    );
    for (const linePort of plan.linePorts) {
      parts.push(
        `\t\tiifname "${lan.lanInterface}" ip saddr @${sessionSetName(linePort.lineId)} meta l4proto { tcp, udp } tproxy ip to :${linePort.port} meta mark set ${TPROXY_MARK} accept comment "线路 ${linePort.lineId}"`,
      );
    }
    parts.push('\t}');
  }

  // DNS 劫持：DNAT 到 tun 对端，让查询进入 sing-box 的 DNS 路由
  parts.push('');
  parts.push('\tchain dns_hijack {');
  parts.push('\t\ttype nat hook prerouting priority dstnat; policy accept;');
  if (plan.sessionMode) {
    parts.push('\t\t# 已登录会话的 DNS 在 tproxy 阶段已交给对应线路的入站，这里不再重复处理');
    parts.push(`\t\tiifname "${lan.lanInterface}" ip saddr @${AUTHED_SET} counter return`);
    parts.push('\t\t# 未登录设备：DNS 统一指向门户解析器，任何域名都解析到网关，才能触发登录弹窗');
    parts.push(
      `\t\tiifname "${lan.lanInterface}" meta l4proto { tcp, udp } th dport 53 counter dnat ip to ${lan.gateway}:53`,
    );
  } else {
    parts.push('\t\t# 只对已授权设备做 DNS 劫持：未授权/未知设备连解析都不给，避免被当探测跳板');
    parts.push(`\t\tiifname "${lan.lanInterface}" ip saddr != @authorized_v4 counter return`);
    if (dnsTarget) {
      parts.push(
        `\t\tiifname "${lan.lanInterface}" meta l4proto { tcp, udp } th dport 53 counter dnat ip to ${dnsTarget}:53`,
      );
    }
  }
  parts.push('\t\t# 明文 DoT 直接拒绝，避免绕过受控 DNS');
  parts.push(`\t\tiifname "${lan.lanInterface}" meta l4proto tcp th dport 853 counter reject`);
  if (plan.sessionMode) {
    parts.push('\t\t# 未登录设备访问任意 HTTP，一律跳到登录页（触发系统「需要登录」提示）');
    parts.push(
      `\t\tiifname "${lan.lanInterface}" ip saddr != @${AUTHED_SET} meta l4proto tcp th dport 80 counter dnat ip to ${lan.gateway}:${lan.portalPort}`,
    );
  }
  parts.push('\t}');

  // 客户端横向隔离：只在明确要求隔离时生成
  if (!lan.allowClientToClient) {
    parts.push('');
    parts.push('\tchain client_isolation {');
    parts.push('\t\ttype filter hook forward priority filter - 10; policy accept;');
    parts.push(`\t\tiifname "${lan.lanInterface}" oifname "${lan.lanInterface}" counter reject comment "客户端之间禁止互访"`);
    parts.push('\t}');
  }

  parts.push('');
  parts.push('\tchain forward {');
  parts.push('\t\ttype filter hook forward priority filter; policy drop;');
  parts.push('\t\tct state established,related counter accept');
  parts.push(`\t\tip daddr ${lan.gateway} counter accept comment "网关与本地门户"`);
  if (plan.sessionMode) {
    parts.push('\t\t# 会话模式下已登录流量在 tproxy 阶段就地转交本机，不经过 forward；');
    parts.push('\t\t# 走到这里说明既没登录也没被分流，一律拒绝（Kill Switch 的语义不变）');
    parts.push(`\t\tiifname "${lan.lanInterface}" ip saddr != @${AUTHED_SET} counter reject comment "未登录设备禁止出网"`);
  } else {
    parts.push(`\t\tiifname "${lan.lanInterface}" ip saddr @pending_v4 counter reject comment "未授权设备禁止公网访问"`);
    parts.push(`\t\toifname "${lan.tunName}" ip saddr @authorized_v4 counter accept comment "唯一合法公网出口"`);
  }
  parts.push('\t\tcounter reject comment "kill-switch: 未进入代理链路的流量一律拒绝"');
  parts.push('\t}');

  parts.push('');
  parts.push('\tchain input {');
  parts.push('\t\ttype filter hook input priority filter; policy drop;');
  parts.push('\t\tiifname "lo" counter accept');
  parts.push('\t\tct state established,related counter accept');
  parts.push(`\t\tiifname "${lan.lanInterface}" udp dport { 53, 67, 68 } counter accept comment "DHCP 与受控 DNS"`);
  parts.push(`\t\tiifname "${lan.lanInterface}" tcp dport { 53 } counter accept`);
  parts.push(
    `\t\tiifname "${lan.lanInterface}" tcp dport { ${portalPorts} } counter accept comment "本地门户"`,
  );
  parts.push(`\t\tiifname "${lan.lanInterface}" icmp type { echo-request } counter accept`);
  if (plan.sessionMode && tproxyPorts.length > 0) {
    parts.push(
      `\t\tiifname "${lan.lanInterface}" meta l4proto { tcp, udp } th dport { ${tproxyPorts} } counter accept comment "tproxy 入站：已登录会话的就地交付端口"`,
    );
  }
  parts.push('\t\tmeta l4proto ipv6-icmp counter accept');
  parts.push('\t\tcounter reject comment "其余入站一律拒绝"');
  parts.push('\t}');

  parts.push('');
  parts.push('\tchain output {');
  parts.push('\t\ttype filter hook output priority filter; policy accept;');
  parts.push('\t}');
  parts.push('}');

  // IPv6：V1 全阻断，连「恢复 IPv6 但没有代理」这种半残状态都不允许出现
  parts.push('');
  parts.push('table ip6 linkpilot6');
  parts.push('delete table ip6 linkpilot6');
  parts.push('table ip6 linkpilot6 {');
  parts.push('\tchain forward {');
  parts.push('\t\ttype filter hook forward priority filter; policy drop;');
  parts.push('\t\tcounter reject comment "V1 关闭 IPv6，禁止任何转发"');
  parts.push('\t}');
  parts.push('\tchain input {');
  parts.push('\t\ttype filter hook input priority filter; policy drop;');
  parts.push('\t\tiifname "lo" counter accept');
  parts.push('\t\tmeta l4proto ipv6-icmp counter accept comment "保留邻居发现，便于诊断"');
  parts.push('\t\tcounter reject');
  parts.push('\t}');
  parts.push('}');
  parts.push('');

  return parts.join('\n');
}
