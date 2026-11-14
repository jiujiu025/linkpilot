/**
 * OpenWrt 侧配置片段生成器
 *
 * 只生成「可审计的 UCI 命令」，不直接改配置文件：
 * - 每条命令都能幂等重放，应用失败可以逐条回滚；
 * - Agent 以最小权限执行固定动作，不需要任意 Shell；
 * - 客户页面永远看不到这些内容。
 *
 * 静态租约只输出「设备 ID + 期望地址」，真实 MAC 由 Agent 在本地
 * 按 macHash 匹配 DHCP 观测结果后注入，云端不持有明文 MAC。
 */
import type { DesiredState } from '../core/schema.ts';
import type { CompilePlan } from './plan.ts';

export type LeasePlan = {
  clientId: string;
  hostname: string;
  ipAddress: string;
  macHash: string;
};

export type OpenwrtBuildInput = {
  plan: CompilePlan;
  state: DesiredState;
};

export type OpenwrtArtifacts = {
  uci: string;
  leases: LeasePlan[];
};

export function buildOpenwrt({ plan, state }: OpenwrtBuildInput): OpenwrtArtifacts {
  const lan = state.lan;
  const wifi = state.wifi;
  // 老设备档案里没有这两个字段：按「ARM 档位」处理，保持产物不变
  const lanPorts = Array.isArray(lan.lanPorts) ? lan.lanPorts : [];
  const wanPort = lan.wanPort ?? '';
  const lines: string[] = [];

  lines.push('#!/bin/sh');
  lines.push('# ------------------------------------------------------------------');
  lines.push(`# 由 LinkPilot 策略编译器生成，禁止手工修改（设备 ${state.deviceId} / r${state.revision}）`);
  lines.push('# 幂等：可重复执行；每条 set 后紧跟 commit，保证异常中断时状态可预期');
  lines.push('# ------------------------------------------------------------------');
  lines.push('set -e');
  lines.push('');

  lines.push('# ---- 接口映射 ----');
  if (lanPorts.length > 0) {
    // x86 档位：网桥不会被自动创建，不显式生成就是 LAN 不通、DHCP 与门户一起失效
    lines.push('# x86 档位：显式建 br-lan 网桥，端口由设备档案给出');
    lines.push('uci set network.lan_dev=device');
    lines.push(`uci set network.lan_dev.name='${lan.lanInterface}'`);
    lines.push("uci set network.lan_dev.type='bridge'");
    lines.push(`uci set network.lan_dev.ports='${lanPorts.join(' ')}'`);
    lines.push(`uci set network.lan.device='${lan.lanInterface}'`);
  } else {
    lines.push('# ARM 一体机：br-lan 由设备树固化，此处不生成 device 段');
  }
  if (wanPort) {
    lines.push('# WAN 口按设备档案固化，避免 eth0/eth1 探测顺序变化导致 WAN/LAN 对调');
    lines.push('uci set network.wan_dev=device');
    lines.push(`uci set network.wan_dev.name='${wanPort}'`);
    lines.push(`uci set network.${lan.wanInterface}.device='${wanPort}'`);
  }
  lines.push('');

  lines.push('# ---- 局域网与 DHCP ----');
  lines.push(`uci set network.lan.ipaddr='${lan.gateway}'`);
  lines.push(`uci set network.lan.netmask='${cidrToNetmask(lan.cidr)}'`);
  lines.push(`uci set dhcp.lan.start='${ipToOffset(lan.dhcpStart, lan.gateway)}'`);
  lines.push(`uci set dhcp.lan.limit='${dhcpLimit(lan)}'`);
  lines.push(`uci set dhcp.lan.leasetime='12h'`);
  lines.push(`uci set dhcp.lan.dhcp_option='6,${lan.gateway}'`);
  lines.push('');

  lines.push('# ---- IPv6 默认关闭（docs/design/03 §5）----');
  lines.push("uci set dhcp.lan.dhcpv6='disabled'");
  lines.push("uci set dhcp.lan.ra='disabled'");
  lines.push("uci set dhcp.lan.ndp='disabled'");
  lines.push("uci set dhcp.lan.ra_slaac='0'");
  lines.push("uci -q delete dhcp.lan.ra_flags || true");
  if (lan.ipv6Enabled) {
    lines.push("# 注意：当前版本声明 ipv6Enabled=true，但编译产物仍按 V1 默认关闭处理，需单独评审");
  }
  lines.push("uci set network.wan.ipv6='0'");
  lines.push("uci set network.wan6.disabled='1' 2>/dev/null || true");
  lines.push("uci set dhcp.odhcpd.enabled='0' 2>/dev/null || true");
  lines.push('');

  if (wifi.enabled) {
    lines.push('# ---- 单 SSID（WPA2/WPA3 混合，客户端隔离由 nftables 兜底）----');
    lines.push(`uci set wireless.@wifi-iface[0].ssid='${wifi.ssid}'`);
    lines.push("uci set wireless.@wifi-iface[0].encryption='sae-mixed'");
    lines.push("uci set wireless.@wifi-iface[0].key='$LP_WIFI_PSK'");
    lines.push("uci set wireless.@wifi-iface[0].isolate='1'");
    lines.push(`uci set wireless.@wifi-iface[0].hidden='${wifi.hidden ? 1 : 0}'`);
    if (wifi.band === '2.4' || wifi.band === '5') {
      lines.push(`uci set wireless.@wifi-iface[0].band='${wifi.band === '2.4' ? '2g' : '5g'}'`);
    }
  } else {
    lines.push('# ---- 本机无无线模块（x86/N100 档位）----');
    lines.push('# 无线接入由外部 AP 提供：AP 桥接到 LAN，客户端仍受 nftables 与门户约束');
    lines.push('# 这里不生成任何 wireless 配置，也不触发无线重载，避免因缺少 radio 而报错');
  }
  lines.push('');

  lines.push('# ---- dnsmasq：DNS 由 nftables DNAT 全量接管，本地解析器只保留 DHCP ----');
  lines.push("uci set dhcp.@dnsmasq[0].port='0'");
  lines.push("uci set dhcp.@dnsmasq[0].domainneeded='1'");
  lines.push("uci set dhcp.@dnsmasq[0].boguspriv='1'");
  lines.push("uci set dhcp.@dnsmasq[0].filterwin2k='0'");
  lines.push("uci set dhcp.@dnsmasq[0].localise_queries='0'");
  lines.push("uci set dhcp.@dnsmasq[0].rebind_protection='0'");
  lines.push('');

  lines.push('# ---- 门户：固定本地地址，不依赖 mDNS ----');
  lines.push(`# 门户监听 ${lan.gateway}:${lan.portalPort}，控制口 ${lan.gateway}:${lan.controlPort}（仅局域网）`);
  lines.push('');

  if (state.accessControl.mode === 'session') {
    lines.push('# ---- tproxy 策略路由（内核必需，否则 tproxy 标记的包不会被本机收下）----');
    lines.push('# mark 在 nftables 里打上，这里负责把 mark 指向 local 表；重复执行不会堆积规则');
    lines.push('ip rule del fwmark 1 lookup 100 2>/dev/null || true');
    lines.push('ip rule add fwmark 1 lookup 100');
    lines.push('ip route replace local default dev lo table 100');
    lines.push('sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true');
    lines.push('');
  }

  lines.push('# ---- 提交 ----');
  lines.push('uci commit network');
  lines.push('uci commit dhcp');
  if (wifi.enabled) {
    lines.push('uci commit wireless');
  }
  lines.push('');
  lines.push('/etc/init.d/network reload');
  lines.push('/etc/init.d/dnsmasq restart');
  if (wifi.enabled) {
    lines.push('wifi reload');
  }
  lines.push('');

  const leases: LeasePlan[] = plan.clients.map((client) => {
    const record = state.clients.find((c) => c.id === client.clientId);
    return {
      clientId: client.clientId,
      hostname: record?.hostname || sanitizeHostname(client.label),
      ipAddress: client.ipAddress,
      macHash: record?.macHash ?? '',
    };
  });

  return { uci: lines.join('\n'), leases };
}

function sanitizeHostname(label: string): string {
  return label
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 30) || 'device';
}

function cidrToNetmask(cidr: string): string {
  const prefix = Number(cidr.split('/')[1] ?? '24');
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [24, 16, 8, 0].map((shift) => (mask >>> shift) & 0xff).join('.');
}

function ipToOffset(ip: string, gateway: string): number {
  const a = ip.split('.').map(Number);
  const b = gateway.split('.').map(Number);
  if (a.length !== 4 || b.length !== 4) return 100;
  const last = (a[3] ?? 0) - (b[3] ?? 0);
  return last > 0 ? last : 100;
}

function dhcpLimit(lan: DesiredState['lan']): number {
  const starts = lan.dhcpStart.split('.').map(Number);
  const ends = lan.dhcpEnd.split('.').map(Number);
  const diff = (ends[3] ?? 0) - (starts[3] ?? 0);
  return diff > 0 ? diff : 100;
}
