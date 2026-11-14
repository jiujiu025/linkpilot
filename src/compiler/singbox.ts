/**
 * sing-box 配置生成器
 *
 * 只做一件事：把 CompilePlan 翻译成 sing-box 1.11 风格的配置对象。
 * 所有分支判断都在 plan 层完成，这里不再做业务决策。
 *
 * 关键取舍：
 * - 分流按「源地址」而不是账号：数据包路径上不可能查账号库（docs/design/01 冲突 B），
 *   所以每台已授权设备必须有稳定的 DHCP 静态租约地址。
 * - route.final = block：未知流量宁可断，不可直连出去。
 * - DNS 走 hijack-dns，按 source_ip_cidr 分到各自线路的解析器。
 */
import type { DesiredState, LineCredential } from '../core/schema.ts';
import { BLOCK_TAG, DIRECT_TAG, TUN_INBOUND_TAG, type CompilePlan, type PlannedRule } from './plan.ts';
import { tunPeerAddress } from './ip.ts';

type Json = Record<string, unknown>;

function tlsConfig(tls: NonNullable<Extract<LineCredential, { kind: 'vless' }>['tls']>): Json {
  const out: Json = { enabled: true, server_name: tls.serverName };
  if (tls.alpn.length > 0) out.alpn = tls.alpn;
  if (tls.allowInsecure) out.insecure = true;
  if (tls.fingerprint) out.utls = { enabled: true, fingerprint: tls.fingerprint };
  if (tls.reality) {
    out.reality = { enabled: true, public_key: tls.reality.publicKey, short_id: tls.reality.shortId };
  }
  return out;
}

function transportConfig(
  transport: Extract<LineCredential, { kind: 'vless' }>['transport'],
): Json | null {
  switch (transport.type) {
    case 'tcp':
      return null;
    case 'ws':
      return {
        type: 'ws',
        path: transport.path ?? '/',
        headers: transport.host ? { Host: transport.host } : {},
      };
    case 'httpupgrade':
      return {
        type: 'httpupgrade',
        path: transport.path ?? '/',
        headers: transport.host ? { Host: transport.host } : {},
      };
    case 'grpc':
      return { type: 'grpc', service_name: transport.serviceName ?? '' };
    default:
      return null;
  }
}

export function buildOutbound(
  tag: string,
  server: string,
  port: number,
  credential: LineCredential,
): Json {
  const base: Json = { tag, server, server_port: port };
  switch (credential.kind) {
    case 'vless': {
      const out: Json = { type: 'vless', ...base, uuid: credential.uuid };
      if (credential.flow) out.flow = credential.flow;
      if (credential.tls) out.tls = tlsConfig(credential.tls);
      const transport = transportConfig(credential.transport);
      if (transport) out.transport = transport;
      return out;
    }
    case 'vmess': {
      const out: Json = {
        type: 'vmess',
        ...base,
        uuid: credential.uuid,
        alter_id: credential.alterId,
        security: credential.security,
      };
      if (credential.tls) out.tls = tlsConfig(credential.tls);
      const transport = transportConfig(credential.transport as never);
      if (transport) out.transport = transport;
      return out;
    }
    case 'hysteria2': {
      const out: Json = { type: 'hysteria2', ...base, password: credential.password };
      if (credential.tls) {
        out.tls = {
          enabled: true,
          server_name: credential.tls.serverName,
          ...(credential.tls.allowInsecure ? { insecure: true } : {}),
          ...(credential.tls.alpn.length > 0 ? { alpn: credential.tls.alpn } : {}),
        };
      }
      if (credential.obfs) out.obfs = { type: credential.obfs.type, password: credential.obfs.password };
      return out;
    }
    case 'trojan': {
      const out: Json = { type: 'trojan', ...base, password: credential.password };
      out.tls = tlsConfig(credential.tls);
      const transport = transportConfig(credential.transport);
      if (transport) out.transport = transport;
      return out;
    }
    case 'shadowsocks':
      return { type: 'shadowsocks', ...base, method: credential.method, password: credential.password };
    case 'wireguard': {
      const out: Json = {
        type: 'wireguard',
        tag,
        server,
        server_port: port,
        local_address: [credential.localAddress],
        private_key: credential.privateKey,
        peer_public_key: credential.peerPublicKey,
        mtu: credential.mtu,
      };
      if (credential.presharedKey) out.pre_shared_key = credential.presharedKey;
      return out;
    }
    case 'socks5': {
      const out: Json = { type: 'socks', ...base, version: '5' };
      if (credential.username) out.username = credential.username;
      if (credential.password) out.password = credential.password;
      return out;
    }
    case 'http': {
      const out: Json = { type: 'http', ...base };
      if (credential.username) out.username = credential.username;
      if (credential.password) out.password = credential.password;
      return out;
    }
    default:
      throw new Error('不支持的协议类型');
  }
}

function ruleToJson(rule: PlannedRule, clientIp: string): Json {
  const out: Json = {
    source_ip_cidr: [`${clientIp}/32`],
    action: rule.decision === 'reject' ? 'reject' : 'route',
  };
  if (rule.decision === 'route') out.outbound = rule.outboundTag;
  if (rule.domainSuffix.length > 0) out.domain_suffix = rule.domainSuffix;
  if (rule.domainKeyword.length > 0) out.domain_keyword = rule.domainKeyword;
  if (rule.ipCidr.length > 0) out.ip_cidr = rule.ipCidr;
  if (rule.port.length > 0) out.port = rule.port;
  if (rule.network.length > 0) out.network = rule.network;
  if (rule.ruleSet.length > 0) out.rule_set = rule.ruleSet;
  return out;
}

export type SingboxBuildInput = {
  plan: CompilePlan;
  state: DesiredState;
  credentials: Record<string, LineCredential>;
};

export function buildSingboxConfig({ plan, state, credentials }: SingboxBuildInput): Json {
  const lan = state.lan;

  const outbounds: Json[] = [];
  const dnsServers: Json[] = [{ tag: 'dns:direct', address: '223.5.5.5', detour: DIRECT_TAG }];

  for (const line of plan.usedLines) {
    const credential = credentials[line.credentialId];
    if (!credential) continue;
    outbounds.push(buildOutbound(`line:${line.id}`, line.server, line.port, credential));
    dnsServers.push({
      tag: `dns:${line.id}`,
      // 代理解析走 HTTPS，避免明文 DNS 到出口后再次泄露
      address: 'https://1.1.1.1/dns-query',
      detour: `line:${line.id}`,
    });
  }
  dnsServers.push({ tag: 'dns:block', address: 'rcode://refused' });
  outbounds.push({ type: 'direct', tag: DIRECT_TAG });
  // route.final 为空时会退化成「第一个出站」，等于把兜底变成主线路直出；
  // 因此显式保留 block 出站并用它做 final，语义才不会随出站顺序漂移。
  outbounds.push({ type: 'block', tag: BLOCK_TAG });

  const referencedRuleSets = new Set<string>();
  for (const client of plan.clients) {
    for (const rule of client.rules) {
      for (const set of rule.ruleSet) referencedRuleSets.add(set);
    }
  }

  const ruleSet: Json[] = [];
  if (referencedRuleSets.has('geoip-cn')) {
    ruleSet.push({
      tag: 'geoip-cn',
      type: 'remote',
      format: 'binary',
      url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
      download_detour: DIRECT_TAG,
      update_interval: '168h',
    });
  }
  if (referencedRuleSets.has('geosite-cn')) {
    ruleSet.push({
      tag: 'geosite-cn',
      type: 'remote',
      format: 'binary',
      url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
      download_detour: DIRECT_TAG,
      update_interval: '168h',
    });
  }

  const dnsRules: Json[] = [
    { domain_suffix: ['.lan', '.local', '.arpa'], server: 'dns:direct' },
    { process_name: ['linkpilot-agent'], server: 'dns:direct' },
  ];
  for (const client of plan.clients) {
    if (client.mode === 'cn_direct') {
      dnsRules.push({
        source_ip_cidr: [`${client.ipAddress}/32`],
        domain_suffix: ['.cn'],
        rule_set: ['geosite-cn'],
        server: 'dns:direct',
      });
    }
    // 每台设备都必须有一条兜底 DNS 规则，避免落到 final 上
    dnsRules.push({
      source_ip_cidr: [`${client.ipAddress}/32`],
      server: client.mode === 'direct_only' ? 'dns:direct' : client.dnsServerTag,
    });
  }

  const routeRules: Json[] = [{ action: 'sniff' }, { action: 'hijack-dns', protocol: 'dns' }];

  if (plan.sessionMode) {
    /*
     * 会话模式：每条线路一个 tproxy 入站，路由按「入站」而不是「源地址 × 规则」决定。
     * 这样配置体量是 O(线路)，登录换线只改防火墙集合，不需要重载本配置。
     */
    for (const linePort of plan.linePorts) {
      const tag = `in:${linePort.lineId}`;
      dnsRules.push({ inbound: [tag], server: `dns:${linePort.lineId}` });
      dnsRules.push({
        inbound: [tag],
        domain_suffix: ['.lan', '.local', '.arpa'],
        server: 'dns:direct',
      });
    }
  }

  // 控制通道必须直连：代理挂了还要能被远程运维
  for (const endpoint of plan.controlEndpoints) {
    routeRules.push({ action: 'route', outbound: DIRECT_TAG, ip_cidr: [`${endpoint}/32`] });
  }
  routeRules.push({ action: 'route', outbound: DIRECT_TAG, process_name: ['linkpilot-agent'] });
  routeRules.push({ action: 'route', outbound: DIRECT_TAG, port: [123], network: ['udp'] });

  for (const client of plan.clients) {
    const sorted = [...client.rules].sort((a, b) =>
      a.priority === b.priority ? (a.ruleId < b.ruleId ? -1 : 1) : a.priority - b.priority,
    );
    for (const rule of sorted) routeRules.push(ruleToJson(rule, client.ipAddress));
  }

  // 会话模式：入站即线路，优先级低于显式的控制通道直连规则
  for (const linePort of plan.linePorts) {
    routeRules.push({ inbound: [`in:${linePort.lineId}`], outbound: `line:${linePort.lineId}` });
  }

  // 兜底拒绝：即使 final 因为版本差异失效，也不会出现「未匹配即直连」
  routeRules.push({ action: 'reject' });

  const config: Json = {
    log: { level: 'warn', timestamp: true },
    dns: {
      servers: dnsServers,
      rules: dnsRules,
      // 兜底拒绝：未登记的解析请求宁可失败，不可漏到 WAN
      final: 'dns:block',
      strategy: 'ipv4_only',
      independent_cache: true,
    },
    inbounds: plan.sessionMode
      ? plan.linePorts.map((linePort) => ({
          type: 'tproxy',
          tag: `in:${linePort.lineId}`,
          listen: '0.0.0.0',
          listen_port: linePort.port,
          udp_timeout: '5m',
        }))
      : [
          {
            type: 'tun',
            tag: TUN_INBOUND_TAG,
            interface_name: lan.tunName,
            address: [lan.tunCidr],
            mtu: 1500,
            auto_route: true,
            strict_route: true,
            stack: 'system',
            endpoint_independent_nat: false,
          },
        ],
    outbounds,
    route: {
      rules: routeRules,
      ...(ruleSet.length > 0 ? { rule_set: ruleSet } : {}),
      final: BLOCK_TAG,
      auto_detect_interface: true,
    },
  };

  return config;
}

/** DNS 劫持目标：tun 对端地址，供 nftables DNAT 使用 */
export function dnsHijackTarget(state: DesiredState): string | null {
  return tunPeerAddress(state.lan.tunCidr);
}
