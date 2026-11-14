/**
 * 编译产物不变量校验
 *
 * 这是「拒绝生成」的地方，不是「生成完再想办法」。
 * 任何一条 error 级不变量不成立，编译器就不产出配置——
 * 半残配置比没有配置更危险，因为它看起来在工作。
 *
 * 检查对象是最终产物（字符串 / JSON），不是中间计划，
 * 这样生成器本身的 bug 也会被同一批断言抓住。
 */
import type { DesiredState, LineCredential } from '../core/schema.ts';
import { isIpv4 } from './ip.ts';
import type { CompilePlan } from './plan.ts';
import { dnsHijackTarget } from './singbox.ts';

export type Violation = {
  code: string;
  severity: 'error' | 'warn';
  message: string;
  where: string;
};

export type ValidationInput = {
  plan: CompilePlan;
  state: DesiredState;
  singbox: Record<string, unknown>;
  nftables: string;
  uci: string;
  manifest: Record<string, unknown>;
  credentials: Record<string, LineCredential>;
};

type Json = Record<string, unknown>;

function asArray(value: unknown): Json[] {
  return Array.isArray(value) ? (value as Json[]) : [];
}

/**
 * 按大括号配对提取一条 nft 链的正文。
 * 不能用 `chain forward \{[\s\S]*?policy drop;` 这种偷懒正则——
 * 它会越过链尾匹配到下一个链的 policy，把「转发链已经放开」误判成通过。
 */
function extractChain(text: string, name: string): string | null {
  const start = text.indexOf(`chain ${name} {`);
  if (start < 0) return null;
  let depth = 0;
  for (let i = text.indexOf('{', start); i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

export function validateArtifacts(input: ValidationInput): Violation[] {
  const { plan, state, singbox, nftables, uci, credentials } = input;
  const violations: Violation[] = [];
  const err = (code: string, message: string, where: string): void => {
    violations.push({ code, severity: 'error', message, where });
  };
  const warn = (code: string, message: string, where: string): void => {
    violations.push({ code, severity: 'warn', message, where });
  };

  /* ---------------------------------------------------- sing-box 结构断言 */

  const inbounds = asArray(singbox.inbounds);
  const tun = inbounds.find((i) => i.type === 'tun');
  if (plan.sessionMode) {
    /*
     * 会话模式走 tproxy：不再有 tun。此时必须逐个核对「线路有入站、入站有路由」，
     * 因为少一条就会变成「登录成功但该线路的流量无处可去」。
     */
    for (const linePort of plan.linePorts) {
      const inbound = inbounds.find((i) => i.tag === `in:${linePort.lineId}`);
      if (!inbound) {
        err('TPROXY_INBOUND_MISSING', `线路 ${linePort.lineId} 缺少 tproxy 入站`, 'singbox.inbounds');
      } else if (inbound.listen_port !== linePort.port) {
        err('TPROXY_PORT_MISMATCH', `线路 ${linePort.lineId} 入站端口与防火墙不一致`, 'singbox.inbounds');
      }
      if (!asArray((singbox.route as Json | undefined)?.rules).some(
        (rule) => Array.isArray(rule.inbound) && (rule.inbound as string[]).includes(`in:${linePort.lineId}`),
      )) {
        err('TPROXY_ROUTE_MISSING', `线路 ${linePort.lineId} 没有按入站的路由规则`, 'singbox.route.rules');
      }
    }
    if (inbounds.length !== plan.linePorts.length) {
      err('TPROXY_INBOUND_EXTRA', '存在与线路不对应的入站，可能把流量引到不存在的出口', 'singbox.inbounds');
    }
  } else if (!tun) {
    err('TUN_MISSING', '缺少 tun 入站，客户流量不会进入代理链路', 'singbox.inbounds');
  } else {
    if (tun.auto_route !== true) err('TUN_NO_AUTOROUTE', 'tun 未开启 auto_route', 'singbox.inbounds[0]');
    if (tun.strict_route !== true) {
      err('TUN_NO_STRICTROUTE', 'tun 未开启 strict_route，存在绕过路由规则直连的风险', 'singbox.inbounds[0]');
    }
    if (tun.interface_name !== state.lan.tunName) {
      err('TUN_NAME_MISMATCH', 'tun 接口名与 nftables 规则不一致，Kill Switch 会失效', 'singbox.inbounds[0]');
    }
  }

  const route = (singbox.route ?? {}) as Json;
  if (route.final !== 'block') {
    err('ROUTE_FINAL_OPEN', 'route.final 必须为 block，否则未匹配流量会直连出网', 'singbox.route.final');
  }

  const routeRules = asArray(route.rules);
  const outboundTags = new Set(asArray(singbox.outbounds).map((o) => String(o.tag)));
  if (!outboundTags.has('block')) {
    err('BLOCK_OUTBOUND_MISSING', '缺少 block 出站，route.final 无法安全兜底', 'singbox.outbounds');
  }
  const lastRule = routeRules[routeRules.length - 1];
  const hasCatchAllReject =
    lastRule !== undefined &&
    lastRule.action === 'reject' &&
    Object.keys(lastRule).every((key) => key === 'action');
  if (!hasCatchAllReject) {
    err(
      'NO_CATCHALL_REJECT',
      '缺少无条件拒绝的兜底规则；一旦 final 语义或出站顺序变化就会静默直连',
      'singbox.route.rules',
    );
  }
  for (const rule of routeRules) {
    if (rule.action === 'route' && typeof rule.outbound === 'string' && !outboundTags.has(rule.outbound)) {
      err('DANGLING_OUTBOUND', `路由规则引用不存在的出口 ${rule.outbound}`, 'singbox.route.rules');
    }
    if (rule.action === 'reject' && rule.outbound !== undefined) {
      err('REJECT_WITH_OUTBOUND', 'reject 规则不应携带出口', 'singbox.route.rules');
    }
  }

  /* ------------------------------------------------------ 每设备完整性 */

  if (new Set(plan.authorizedClientIps).size !== plan.authorizedClientIps.length) {
    err('DUPLICATE_CLIENT_IP', '存在两台已授权设备共用同一局域网地址', 'plan');
  }

  for (const client of plan.clients) {
    const scoped = routeRules.filter((rule) =>
      Array.isArray(rule.source_ip_cidr) &&
      (rule.source_ip_cidr as string[]).includes(`${client.ipAddress}/32`),
    );
    if (scoped.length === 0) {
      err('CLIENT_UNROUTED', `设备「${client.label}」没有任何路由规则，实测表现会是「已授权但没网」`, 'singbox.route.rules');
    }
    const hasDefault = scoped.some((rule) => String(rule.outbound ?? '') !== '' && rule.action === 'route');
    if (!hasDefault) {
      err('CLIENT_NO_DEFAULT', `设备「${client.label}」缺少兜底路由，行为依赖 route.final`, 'singbox.route.rules');
    }
    const dns = (singbox.dns ?? {}) as Json;
    const dnsScoped = asArray(dns.rules).some((rule) =>
      Array.isArray(rule.source_ip_cidr) &&
      (rule.source_ip_cidr as string[]).includes(`${client.ipAddress}/32`),
    );
    if (!dnsScoped) {
      err('CLIENT_NO_DNS_RULE', `设备「${client.label}」缺少 DNS 规则，会落到兜底拒绝上`, 'singbox.dns.rules');
    }
  }

  /* -------------------------------------------------------- nftables 断言 */

  // 必须只看 inet 表这一段：ip6 表也有 forward 链，混在一起会把 IPv4 漏判成通过
  const inetBlock = nftables.split(/^table ip6 /m)[0] ?? '';
  const ip6Block = nftables.slice(inetBlock.length);
  const inetForward = extractChain(inetBlock, 'forward');
  const forwardPolicyDrop = inetForward !== null && inetForward.includes('policy drop;');
  if (!forwardPolicyDrop) {
    err('NFT_FORWARD_OPEN', 'nftables 转发链不是默认 drop，Kill Switch 形同虚设', 'nftables.forward');
  }
  if (plan.sessionMode) {
    if (!nftables.includes('tproxy ip to :')) {
      err('NFT_TPROXY_MISSING', '会话模式没有任何 tproxy 规则，已登录流量会直接落到 Kill Switch 上', 'nftables.tproxy_in');
    }
    if (!nftables.includes('@authed_v4')) {
      err('NFT_AUTHED_SET_MISSING', '缺少会话总集合引用，未登录与已登录无法区分', 'nftables');
    }
  } else if (!nftables.includes(state.lan.tunName)) {
    err('NFT_TUN_MISSING', 'nftables 未引用 tun 接口，代理流量也会被自己拦掉', 'nftables.forward');
  }
  const dnsTarget = dnsHijackTarget(state);
  if (!dnsTarget) {
    err('DNS_TARGET_INVALID', `tun 网段 ${state.lan.tunCidr} 无法推导 DNS 劫持目标`, 'nftables.dns_hijack');
  } else if (plan.sessionMode) {
    // 会话模式：已登录的 DNS 由 tproxy 交给对应线路，未登录的必须被引到门户解析器
    if (!nftables.includes(`dnat ip to ${state.lan.gateway}:53`)) {
      err('DNS_HIJACK_MISSING', '未登录设备的 DNS 未被接管，连登录弹窗都触发不了', 'nftables.dns_hijack');
    }
    if (!nftables.includes(`dnat ip to ${state.lan.gateway}:${state.lan.portalPort}`)) {
      err('CAPTIVE_REDIRECT_MISSING', '未登录设备访问 HTTP 不会跳到登录页', 'nftables.dns_hijack');
    }
  } else if (!nftables.includes(`dnat ip to ${dnsTarget}:53`)) {
    err('DNS_HIJACK_MISSING', '缺少 DNS 劫持规则，客户端可绕过受控解析', 'nftables.dns_hijack');
  }
  const ip6Forward = extractChain(ip6Block, 'forward');
  if (!/table ip6 linkpilot6/.test(ip6Block) || ip6Forward === null || !ip6Forward.includes('policy drop;')) {
    err('IPV6_TABLE_MISSING', '缺少 IPv6 阻断表，可能通过 IPv6 直连泄露', 'nftables.ip6');
  }
  if (!plan.sessionMode && !nftables.includes('saddr @pending_v4 counter return')) {
    warn(
      'DNS_HIJACK_PENDING',
      '未授权设备也会被 DNS 劫持，存在被用来做解析探测的可能',
      'nftables.dns_hijack',
    );
  }
  for (const ip of plan.authorizedClientIps) {
    if (isIpv4(ip) && !nftables.includes(ip)) {
      err('NFT_CLIENT_MISSING', `已授权设备 ${ip} 未出现在 nftables 集合中`, 'nftables.authorized_v4');
    }
  }
  for (const ip of plan.pendingClientIps) {
    if (plan.authorizedClientIps.includes(ip)) {
      err('CLIENT_STATE_CONFLICT', `设备 ${ip} 同时处于已授权和未授权集合`, 'plan');
    }
  }

  /* -------------------------------------------------- 硬件档位一致性 */

  if (!state.wifi.enabled && uci.includes('wireless.@wifi-iface')) {
    err(
      'WIFI_DISABLED_BUT_CONFIGURED',
      '设备声明无无线模块，但 UCI 片段仍在写 wireless 配置；在无 radio 的机器上会拖垮整批应用',
      'uci.wireless',
    );
  }
  if (state.wifi.enabled && !uci.includes('wireless.@wifi-iface')) {
    err('WIFI_ENABLED_BUT_MISSING', '设备声明启用无线，但 UCI 片段没有 wireless 配置', 'uci.wireless');
  }

  /* ---------------------------------------------------------- 容量检查 */

  if (state.accessControl.mode === 'session') {
    const start = Number(state.lan.dhcpStart.split('.')[3] ?? 0);
    const end = Number(state.lan.dhcpEnd.split('.')[3] ?? 0);
    const pool = end > start ? end - start + 1 : 0;
    // 一人一台设备：账号数不能超过地址池，否则会出现「连上了但拿不到地址」
    const accounts = state.accessAccounts.filter((a) => a.enabled && !a.revokedAt).length;
    if (pool > 0 && accounts > pool) {
      warn(
        'ACCOUNT_POOL_SHORT',
        `接入账号 ${accounts} 个，但 DHCP 池只有 ${pool} 个地址；到量后新设备会拿不到 IP`,
        'lan.dhcpStart/dhcpEnd',
      );
    }
  }

  /* ------------------------------------------------------ 凭证泄露扫描 */

  const secretValues = new Set<string>();
  for (const credential of Object.values(credentials)) {
    if ('password' in credential && typeof credential.password === 'string') secretValues.add(credential.password);
    if (credential.kind === 'vless') secretValues.add(credential.uuid);
    if (credential.kind === 'wireguard') secretValues.add(credential.privateKey);
  }
  const leakScopes: Array<[string, string]> = [
    ['nftables', nftables],
    ['uci', uci],
  ];
  for (const [where, text] of leakScopes) {
    for (const secret of secretValues) {
      if (secret.length >= 8 && text.includes(secret)) {
        err('SECRET_IN_ARTIFACT', '线路凭证出现在非代理配置产物中', where);
      }
    }
  }

  /* ------------------------------------------------------------ 运维告警 */

  if (plan.controlEndpoints.length === 0) {
    warn(
      'NO_CONTROL_ENDPOINT',
      '未配置控制通道例外地址；严格模式下 Agent 可能无法回连云端，远程运维会失效',
      'plan.controlEndpoints',
    );
  }
  for (const client of plan.clients) {
    if (client.mode === 'strict_global' && client.rules.some((r) => r.decision === 'route' && r.outboundTag === 'direct')) {
      warn('STRICT_WITH_DIRECT', `策略「${client.profileName}」严格全局代理下含直连规则`, 'plan');
    }
  }

  return violations;
}

export function hasBlockingViolation(violations: Violation[]): boolean {
  return violations.some((v) => v.severity === 'error');
}
