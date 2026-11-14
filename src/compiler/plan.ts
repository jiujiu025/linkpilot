/**
 * 解析层：把业务模型压成「确定的、无分支的」本地执行计划
 *
 * 这一层之后的所有产物（sing-box JSON / nftables 规则 / UCI 片段）都是纯函数输出，
 * 不再包含任何「可能」「也许」「视情况」——编译期必须把所有不确定性消解掉。
 * 无法消解的（缺线路、缺 profile、绑定冲突）一律抛错，而不是生成半残配置。
 */
import { AppError } from '../core/errors.ts';
import type {
  Client,
  DesiredState,
  DeviceRouteBinding,
  Line,
  LineCredential,
  RouteProfile,
  RoutingRule,
} from '../core/schema.ts';

export const DIRECT_TAG = 'direct';
export const BLOCK_TAG = 'block';
export const TUN_INBOUND_TAG = 'tun-in';

/**
 * 会话模式：每条线路一个 tproxy 入站的端口基数。
 *
 * 用「一线路一入站」而不是「一设备一规则」，是为了让登录只改防火墙集合，
 * 不用重编译、更不用重启 sing-box——否则一个人登录，全网一起断。
 */
export const SESSION_PORT_BASE = 10000;
/** tproxy 命中的流量打这个 mark，供策略路由使用 */
export const TPROXY_MARK = 1;

export type LinePort = { lineId: string; port: number };

export type OutboundTarget = {
  lineId: string;
  tag: string;
  name: string;
  region: string;
  server: string;
  port: number;
  credentialId: string;
};

export type PlannedRule = {
  ruleId: string;
  priority: number;
  /** route = 走某个出口；reject = 强制阻断 */
  decision: 'route' | 'reject';
  outboundTag: string;
  reason: 'admin_rule' | 'cn_direct' | 'default_route' | 'admin_block';
  domainSuffix: string[];
  domainKeyword: string[];
  ipCidr: string[];
  port: number[];
  network: ('tcp' | 'udp')[];
  ruleSet: string[];
};

export type ClientPlan = {
  clientId: string;
  label: string;
  ipAddress: string;
  bindingId: string;
  profileId: string;
  profileName: string;
  mode: RouteProfile['mode'];
  primary: OutboundTarget;
  standby: OutboundTarget | null;
  dnsServerTag: string;
  rules: PlannedRule[];
};

export type CompilePlan = {
  clients: ClientPlan[];
  pendingClientIps: string[];
  authorizedClientIps: string[];
  usedLines: Line[];
  /** 是否为「账号会话」模式：数据面按 tproxy 入站区分线路 */
  sessionMode: boolean;
  /** 会话模式下每条线路对应的入站端口（编译期固定，运行期不变） */
  linePorts: LinePort[];
  /**
   * 设备自身（Agent / NTP）必须直连的目标，避免控制通道被代理链路一起带走：
   * 代理挂了还能被远程运维，是产品可运营性的底线。
   */
  controlEndpoints: string[];
  warnings: string[];
};

export type PlanInput = {
  state: DesiredState;
  credentials: Record<string, LineCredential>;
  controlEndpoints?: string[];
  /**
   * 手动锁线：clientId → lineId，键 `__default__` 表示对全部设备生效。
   * 必须按设备生效——把线路在线路组里提前会连带影响同组其他设备，
   * 在直播场景里等于「救一台、断一片」。
   */
  pins?: Record<string, string>;
  now?: number;
};

export function outboundTagForLine(lineId: string): string {
  return `line:${lineId}`;
}

function bindingsByClient(state: DesiredState): Map<string, DeviceRouteBinding[]> {
  const map = new Map<string, DeviceRouteBinding[]>();
  for (const binding of state.bindings) {
    const list = map.get(binding.clientId) ?? [];
    list.push(binding);
    map.set(binding.clientId, list);
  }
  return map;
}

function isBindingActive(binding: DeviceRouteBinding, now: number): boolean {
  if (binding.revokedAt) return false;
  const from = Date.parse(binding.validFrom);
  if (Number.isFinite(from) && from > now) return false;
  if (binding.validUntil) {
    const until = Date.parse(binding.validUntil);
    if (Number.isFinite(until) && until <= now) return false;
  }
  return true;
}

function pickLines(
  state: DesiredState,
  lineGroupId: string,
  usedCredentialIds: Set<string>,
  pinnedLineId?: string,
): { primary: Line | null; standby: Line | null; groupMissing: boolean; pinnedApplied: boolean } {
  const group = state.lineGroups.find((g) => g.id === lineGroupId);
  if (!group) return { primary: null, standby: null, groupMissing: true, pinnedApplied: false };
  const lines: Line[] = [];
  for (const lineId of group.lineIds) {
    const line = state.lines.find((l) => l.id === lineId);
    if (line && line.enabled) lines.push(line);
  }
  for (const line of lines) usedCredentialIds.add(line.credentialId);

  let primary = lines[0] ?? null;
  let pinnedApplied = false;
  if (pinnedLineId) {
    const pinned = lines.find((line) => line.id === pinnedLineId);
    if (pinned) {
      primary = pinned;
      pinnedApplied = true;
    }
  }
  const standby = lines.find((line) => line.id !== primary?.id) ?? null;
  return { primary, standby, groupMissing: false, pinnedApplied };
}

function resolveTarget(line: Line, credentials: Record<string, LineCredential>): OutboundTarget {
  const credential = credentials[line.credentialId];
  if (!credential) {
    throw new AppError('CAPABILITY_UNSUPPORTED', `线路 ${line.name} 缺少可用凭证`, {
      lineId: line.id,
    });
  }
  if (credential.kind !== line.kind) {
    throw new AppError('CAPABILITY_UNSUPPORTED', `线路 ${line.name} 协议与凭证不一致`, {
      lineId: line.id,
      lineKind: line.kind,
      credentialKind: credential.kind,
    });
  }
  return {
    lineId: line.id,
    tag: outboundTagForLine(line.id),
    name: line.name,
    region: line.region,
    server: line.server,
    port: line.port,
    credentialId: line.credentialId,
  };
}

function toPlannedRule(
  rule: RoutingRule,
  resolved: OutboundTarget,
  fallback: OutboundTarget,
): PlannedRule {
  const match = rule.match;
  if (rule.action === 'block') {
    return {
      ruleId: rule.id,
      priority: rule.priority,
      decision: 'reject',
      outboundTag: 'reject',
      reason: 'admin_block',
      domainSuffix: [...match.domainSuffix],
      domainKeyword: [...match.domainKeyword],
      ipCidr: [...match.ipCidr],
      port: [...match.port],
      network: [...match.network],
      ruleSet: [],
    };
  }
  if (rule.action === 'direct') {
    return {
      ruleId: rule.id,
      priority: rule.priority,
      decision: 'route',
      outboundTag: DIRECT_TAG,
      reason: 'admin_rule',
      domainSuffix: [...match.domainSuffix],
      domainKeyword: [...match.domainKeyword],
      ipCidr: [...match.ipCidr],
      port: [...match.port],
      network: [...match.network],
      ruleSet: [],
    };
  }
  return {
    ruleId: rule.id,
    priority: rule.priority,
    decision: 'route',
    outboundTag: rule.lineGroupId ? resolved.tag : fallback.tag,
    reason: 'admin_rule',
    domainSuffix: [...match.domainSuffix],
    domainKeyword: [...match.domainKeyword],
    ipCidr: [...match.ipCidr],
    port: [...match.port],
    network: [...match.network],
    ruleSet: [],
  };
}

export function resolvePlan(input: PlanInput): CompilePlan {
  const now = input.now ?? Date.now();
  const { state, credentials } = input;
  const warnings: string[] = [];
  const usedCredentialIds = new Set<string>();
  const usedLines = new Map<string, Line>();
  const bindingsMap = bindingsByClient(state);
  const clients: ClientPlan[] = [];
  const pendingClientIps: string[] = [];
  const authorizedClientIps: string[] = [];

  const openwrtConflicts = new Set<string>();

  for (const client of state.clients) {
    // 待授权与已撤销都归入「不可出网」集合：撤销不能只是不显示，必须真的断网
    if (client.state === 'pending' || client.state === 'revoked') {
      pendingClientIps.push(client.ipAddress);
      continue;
    }
    if (client.state !== 'authorized') continue;

    const active = (bindingsMap.get(client.id) ?? []).filter((b) => isBindingActive(b, now));
    if (active.length === 0) {
      warnings.push(`设备「${client.label}」标记为已授权但没有生效绑定，已按阻断处理`);
      pendingClientIps.push(client.ipAddress);
      continue;
    }
    if (active.length > 1) {
      throw new AppError('COMPILE_FAILED', `设备「${client.label}」存在多条同时生效的绑定`, {
        clientId: client.id,
        bindings: active.map((b) => b.id),
      });
    }
    const binding = active[0]!;
    if (openwrtConflicts.has(client.ipAddress)) {
      throw new AppError('COMPILE_FAILED', `局域网地址 ${client.ipAddress} 被多台设备占用`, {
        ip: client.ipAddress,
      });
    }
    openwrtConflicts.add(client.ipAddress);
    authorizedClientIps.push(client.ipAddress);

    const profile = state.routeProfiles.find((p) => p.id === binding.routeProfileId);
    if (!profile) {
      throw new AppError('COMPILE_FAILED', `设备「${client.label}」绑定的线路策略已被删除`, {
        profileId: binding.routeProfileId,
      });
    }

    const pin = input.pins?.[client.id] ?? input.pins?.['__default__'];
    const picked = pickLines(state, profile.primaryLineGroupId, usedCredentialIds, pin);
    if (pin && !picked.pinnedApplied) {
      warnings.push(`设备「${client.label}」的手动锁线 ${pin} 不在当前线路组内，已忽略并回落到默认主线路`);
    }
    if (picked.groupMissing) {
      throw new AppError('COMPILE_FAILED', `策略「${profile.name}」引用的线路组不存在`, {
        lineGroupId: profile.primaryLineGroupId,
      });
    }
    if (!picked.primary) {
      throw new AppError('CAPABILITY_UNSUPPORTED', `策略「${profile.name}」没有可用线路`, {
        profileId: profile.id,
      });
    }

    const primary = resolveTarget(picked.primary, credentials);
    const standby = picked.standby ? resolveTarget(picked.standby, credentials) : null;
    usedLines.set(primary.lineId, picked.primary);
    if (picked.standby && standby) usedLines.set(standby.lineId, picked.standby);

    if (picked.pinnedApplied && pin) {
      warnings.push(`设备「${client.label}」处于手动锁线状态（${pin}），自动切换已暂停`);
    }

    if (profile.mode === 'strict_global' && profile.rules.some((r) => r.action === 'direct')) {
      warnings.push(`策略「${profile.name}」为严格全局代理，但包含直连规则，请确认这是有意为之`);
    }

    const rules: PlannedRule[] = [];
    const applicable = profile.rules
      .filter((rule) => rule.enabled)
      .filter((rule) => rule.match.clientIds.length === 0 || rule.match.clientIds.includes(client.id))
      .sort((a, b) => (a.priority === b.priority ? (a.id < b.id ? -1 : 1) : a.priority - b.priority));

    for (const rule of applicable) {
      let target = primary;
      if (rule.action === 'proxy' && rule.lineGroupId) {
        const groupPick = pickLines(state, rule.lineGroupId, usedCredentialIds);
        if (!groupPick.primary) {
          throw new AppError('CAPABILITY_UNSUPPORTED', `规则 ${rule.id} 指向的线路组没有可用线路`, {
            ruleId: rule.id,
          });
        }
        target = resolveTarget(groupPick.primary, credentials);
        usedLines.set(target.lineId, groupPick.primary);
        if (groupPick.standby) {
          // 备用线路也要出现在 outbounds 里，否则热备切换时无法零改配置
          resolveTarget(groupPick.standby, credentials);
          usedLines.set(groupPick.standby.id, groupPick.standby);
        }
      }
      rules.push(toPlannedRule(rule, target, primary));
    }

    // 大陆直连：只信任本地规则集，不依赖云端实时查询
    if (profile.mode === 'cn_direct') {
      rules.push({
        ruleId: `builtin:cn-direct:${client.id}`,
        priority: 90000,
        decision: 'route',
        outboundTag: DIRECT_TAG,
        reason: 'cn_direct',
        domainSuffix: ['.cn'],
        domainKeyword: [],
        ipCidr: [],
        port: [],
        network: [],
        ruleSet: ['geoip-cn', 'geosite-cn'],
      });
    }

    if (profile.mode === 'direct_only') {
      warnings.push(`策略「${profile.name}」为全直连诊断模式，设备「${client.label}」不受代理保护`);
    }

    rules.push({
      ruleId: `default:${client.id}`,
      priority: 100000,
      decision: 'route',
      outboundTag: profile.mode === 'direct_only' ? DIRECT_TAG : primary.tag,
      reason: 'default_route',
      domainSuffix: [],
      domainKeyword: [],
      ipCidr: [],
      port: [],
      network: [],
      ruleSet: [],
    });

    clients.push({
      clientId: client.id,
      label: client.label,
      ipAddress: client.ipAddress,
      bindingId: binding.id,
      profileId: profile.id,
      profileName: profile.name,
      mode: profile.mode,
      primary,
      standby,
      dnsServerTag: `dns:${primary.lineId}`,
      rules,
    });
  }

  if (clients.length === 0) {
    warnings.push('当前没有任何已授权设备，编译结果只包含门户与隔离规则');
  }

  /* 会话模式：给「有账号在用」的线路分配固定入站端口 */
  const sessionMode = state.accessControl.mode === 'session';
  const linePorts: LinePort[] = [];
  if (sessionMode) {
    // 预授权设备也要有入站端口：它们不登录，但同样要落到某条线路上
    const lineIds = [
      ...new Set([
        ...state.accessAccounts.filter((a) => a.enabled).map((a) => a.lineId),
        ...state.trustedDevices.map((d) => d.lineId),
      ]),
    ].sort();
    for (const lineId of lineIds) {
      const line = state.lines.find((l) => l.id === lineId);
      if (!line) {
        // 账号指向的线路被删了：宁可编译失败，也不要生成「登录后无处可去」的配置
        throw new AppError('COMPILE_FAILED', `接入账号引用的线路不存在：${lineId}`, { lineId });
      }
      if (!credentials[line.credentialId]) {
        throw new AppError('CAPABILITY_UNSUPPORTED', `线路 ${line.name} 缺少可用凭证`, { lineId });
      }
      usedLines.set(line.id, line);
      linePorts.push({ lineId: line.id, port: SESSION_PORT_BASE + linePorts.length });
    }
    if (linePorts.length === 0) {
      warnings.push('会话模式已开启，但没有任何可用接入账号，所有终端都会停在门户页');
    }
    for (const device of state.trustedDevices) {
      if (!linePorts.some((p) => p.lineId === device.lineId)) {
        warnings.push(`预授权设备「${device.label || device.id}」的线路不参与本次编译，已忽略`);
      }
    }
  }

  return {
    clients,
    pendingClientIps,
    authorizedClientIps,
    usedLines: [...usedLines.values()],
    controlEndpoints: input.controlEndpoints ?? [],
    sessionMode,
    linePorts,
    warnings,
  };
}

export function activeClientLabel(client: Client): string {
  return client.label || client.hostname || client.id;
}
