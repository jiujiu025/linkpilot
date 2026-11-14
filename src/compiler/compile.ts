/**
 * 编译器入口
 *
 * 输入：DesiredState（业务模型）+ 已解封的线路凭证
 * 输出：一组可审计的本地产物 + 校验结论 + 人可读的执行计划
 *
 * 契约：
 * - 纯函数，无 IO，无网络，无时间依赖（时间通过 now 注入）——
 *   同一输入必须得到同一 digest，否则回滚和幂等全部失效。
 * - 存在 error 级违规时抛错，不产出任何产物。
 */
import { digestOf } from '../core/canonical.ts';
import { AppError } from '../core/errors.ts';
import type { DesiredState, LineCredential } from '../core/schema.ts';
import { buildNftables } from './nftables.ts';
import { buildOpenwrt, type LeasePlan } from './openwrt.ts';
import { resolvePlan, type CompilePlan } from './plan.ts';
import { buildSingboxConfig } from './singbox.ts';
import { hasBlockingViolation, validateArtifacts, type Violation } from './validate.ts';

export const COMPILER_VERSION = '0.1.0';
export const GENERATOR = 'linkpilot-compiler';

export type Json = Record<string, unknown>;

export type CompiledArtifacts = {
  singbox: Json;
  nftables: string;
  uci: string;
  leases: LeasePlan[];
  manifest: Json;
};

export type CompileResult = {
  revision: number;
  digest: string;
  artifacts: CompiledArtifacts;
  plan: CompilePlan;
  violations: Violation[];
  warnings: string[];
  stats: {
    clients: number;
    pending: number;
    lines: number;
    routeRules: number;
    dnsRules: number;
    singboxBytes: number;
    nftablesBytes: number;
  };
};

export type CompileInput = {
  state: DesiredState;
  credentials: Record<string, LineCredential>;
  /** 云端控制通道地址，必须直连，否则代理故障时无法远程运维 */
  controlEndpoints?: string[];
  /** 手动锁线：clientId → lineId（`__default__` 表示全局） */
  pins?: Record<string, string>;
  now?: number;
};

export function compileDesiredState(input: CompileInput): CompileResult {
  const plan = resolvePlan({
    state: input.state,
    credentials: input.credentials,
    controlEndpoints: input.controlEndpoints ?? [],
    pins: input.pins,
    now: input.now ?? Date.now(),
  });

  const singbox = buildSingboxConfig({ plan, state: input.state, credentials: input.credentials });
  const nftables = buildNftables({ plan, state: input.state, now: input.now ?? Date.now() });
  const { uci, leases } = buildOpenwrt({ plan, state: input.state });

  const digest = digestOf({ singbox, nftables, uci, leases });

  const manifest: Json = {
    generator: GENERATOR,
    compilerVersion: COMPILER_VERSION,
    deviceId: input.state.deviceId,
    organizationId: input.state.organizationId,
    revision: input.state.revision,
    generatedAt: new Date(input.now ?? Date.now()).toISOString(),
    digest,
    counts: {
      clients: plan.clients.length,
      pending: plan.pendingClientIps.length,
      lines: plan.usedLines.length,
    },
    // 产物中只出现协议与线路 ID，不出现选择器以外的任何凭证片段
    lines: plan.usedLines.map((line) => ({
      id: line.id,
      name: line.name,
      region: line.region,
      kind: line.kind,
      server: line.server,
      port: line.port,
    })),
    plans: plan.clients.map((client) => ({
      clientId: client.clientId,
      label: client.label,
      ip: client.ipAddress,
      profile: client.profileName,
      mode: client.mode,
      primary: client.primary.lineId,
      standby: client.standby?.lineId ?? null,
      rules: client.rules.length,
    })),
  };

  const violations = validateArtifacts({
    plan,
    state: input.state,
    singbox,
    nftables,
    uci,
    manifest,
    credentials: input.credentials,
  });

  if (hasBlockingViolation(violations)) {
    const blocking = violations.filter((v) => v.severity === 'error');
    throw new AppError('COMPILE_FAILED', `配置未通过不变量校验（${blocking.length} 项）`, {
      violations: blocking,
    });
  }

  const route = singbox.route as Json;
  const dns = singbox.dns as Json;

  return {
    revision: input.state.revision,
    digest,
    artifacts: { singbox, nftables, uci, leases, manifest },
    plan,
    violations,
    warnings: [...plan.warnings, ...violations.filter((v) => v.severity === 'warn').map((v) => v.message)],
    stats: {
      clients: plan.clients.length,
      pending: plan.pendingClientIps.length,
      lines: plan.usedLines.length,
      routeRules: Array.isArray(route.rules) ? route.rules.length : 0,
      dnsRules: Array.isArray(dns.rules) ? dns.rules.length : 0,
      singboxBytes: JSON.stringify(singbox, null, 2).length,
      nftablesBytes: nftables.length,
    },
  };
}

export * from './plan.ts';
export * from './validate.ts';
export * from './singbox.ts';
export * from './nftables.ts';
export * from './openwrt.ts';
export * from './ip.ts';
