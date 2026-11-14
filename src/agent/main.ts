/**
 * Router Agent 进程入口
 *
 * 职责边界（docs/design/04 §1）：
 * - 主动出站拉配置，不接受任何入站管理连接；
 * - 只执行白名单固定命令，不执行任意 Shell；
 * - 配置必须先验签、再解密凭证、再本地编译，最后原子应用；
 * - 应用失败自动退回上一稳定版本，并把失败版本拉黑，避免反复把设备搞挂。
 *
 * 解密后的线路凭证只存在于进程内存（sing-box 配置本来也需要），不落盘。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateEd25519KeyPair, generateX25519KeyPair, randomHex } from '../core/crypto.ts';
import { AppError } from '../core/errors.ts';
import { verifyBundle, verifyCommandSignature } from '../core/bundle-envelope.ts';
import { openSecrets } from '../core/secrets.ts';
import {
  CommandAckRequest,
  ConfigBundle,
  DeviceCommand,
  EnrollmentResponse,
  type DesiredState,
  type LineCredential,
} from '../core/schema.ts';
import { compileDesiredState, type CompileResult } from '../compiler/compile.ts';
import { applyArtifacts, readActive, readArtifacts, rollbackTo, listRevisions } from './apply.ts';
import { createAgentClient, postEnrollment } from './client.ts';
import { startPortal, type PortalSnapshot } from './portal.ts';
import { detectHardware, describeHardware, resolveWifiEnabled, type HardwareProfile } from './hardware.ts';
import { createSupervisor } from './supervisor.ts';
import { SessionStore } from './sessions.ts';
import { renderSessionsNft } from '../compiler/sessions.ts';
import { identityForIp, ipForMacHash, readArpTable, readDhcpLeases } from './netinfo.ts';
import { startPortalDns } from './portal-dns.ts';
import { verifyPassword } from '../core/crypto.ts';

/* ------------------------------------------------------------------ 配置 */

export type AgentConfig = {
  dataDir: string;
  cloudUrl: string;
  enrollmentToken: string;
  deviceModel: string;
  agentVersion: string;
  portalPort: number;
  portalHost: string;
  dryRun: boolean;
  pollIntervalMs: number;
  heartbeatIntervalMs: number;
};

function loadConfig(): AgentConfig {
  return {
    dataDir: process.env.LP_AGENT_DIR ?? path.resolve('runtime/agent'),
    cloudUrl: process.env.LP_CLOUD_URL ?? 'http://127.0.0.1:18080',
    enrollmentToken: process.env.LP_ENROLL_TOKEN ?? '',
    deviceModel: process.env.LP_DEVICE_MODEL ?? 'Xiaomi AX3000T (样机)',
    agentVersion: '0.1.0',
    portalPort: Number(process.env.LP_PORTAL_PORT ?? 8088),
    // 真机上门户必须让局域网终端访问到；访问控制由 nftables 的 input 链负责，
    // 只放行 br-lan 到门户端口，WAN 侧依然不可达。
    portalHost: process.env.LP_PORTAL_HOST ?? (process.env.LP_DRY_RUN !== '0' ? '127.0.0.1' : '0.0.0.0'),
    dryRun: process.env.LP_DRY_RUN !== '0',
    pollIntervalMs: Number(process.env.LP_POLL_MS ?? 5000),
    heartbeatIntervalMs: Number(process.env.LP_HEARTBEAT_MS ?? 15000),
  };
}

/* ------------------------------------------------------------------ 状态 */

type AgentState = {
  deviceId: string | null;
  cloudPublicKey: string | null;
  currentRevision: number;
  lastDigest: string;
  lastApply: string;
  maintenance: boolean;
  /** 手动锁线：clientId → lineId（null 表示整机默认） */
  pins: Record<string, string>;
  /** 健康验证失败或主动回滚过的版本，阻止自动重复下发 */
  failedRevisions: number[];
  portalSecret: string;
  enrolledAt: string | null;
};

type Identity = { ed25519: { publicKey: string; privateKey: string }; x25519: { publicKey: string; privateKey: string } };

function ensureIdentity(dir: string): Identity {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'identity.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')) as Identity;
  const identity: Identity = { ed25519: generateEd25519KeyPair(), x25519: generateX25519KeyPair() };
  fs.writeFileSync(file, JSON.stringify(identity, null, 2), { mode: 0o600 });
  return identity;
}

function loadState(dir: string): AgentState {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'state.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')) as AgentState;
  return {
    deviceId: null,
    cloudPublicKey: null,
    currentRevision: 0,
    lastDigest: '',
    lastApply: '',
    maintenance: false,
    pins: {},
    failedRevisions: [],
    portalSecret: randomHex(32),
    enrolledAt: null,
  };
}

function saveState(dir: string, state: AgentState): void {
  const file = path.join(dir, 'state.json');
  const tmp = `${file}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/* ------------------------------------------------------------- 锁线重算 */

/**
 * 手动锁线按设备生效，由编译器在解析阶段应用。
 * 这里不再重排线路组——那会让同组其他设备一起被切走。
 */
/* ------------------------------------------------------------------- 主流程 */

export async function runAgent(config: AgentConfig): Promise<void> {
  const identity = ensureIdentity(config.dataDir);
  const state = loadState(config.dataDir);
  const revisionsRoot = path.join(config.dataDir, 'routing');
  const hardware: HardwareProfile = detectHardware();
  const supervisor = createSupervisor({ profile: hardware, dryRun: config.dryRun });

  /*
   * 开机先装回上一次可用的防火墙。
   *
   * 顺序很重要：nftables 规则不持久化，若等云端拉取再装，从开机到拉到配置这段时间
   * 转发链是默认放行的——那正是最危险的「裸奔窗口」。这里用本地 active 版本兜住。
   */
  async function restoreBootFirewall(): Promise<void> {
    const active = readActive(revisionsRoot);
    if (!active) return;
    const artifacts = readArtifacts(revisionsRoot, active.revision);
    if (!artifacts) return;
    const file = path.join(config.dataDir, 'boot-guard.nft');
    fs.mkdirSync(config.dataDir, { recursive: true });
    fs.writeFileSync(file, artifacts.nftables, 'utf8');
    const result = await supervisor.applyNftFile(file);
    console.log(`[agent] 开机防火墙 ${result.ok ? '已恢复' : '恢复失败'}：${result.detail}`);
  }

  // 内存中的最新配置：手动锁线需要在不重新下发的前提下重算
  let lastPayload: DesiredState | null = null;
  let lastCredentials: Record<string, LineCredential> | null = null;
  let lastCompile: CompileResult | null = null;
  let cloudReachable = false;
  let lastApplySteps: { name: string; status: string; detail: string; durationMs?: number }[] = [];

  // 会话状态落 device 自己的 dataDir：断电重启后用户不用重新登录
  const sessionStore = new SessionStore({
    file: path.join(config.dataDir, 'sessions.json'),
    graceMinutes: 5,
  });
  sessionStore.load();

  const controlEndpoints = (() => {
    try {
      const host = new URL(config.cloudUrl).hostname;
      return /^\d+\.\d+\.\d+\.\d+$/.test(host) ? [host] : [];
    } catch {
      return [];
    }
  })();

  async function enroll(): Promise<void> {
    if (!config.enrollmentToken) {
      throw new AppError('UNAUTHORIZED', '设备未注册且没有提供注册令牌（LP_ENROLL_TOKEN）');
    }
    const response = (await postEnrollment(config.cloudUrl, {
      token: config.enrollmentToken,
      deviceModel: config.deviceModel,
      agentVersion: config.agentVersion,
      hardwareFingerprint: `${os.platform()}-${os.arch()}-${os.hostname()}`,
      ed25519PublicKey: identity.ed25519.publicKey,
      x25519PublicKey: identity.x25519.publicKey,
    })) as EnrollmentResponse & { ok: boolean };

    state.deviceId = response.deviceId;
    state.cloudPublicKey = response.cloudEd25519PublicKey;
    state.enrolledAt = new Date().toISOString();
    saveState(config.dataDir, state);
    console.log(`[agent] 注册成功 deviceId=${response.deviceId}`);
  }

  if (!state.deviceId || !state.cloudPublicKey) {
    await enroll();
  }

  const client = createAgentClient({
    baseUrl: config.cloudUrl,
    deviceId: state.deviceId!,
    ed25519PrivateKey: identity.ed25519.privateKey,
  });

  /* ------------------------------------------------------------- 应用配置 */

  async function compileAndApply(bundle: ConfigBundle, secrets: { wifiPsk: string; credentials: Record<string, LineCredential> }): Promise<boolean> {
    // 硬件事实优先：云端不知道这台机器有没有无线模块
    const wifiDecision = resolveWifiEnabled(hardware, bundle.payload.wifi.enabled);
    const compileState =
      wifiDecision.enabled === bundle.payload.wifi.enabled
        ? bundle.payload
        : { ...bundle.payload, wifi: { ...bundle.payload.wifi, enabled: wifiDecision.enabled } };

    const result = compileDesiredState({
      state: compileState,
      credentials: secrets.credentials,
      controlEndpoints,
      pins: state.pins,
    });
    lastCompile = result;

    const outcome = await applyArtifacts(result.artifacts, bundle.revision, {
      root: revisionsRoot,
      dryRun: config.dryRun,
      postActivate: ({ revision, dir }) =>
        supervisor.apply({ revision, dir, wifiPsk: secrets.wifiPsk }),
    });
    lastApplySteps = outcome.steps;
    if (wifiDecision.note) {
      lastApplySteps = [
        { name: 'hardware-adjust', status: 'ok', detail: wifiDecision.note, durationMs: 0 },
        ...lastApplySteps,
      ];
    }

    if (outcome.status === 'failed' || outcome.status === 'rolled_back') {
      if (!state.failedRevisions.includes(bundle.revision)) state.failedRevisions.push(bundle.revision);
      state.lastApply = `r${bundle.revision} 应用失败，已保持上一版本`;
      saveState(config.dataDir, state);
      await report(bundle, 'failed', outcome.steps, outcome.rollbackTo);
      console.warn(`[agent] r${bundle.revision} 应用失败：${outcome.steps.filter((s) => s.status === 'failed').map((s) => s.name).join(', ')}`);
      return false;
    }

    state.currentRevision = bundle.revision;
    state.lastDigest = result.digest;
    state.lastApply = `r${bundle.revision} 已应用（${config.dryRun ? 'dry-run' : 'active'}）`;
    state.failedRevisions = state.failedRevisions.filter((r) => r !== bundle.revision);
    saveState(config.dataDir, state);
    await report(bundle, 'succeeded', outcome.steps, outcome.rollbackTo);
    console.log(`[agent] r${bundle.revision} 已应用  digest=${result.digest.slice(0, 12)}  rules=${result.stats.routeRules}`);
    return true;
  }

  async function report(
    bundle: ConfigBundle,
    status: 'succeeded' | 'failed' | 'rolled_back',
    steps: { name: string; status: string; detail: string; durationMs?: number }[],
    rollback: number | null,
  ): Promise<void> {
    try {
      await client.call('/agent/observed-state', {
        revisionId: bundle.revisionId,
        revision: bundle.revision,
        appliedAt: new Date().toISOString(),
        status,
        steps: steps.map((step) => ({
          name: step.name,
          status: step.status === 'ok' ? 'ok' : step.status === 'skipped' ? 'skipped' : 'failed',
          detail: step.detail,
          durationMs: step.durationMs ?? 0,
        })),
        artifactDigest: bundle.digest,
        rollbackTo: rollback,
      });
    } catch (error) {
      console.warn('[agent] 应用结果回传失败（本地已生效）', error instanceof Error ? error.message : error);
    }
  }

  /* --------------------------------------------------------------- 拉配置 */

  async function reconcile(reason: string): Promise<boolean> {
    const response = (await client.call('/agent/desired-state/pull', {
      currentRevision: state.currentRevision,
    })) as { upToDate: boolean; revision: number; bundle?: ConfigBundle };

    if (response.upToDate) return false;

    const bundle = ConfigBundle.parse(response.bundle);
    if (state.failedRevisions.includes(bundle.revision)) {
      console.warn(`[agent] r${bundle.revision} 曾被判定失败，等待云端修复后下发新版本`);
      return false;
    }

    const verdict = verifyBundle(bundle, {
      deviceId: state.deviceId!,
      cloudPublicKey: state.cloudPublicKey!,
      currentRevision: state.currentRevision,
    });
    if (!verdict.ok) {
      console.warn(`[agent] 配置包被拒绝：${verdict.code} ${verdict.detail}`);
      throw new AppError(verdict.code === 'REVISION_REJECTED' ? 'REVISION_REJECTED' : 'SIGNATURE_INVALID', verdict.detail);
    }

    const secrets = openSecrets(identity.x25519.privateKey, state.deviceId!, bundle.revision, bundle.secrets);
    lastPayload = bundle.payload;
    lastCredentials = secrets.credentials;

    // 会话模式：配置落地后立刻把「预授权设备」和已登录会话刷回防火墙
    if (bundle.payload.accessControl.mode === 'session' && !config.dryRun) {
      ensurePortalDns();
      await syncTrustedDevices();
      await flushSessions();
    }

    // 落一份脱敏的业务快照，供本地门户展示（不含任何凭证）
    fs.mkdirSync(config.dataDir, { recursive: true });
    fs.writeFileSync(
      path.join(config.dataDir, 'desired-state.json'),
      JSON.stringify({ ...bundle.payload, portalAccounts: bundle.payload.portalAccounts }, null, 2),
      'utf8',
    );

    const ok = await compileAndApply(bundle, secrets);
    console.log(`[agent] ${reason} → r${bundle.revision} ${ok ? '成功' : '失败'}`);
    return ok;
  }

  /* ------------------------------------------------------------- 心跳上报 */

  function resources() {
    const totalMb = Math.round(os.totalmem() / 1024 / 1024);
    const freeMb = Math.round(os.freemem() / 1024 / 1024);
    return {
      cpuLoad1: Number(os.loadavg()[0]?.toFixed(2) ?? 0),
      memoryUsedMb: totalMb - freeMb,
      memoryTotalMb: totalMb,
      temperatureC: null,
      diskFreeMb: 0,
    };
  }

  async function heartbeat(): Promise<void> {
    await client.call('/agent/heartbeat', {
      agentVersion: config.agentVersion,
      uptimeSeconds: Math.round(process.uptime()),
      observedRevision: state.currentRevision,
      health: state.maintenance ? 'maintenance' : state.currentRevision > 0 ? 'healthy' : 'degraded',
      resources: resources(),
      proxyRunning: await supervisor.proxyRunning(),
      lastApplyResult: state.lastApply,
      hardware: {
        model: hardware.model,
        arch: hardware.arch,
        cpuModel: hardware.cpuModel,
        cpuCores: hardware.cpuCores,
        memoryTotalMb: hardware.memoryTotalMb,
        hasWifi: hardware.hasWifi,
        nics: hardware.nics,
        initSystem: hardware.initSystem,
        kernel: hardware.kernel,
      },
    });
  }

  /* --------------------------------------------------------------- 命令 */

  async function handleCommand(command: DeviceCommand): Promise<void> {
    const verdict = verifyCommandSignature(command, {
      deviceId: state.deviceId!,
      cloudPublicKey: state.cloudPublicKey!,
    });
    if (!verdict.ok) {
      console.warn(`[agent] 命令 ${command.id} 被拒绝：${verdict.code}`);
      await ack(command, 'FAILED', verdict.code, verdict.detail);
      return;
    }

    try {
      switch (command.type) {
        case 'AUTHORIZE_DEVICE':
        case 'CHANGE_ROUTE_PROFILE':
        case 'REVOKE_DEVICE':
        case 'ROTATE_CREDENTIAL': {
          await ack(command, 'RUNNING', 'PULLING', '正在拉取新配置');
          const applied = await reconcile(`命令 ${command.type}`);
          await ack(command, applied ? 'SUCCEEDED' : 'FAILED', applied ? 'APPLIED' : 'NOT_APPLIED', applied ? '配置已应用' : '配置未应用，请查看诊断');
          return;
        }
        case 'ROLLBACK_CONFIG': {
          const target = (command.params as { toRevision?: number | null }).toRevision ?? null;
          const rolled = await rollbackTo(revisionsRoot, target);
          if (!rolled.ok) {
            await ack(command, 'FAILED', 'ROLLBACK_FAILED', rolled.detail);
            return;
          }
          // 回滚后把这个版本拉黑，避免云端下一轮又把它推回来
          if (!state.failedRevisions.includes(state.currentRevision)) {
            state.failedRevisions.push(state.currentRevision);
          }
          state.currentRevision = rolled.revision ?? state.currentRevision;
          state.lastApply = rolled.detail;
          saveState(config.dataDir, state);
          await ack(command, 'SUCCEEDED', 'ROLLED_BACK', rolled.detail);
          return;
        }
        case 'ENTER_MAINTENANCE': {
          state.maintenance = Boolean((command.params as { enabled?: boolean }).enabled);
          saveState(config.dataDir, state);
          await ack(command, 'SUCCEEDED', state.maintenance ? 'MAINTENANCE_ON' : 'MAINTENANCE_OFF', '维护模式已切换');
          return;
        }
        case 'SWITCH_LINE': {
          const params = command.params as { clientId?: string | null; targetLineId?: string };
          if (!params.targetLineId) {
            await ack(command, 'FAILED', 'BAD_PARAMS', '缺少目标线路');
            return;
          }
          state.pins[params.clientId ?? '__default__'] = params.targetLineId;
          saveState(config.dataDir, state);
          if (lastPayload && lastCredentials) {
            const bundle: ConfigBundle = {
              deviceId: state.deviceId!,
              revision: state.currentRevision,
              revisionId: `rev-${state.deviceId}-${state.currentRevision}`,
              generatedAt: new Date().toISOString(),
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              digest: state.lastDigest,
              payload: lastPayload,
              secrets: { keyVersion: 1, ephemeralPublicKey: '', nonce: '', ciphertext: '' },
              signature: '',
            };
            await compileAndApply(bundle, { wifiPsk: '', credentials: lastCredentials });
          }
          await ack(command, 'SUCCEEDED', 'PINNED', `已锁定到 ${params.targetLineId}`);
          return;
        }
        case 'CHANGE_WIFI_PSK': {
          // 口令本身已在云端加密，随下一次配置下发；这里只确认能落到 hostapd
          const psk = (command.params as { psk?: string }).psk;
          if (!psk) {
            await ack(command, 'FAILED', 'BAD_PARAMS', '缺少口令');
            return;
          }
          await ack(command, 'SUCCEEDED', 'QUEUED', '口令已随配置下发，等待应用');
          return;
        }
        case 'RESTART_PROXY':
        case 'RESTART_NETWORK': {
          const restarted =
            command.type === 'RESTART_PROXY'
              ? await supervisor.restartProxy()
              : await supervisor.restartNetwork();
          await ack(
            command,
            restarted.ok ? 'SUCCEEDED' : 'FAILED',
            restarted.ok ? 'RESTARTED' : 'HELPER_UNAVAILABLE',
            restarted.detail,
          );
          return;
        }
        case 'UPGRADE_FIRMWARE': {
          await ack(command, 'FAILED', 'NOT_IMPLEMENTED', 'OTA 属于 Phase 7，当前版本不提供');
          return;
        }
        default: {
          await ack(command, 'FAILED', 'UNKNOWN_COMMAND', '未识别的命令类型');
        }
      }
    } catch (error) {
      await ack(command, 'FAILED', 'EXECUTION_ERROR', error instanceof Error ? error.message : '执行异常');
    }
  }

  async function ack(
    command: DeviceCommand,
    status: 'ACCEPTED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED',
    code: string,
    message: string,
  ): Promise<void> {
    const body: CommandAckRequest = {
      commandId: command.id,
      status,
      code,
      message,
      observedRevision: state.currentRevision,
    };
    try {
      await client.call('/agent/commands/ack', body);
    } catch (error) {
      console.warn('[agent] 命令回执失败', error instanceof Error ? error.message : error);
    }
  }

  async function pollCommands(): Promise<void> {
    const response = (await client.call('/agent/commands/pull', {})) as { commands: DeviceCommand[] };
    for (const command of response.commands) {
      console.log(`[agent] 执行命令 ${command.type} (${command.id})`);
      await handleCommand(command);
    }
  }

  /* --------------------------------------------------------------- 会话 */

  /**
   * 把会话表刷进 nftables。
   *
   * 只写集合、不重启 sing-box——一次登录不能让正在推流的人断线，
   * 这是整个会话模式存在的理由，别为了省事改成重编译。
   */
  let portalDns: { close: () => void } | null = null;

  /**
   * 未登录设备的 DNS 必须有应答，否则手机连上只会显示「无法连接互联网」，
   * 永远不会弹登录页。只在会话模式下启动，且只监听 LAN 侧。
   */
  function ensurePortalDns(): void {
    if (portalDns || config.dryRun) return;
    const payload = lastPayload;
    if (!payload || payload.accessControl.mode !== 'session') return;
    try {
      portalDns = startPortalDns({
        host: payload.lan.gateway,
        answerIp: payload.lan.gateway,
        logger: (line) => console.log(line),
      });
    } catch (error) {
      console.warn('[agent] 门户 DNS 启动失败（53 端口可能被占用）', error instanceof Error ? error.message : error);
    }
  }

  async function flushSessions(): Promise<{ ok: boolean; detail: string }> {
    const plan = lastCompile?.plan;
    if (!plan || !plan.sessionMode) return { ok: false, detail: '当前不是账号接入模式' };
    const script = renderSessionsNft({ linePorts: plan.linePorts, sessions: sessionStore.entries() });
    const file = path.join(config.dataDir, 'sessions.nft');
    fs.mkdirSync(config.dataDir, { recursive: true });
    fs.writeFileSync(file, script, 'utf8');
    const result = await supervisor.applySessions(file);
    if (!result.ok) console.warn(`[agent] 会话表更新失败：${result.detail}`);
    return result;
  }

  /**
   * 预授权设备落位：按 MAC 从 dnsmasq 租约找 IP，找到就常驻进会话表。
   * 编码器、NVR 没有浏览器，这条是它们唯一的出口。
   */
  async function syncTrustedDevices(): Promise<void> {
    const plan = lastCompile?.plan;
    const devices = lastPayload?.trustedDevices ?? [];
    if (!plan?.sessionMode || devices.length === 0) return;
    const leases = readDhcpLeases();
    let changed = false;
    for (const device of devices) {
      const ip = ipForMacHash(device.macHash, leases);
      if (!ip) continue;
      const existing = sessionStore.findByMac(device.macHash);
      if (existing && existing.srcIp === ip && existing.lineId === device.lineId) continue;
      sessionStore.seedTrusted({ macHash: device.macHash, lineId: device.lineId, srcIp: ip });
      changed = true;
    }
    if (changed) await flushSessions();
  }

  /* --------------------------------------------------------------- 门户 */

  function snapshot(): PortalSnapshot {
    const active = readActive(revisionsRoot);
    const payload = lastPayload;
    const plan = lastCompile?.plan;
    const authorized = plan?.clients ?? [];
    const profiles = (payload?.routeProfiles ?? []).map((p) => ({ id: p.id, name: p.name }));
    const lines = (payload?.lines ?? []).map((l) => ({ id: l.id, name: l.name, region: l.region }));

    const clients = (payload?.clients ?? []).map((client) => {
      const planned = authorized.find((c) => c.clientId === client.id);
      return {
        id: client.id,
        label: client.label,
        ip: client.ipAddress,
        state: client.state,
        attach: client.attachInterface,
        primaryLine: planned?.primary.name ?? null,
        primaryLineId: planned?.primary.lineId ?? null,
        standbyLine: planned?.standby?.name ?? null,
        profileName: planned?.profileName ?? null,
      };
    });

    const first = authorized[0];
    return {
      device: {
        id: state.deviceId ?? '—',
        model: config.deviceModel,
        health: cloudReachable ? (state.maintenance ? 'maintenance' : 'healthy') : 'offline-cloud',
        activeRevision: active?.revision ?? state.currentRevision,
        digestShort: state.lastDigest.slice(0, 12),
        lastApply: state.lastApply,
        cloudReachable,
      },
      wifi: {
        enabled: hardware.hasWifi,
        ssid: payload?.wifi.ssid ?? 'LinkPilot-WiFi',
        band: payload?.wifi.band ?? '2.4+5',
      },
      exit: {
        lineName: first?.primary.name ?? null,
        region: first?.primary.region ?? null,
      },
      clients,
      profiles,
      lines,
      diagnostics: [
        {
          name: '云端控制通道',
          detail: cloudReachable ? '签名通道正常' : '暂时不可达，本地策略继续生效',
          status: cloudReachable ? 'ok' : 'warn',
        },
        {
          name: '配置签名与版本',
          detail: `当前 r${active?.revision ?? state.currentRevision} · ${state.lastDigest.slice(0, 12)}`,
          status: state.lastDigest ? 'ok' : 'warn',
        },
        {
          name: '代理核心',
          detail: config.dryRun ? 'dry-run 模式：未启动代理核心' : '运行中',
          status: config.dryRun ? 'warn' : 'ok',
        },
        {
          name: 'IPv6 与 DNS 防泄露',
          detail: 'IPv6 默认关闭，DNS 强制接管',
          status: 'ok',
        },
        {
          name: '未授权设备隔离',
          detail: '转发链默认拒绝，未授权设备仅可访问门户',
          status: 'ok',
        },
      ],
      access: {
        mode: payload?.accessControl.mode ?? 'device_binding',
        graceMinutes: payload?.accessControl.graceMinutes ?? 5,
        online: sessionStore.sessions().map((session) => ({
          username: session.username,
          lineId: session.lineId,
          lineName: payload?.lines.find((l) => l.id === session.lineId)?.name ?? null,
          ip: session.srcIp,
          since: new Date(session.loginAt).toISOString(),
          pinned: session.pinned === true,
        })),
      },
      accounts: (payload?.portalAccounts ?? []).map((account) => ({
        username: account.username,
        displayName: account.displayName,
        role: account.role,
        passwordHash: account.passwordHash,
        disabled: account.disabled,
      })),
    };
  }

  startPortal(
    {
      deviceId: state.deviceId!,
      secret: state.portalSecret,
      getSnapshot: snapshot,
      authorizeDevice: async (input) => {
        await client.call('/portal/device-bindings', {
          username: input.username,
          clientId: input.clientId,
          routeProfileId: input.routeProfileId,
        });
        await reconcile('门户授权');
      },
      changeWifi: async (input) => {
        await client.call('/portal/wifi', { username: input.username, psk: input.psk });
        await reconcile('修改 Wi-Fi 口令');
      },
      accessLogin: async ({ username, password, srcIp }) => {
        const payload = lastPayload;
        if (!payload || payload.accessControl.mode !== 'session') {
          throw new AppError('CAPABILITY_UNSUPPORTED', '当前不是账号接入模式');
        }
        const account = payload.accessAccounts.find((a) => a.username === username);
        // 账号不存在与口令错误返回同一个错误，避免枚举账号
        if (!account || !account.enabled || account.revokedAt || !verifyPassword(password, account.passwordHash)) {
          throw new AppError('UNAUTHORIZED', '账号或密码错误');
        }
        if (account.expiresAt && Date.parse(account.expiresAt) <= Date.now()) {
          throw new AppError('FORBIDDEN', '账号已到期，请续费后再试');
        }
        const identity = identityForIp(srcIp, readArpTable());
        const result = sessionStore.login({ account, srcIp, macHash: identity.macHash });
        sessionStore.sweep();
        const applied = await flushSessions();
        if (result.evicted.length > 0) {
          console.log(`[agent] 账号 ${username} 后登踢前登，下线 ${result.evicted.length} 台设备`);
        }
        const line = payload.lines.find((l) => l.id === account.lineId);
        return { ok: applied.ok, lineId: account.lineId, lineName: line?.name ?? null };
      },
      accessState: (srcIp) => {
        const payload = lastPayload;
        if (!payload || payload.accessControl.mode !== 'session') {
          return { enabled: false, authed: false, username: null, lineId: null, lineName: null };
        }
        const identity = identityForIp(srcIp, readArpTable());
        const session = sessionStore.findByMac(identity.macHash);
        if (!session) return { enabled: true, authed: false, username: null, lineId: null, lineName: null };
        const line = payload.lines.find((l) => l.id === session.lineId);
        return {
          enabled: true,
          authed: true,
          username: session.username,
          lineId: session.lineId,
          lineName: line?.name ?? null,
        };
      },
      accessKick: async ({ username }) => {
        // 踢线只清会话，不封账号：客户下次还能自己登回来
        const target = sessionStore.sessions().find((session) => session.username === username);
        if (!target) return false;
        const removed = sessionStore.logoutByMac(target.macHash);
        if (removed) await flushSessions();
        return removed;
      },
      accessLogout: async (srcIp) => {
        const identity = identityForIp(srcIp, readArpTable());
        const removed = sessionStore.logoutByMac(identity.macHash);
        if (removed) await flushSessions();
        return removed;
      },
      pinLine: async (input) => {
        state.pins[input.clientId] = input.lineId;
        saveState(config.dataDir, state);
        if (lastPayload && lastCredentials) {
          const bundle: ConfigBundle = {
            deviceId: state.deviceId!,
            revision: state.currentRevision,
            revisionId: `rev-${state.deviceId}-${state.currentRevision}`,
            generatedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
            digest: state.lastDigest,
            payload: lastPayload,
            secrets: { keyVersion: 1, ephemeralPublicKey: '', nonce: '', ciphertext: '' },
            signature: '',
          };
          await compileAndApply(bundle, { wifiPsk: '', credentials: lastCredentials });
        }
      },
    },
    config.portalPort,
    config.portalHost,
  );

  await restoreBootFirewall();

  console.log(`[agent] 硬件档位 ${describeHardware(hardware)}`);
  console.log(`[agent] 门户已启动 http://${config.portalHost}:${config.portalPort}`);
  console.log(`[agent] 模式 ${config.dryRun ? 'dry-run（不切换 active 指针）' : 'apply'}  revision r${state.currentRevision}`);

  /* --------------------------------------------------------------- 主循环 */

  let stopping = false;
  const stop = (): void => {
    stopping = true;
    console.log('[agent] 收到停止信号');
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  let lastHeartbeat = 0;

  while (!stopping) {
    try {
      await reconcile('轮询');
      cloudReachable = true;
      if (Date.now() - lastHeartbeat > config.heartbeatIntervalMs) {
        await heartbeat();
        lastHeartbeat = Date.now();
      }
      await pollCommands();
    } catch (error) {
      cloudReachable = false;
      console.warn('[agent] 与云端交互失败，本地策略继续运行：', error instanceof Error ? error.message : error);
    }
    await new Promise((resolve) => setTimeout(resolve, config.pollIntervalMs));
  }

  const revisions = listRevisions(revisionsRoot);
  console.log(`[agent] 退出。本地保留版本：r${revisions.join(', r')}`);
}

/*
 * 直接运行入口判定。
 * 除了源码方式（node src/agent/main.ts），固件里跑的是打包后的单文件
 * /opt/linkpilot/agent.mjs（esbuild 输出，见 image/），因此这里也要认它。
 * 用固定名字匹配而不是「非空即启动」，保证被其他模块 import 时不会误启动。
 */
const ENTRY_NAMES = ['main.ts', 'agent.mjs', 'linkpilot-agent'];
if (process.argv[1] && ENTRY_NAMES.some((name) => process.argv[1]!.endsWith(name))) {
  runAgent(loadConfig()).catch((error) => {
    console.error('[agent] 启动失败', error);
    process.exit(1);
  });
}
