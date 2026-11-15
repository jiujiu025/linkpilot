/**
 * 云端控制面
 *
 * 对外三组接口，鉴权模型完全不同（docs/design/05 §4）：
 * - /agent/*     设备身份 + 每条请求 Ed25519 签名 + 时间窗 + nonce 防重放
 * - /api/admin/* 管理员 token（生产环境替换为 OIDC + MFA 会话）
 * - /api/portal/* 门户 API 在设备本地，云端不提供
 *
 * 云端永远不下发 shell，只下发固定命令与签名配置。
 */
import { hashPassword, randomHex, ReplayGuard, sha256Hex, safeEqual } from '../core/crypto.ts';
import { renderAdminHtml } from './admin-ui.ts';
import { parseAccountsCsv, parseLinesCsv, poolCapacity, type ImportRowResult } from './import.ts';
import { accountNameFor, parseNodeList } from './parse-nodes.ts';
import { probeLine, probeMany, probeTargetOf, type ProbeTarget } from './probe.ts';
import { AppError } from '../core/errors.ts';
import { computeBundleDigest, signBundle, signCommand, verifyAgentRequest } from '../core/bundle-envelope.ts';
import { sealSecrets } from '../core/secrets.ts';
import {
  CommandParams,
  EnrollmentRequest,
  HeartbeatRequest,
  ObservedStateReport,
  CommandAckRequest,
  LineCredential,
  DesiredState,
  LanConfig,
  WifiConfig,
  type ConfigBundle,
  type DeviceCommand,
  type Line,
  type EnrollmentResponse,
} from '../core/schema.ts';
import { Router, serve, type Ctx } from './http.ts';
import { loadCloudKeys, openWithMaster, sealWithMaster, type CloudKeys } from './keys.ts';
import { Store, type ClientRecord, type DeviceRecord, type StoredCredential } from './store.ts';
import http from 'node:http';
import { randomInt } from 'node:crypto';

export type ControlConfig = {
  dataDir: string;
  port: number;
  adminToken: string;
  /** 监听地址：默认只允许本机；要在局域网里打开后台，设为 0.0.0.0 */
  host?: string;
};

export type ControlPlane = {
  router: Router;
  store: Store;
  keys: CloudKeys;
  server: http.Server;
  /** 演示与测试用：直接写入一条设备命令 */
  issueCommand(input: {
    deviceId: string;
    type: DeviceCommand['type'];
    params: Record<string, unknown>;
    actor: string;
    reason: string;
  }): DeviceCommand;
  buildBundle(deviceId: string): ConfigBundle;
};

const AGENT_SKEW_MS = 5 * 60 * 1000;
const BUNDLE_TTL_MS = 15 * 60 * 1000;
const COMMAND_TTL_MS = 10 * 60 * 1000;

export function createControlPlane(config: ControlConfig): ControlPlane {
  const store = new Store(config.dataDir);
  const keys = loadCloudKeys(config.dataDir);
  const replay = new ReplayGuard(AGENT_SKEW_MS);
  const router = new Router();

  /* ------------------------------------------------------------ 设备鉴权 */

  function authenticateAgent(ctx: Ctx): DeviceRecord {
    const deviceId = String(ctx.headers['x-lp-device'] ?? '');
    const timestamp = String(ctx.headers['x-lp-timestamp'] ?? '');
    const nonce = String(ctx.headers['x-lp-nonce'] ?? '');
    const signature = String(ctx.headers['x-lp-signature'] ?? '');
    if (!deviceId || !timestamp || !nonce || !signature) {
      throw new AppError('UNAUTHORIZED', '缺少设备签名头');
    }
    const device = store.device(deviceId);
    if (!device) throw new AppError('UNAUTHORIZED', '设备未注册');
    if (device.state === 'revoked') throw new AppError('FORBIDDEN', '设备已被吊销');

    const ts = Date.parse(timestamp);
    if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > AGENT_SKEW_MS) {
      throw new AppError('UNAUTHORIZED', '请求时间戳超出允许窗口', { timestamp });
    }
    if (!replay.use(`${deviceId}:${nonce}`)) {
      throw new AppError('REPLAY_DETECTED', '检测到重放的设备请求');
    }
    const ok = verifyAgentRequest(
      ctx.method,
      ctx.path,
      timestamp,
      nonce,
      ctx.rawBody,
      signature,
      device.ed25519PublicKey,
    );
    if (!ok) throw new AppError('SIGNATURE_INVALID', '设备请求签名校验失败');

    store.mutate((db) => {
      const record = db.devices.find((d) => d.id === deviceId);
      if (record) record.lastSeenAt = new Date().toISOString();
    });
    return device;
  }

  function requireAdmin(ctx: Ctx): string {
    const header = String(ctx.headers.authorization ?? '');
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token || !safeEqual(token, config.adminToken)) {
      throw new AppError('UNAUTHORIZED', '管理令牌无效');
    }
    return 'admin';
  }

  /* ---------------------------------------------------------- 配置包构建 */

  function buildBundle(deviceId: string): ConfigBundle {
    const device = store.requireDevice(deviceId);
    if (!device.x25519PublicKey) throw new AppError('CONFLICT', '设备缺少加密公钥，无法封装凭证');

    const db = store.data;
    const wifiSecret = db.deviceSecrets.find((s) => s.deviceId === deviceId);
    const wifiPsk = wifiSecret
      ? openWithMaster<string>(keys.masterKey, wifiSecret.wifiNonce, wifiSecret.wifiCiphertext, `wifi:${deviceId}`)
      : 'LinkPilot-2026';

    const credentials: Record<string, LineCredential> = {};
    for (const stored of db.credentials) {
      const line = db.lines.find((l) => l.id === stored.lineId);
      if (!line || !line.enabled) continue;
      credentials[stored.id] = openWithMaster<LineCredential>(
        keys.masterKey,
        stored.nonce,
        stored.ciphertext,
        `cred:${stored.id}`,
      );
    }

    /*
     * 必须过一遍 DesiredState.parse 再算摘要：
     * 存储里的旧记录可能缺后来新增的字段（例如 lanPorts），设备侧解析时会补默认值，
     * 两边摘要就对不上，表现为整机 DIGEST_MISMATCH。以 zod 规范化后的结果为准。
     */
    const payload: DesiredState = DesiredState.parse({
      deviceId,
      organizationId: device.organizationId,
      revision: device.revision,
      generatedAt: new Date().toISOString(),
      lan: device.lan,
      wifi: device.wifi,
      portalAccounts: db.portalAccounts,
      accessControl: db.accessControl,
      accessAccounts: db.accessAccounts.filter((a) => a.enabled && !a.revokedAt),
      trustedDevices: db.trustedDevices,
      // 必须剥掉存储层内部字段（deviceId 已在信封上），否则 zod 会把它 strip 掉，
      // 导致设备侧重算摘要与云端不一致——这是最容易踩的一个坑。
      clients: store.clientsOf(deviceId).map(({ deviceId: _ignored, ...rest }) => rest),
      bindings: store.bindingsOf(deviceId).map(({ deviceId: _ignored, ...rest }) => rest),
      routeProfiles: db.routeProfiles,
      lineGroups: db.lineGroups,
      lines: db.lines,
      failoverPolicies: db.failoverPolicies,
    });

    const secrets = sealSecrets(device.x25519PublicKey, deviceId, device.revision, {
      wifiPsk,
      credentials,
    });

    const bundleWithoutSignature = {
      deviceId,
      revision: device.revision,
      revisionId: `rev-${deviceId}-${device.revision}`,
      generatedAt: payload.generatedAt,
      expiresAt: new Date(Date.now() + BUNDLE_TTL_MS).toISOString(),
      digest: computeBundleDigest(payload, secrets),
      payload,
      secrets,
    };

    return signBundle(bundleWithoutSignature, keys.signing.privateKey);
  }

  /* ------------------------------------------------------------- 命令 */

  function issueCommand(input: {
    deviceId: string;
    type: DeviceCommand['type'];
    params: Record<string, unknown>;
    actor: string;
    reason: string;
  }): DeviceCommand {
    let parsed: ReturnType<typeof CommandParams.parse>;
    try {
      parsed = CommandParams.parse({ type: input.type, ...input.params });
    } catch {
      // 非白名单命令 / 参数非法：必须是明确的 400，而不是把 zod 细节吐给调用方
      throw new AppError('BAD_REQUEST', `不支持的命令或参数不合法: ${input.type}`);
    }
    const device = store.requireDevice(input.deviceId);
    if (device.state === 'revoked') throw new AppError('FORBIDDEN', '设备已被吊销，拒绝下发命令');
    if (!input.reason.trim()) throw new AppError('BAD_REQUEST', '高风险操作必须填写原因');

    const command: Omit<DeviceCommand, 'signature'> = {
      id: `cmd-${randomHex(6)}`,
      deviceId: input.deviceId,
      type: parsed.type,
      params: parsed as unknown as Record<string, unknown>,
      actor: input.actor,
      reason: input.reason,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + COMMAND_TTL_MS).toISOString(),
      idempotencyKey: `${parsed.type}:${sha256Hex(JSON.stringify(parsed)).slice(0, 16)}`,
      nonce: randomHex(12),
      status: 'PENDING',
      result: null,
    };
    // 必须用与设备侧完全一致的规范化载荷签名，JSON.stringify 的键序不稳定会直接导致验签失败
    const signature = signCommand(command, keys.signing.privateKey);
    const full: DeviceCommand = { ...command, signature };

    store.mutate((db) => {
      db.commands.push(full);
    });
    store.audit({
      actor: input.actor,
      action: `COMMAND:${parsed.type}`,
      target: input.deviceId,
      reason: input.reason,
      result: 'ok',
      detail: `commandId=${full.id}`,
    });
    return full;
  }

  /* ------------------------------------------------------------- 路由 */

  router.get('/healthz', () => ({ body: { ok: true, service: 'linkpilot-control' } }));

  // 运营后台：单页，不依赖构建；接口全部要 Bearer 令牌，页面本身不含任何凭证
  router.get('/admin', () => ({
    raw: renderAdminHtml(),
    contentType: 'text/html; charset=utf-8',
  }));

  router.post('/agent/enrollment', (ctx) => {
    const body = EnrollmentRequest.parse(ctx.json);
    const tokenHash = sha256Hex(body.token);
    const db = store.data;
    const tokenRecord = db.tokens.find((t) => t.tokenHash === tokenHash);
    if (!tokenRecord) throw new AppError('UNAUTHORIZED', '注册令牌无效');
    if (tokenRecord.usedAt) throw new AppError('CONFLICT', '注册令牌已被使用');
    if (Date.parse(tokenRecord.expiresAt) < Date.now()) throw new AppError('EXPIRED', '注册令牌已过期');

    const now = new Date().toISOString();
    const device: DeviceRecord = {
      id: tokenRecord.deviceId,
      organizationId: tokenRecord.organizationId,
      model: body.deviceModel,
      hardwareFingerprint: body.hardwareFingerprint,
      agentVersion: body.agentVersion,
      ed25519PublicKey: body.ed25519PublicKey,
      x25519PublicKey: body.x25519PublicKey,
      state: 'active',
      enrolledAt: now,
      lastSeenAt: now,
      lastHeartbeatAt: null,
      revision: 1,
      observedRevision: 0,
      health: 'unknown',
      proxyRunning: false,
      resources: null,
      lastApplyResult: '',
      hardware: null,
      /*
       * 用 LanConfig.parse 生成而不是手写对象：新增字段（如 lanPorts）带默认值时，
       * 手写字面量会缺字段，导致云端算出的摘要与设备侧解析补默认值后的摘要不一致，
       * 表现为「所有配置包都 DIGEST_MISMATCH」。
       */
      lan: LanConfig.parse({
        gateway: '192.168.10.1',
        cidr: '192.168.10.0/24',
        dhcpStart: '192.168.10.50',
        dhcpEnd: '192.168.10.250',
        portalPort: 8080,
        controlPort: 8081,
        wanInterface: 'wan',
        lanInterface: 'br-lan',
        tunName: 'lp-tun',
        tunCidr: '172.19.0.1/30',
        dnsPort: 5353,
        ipv6Enabled: false,
      }),
      wifi: WifiConfig.parse({ enabled: true, ssid: 'LinkPilot-WiFi', hidden: false, band: '2.4+5' }),
    };

    store.mutate((inner) => {
      inner.devices = inner.devices.filter((d) => d.id !== device.id);
      inner.devices.push(device);
      const record = inner.tokens.find((t) => t.tokenHash === tokenHash);
      if (record) record.usedAt = now;
      if (!inner.deviceSecrets.some((s) => s.deviceId === device.id)) {
        const sealed = sealWithMaster(keys.masterKey, 'LinkPilot-2026', `wifi:${device.id}`);
        inner.deviceSecrets.push({ deviceId: device.id, wifiNonce: sealed.nonce, wifiCiphertext: sealed.ciphertext });
      }
    });

    store.audit({
      actor: `agent:${device.id}`,
      action: 'ENROLL',
      target: device.id,
      reason: '设备首次激活',
      result: 'ok',
      detail: `model=${body.deviceModel} agent=${body.agentVersion}`,
    });

    const response: EnrollmentResponse = {
      deviceId: device.id,
      organizationId: device.organizationId,
      cloudEd25519PublicKey: keys.signing.publicKey,
      heartbeatIntervalSeconds: 15,
      pollIntervalSeconds: 10,
    };
    return { body: { ok: true, ...response } };
  });

  router.post('/agent/heartbeat', (ctx) => {
    const device = authenticateAgent(ctx);
    const body = HeartbeatRequest.parse(ctx.json);
    store.mutate((db) => {
      const record = db.devices.find((d) => d.id === device.id);
      if (!record) return;
      record.lastHeartbeatAt = new Date().toISOString();
      record.health = body.health;
      record.resources = body.resources;
      record.proxyRunning = body.proxyRunning;
      record.agentVersion = body.agentVersion;
      record.observedRevision = Math.max(record.observedRevision, body.observedRevision);
      record.lastApplyResult = body.lastApplyResult;
      if (body.hardware) record.hardware = body.hardware;
    });
    return { body: { ok: true, serverTime: new Date().toISOString() } };
  });

  router.post('/agent/desired-state/pull', (ctx) => {
    const device = authenticateAgent(ctx);
    const currentRevision = Number((ctx.json as { currentRevision?: number })?.currentRevision ?? 0);
    if (device.revision <= currentRevision) {
      return { body: { ok: true, upToDate: true, revision: device.revision } };
    }
    const bundle = buildBundle(device.id);
    return { body: { ok: true, upToDate: false, bundle } };
  });

  router.post('/agent/observed-state', (ctx) => {
    const device = authenticateAgent(ctx);
    const report = ObservedStateReport.parse(ctx.json);
    store.mutate((db) => {
      db.observed.push({
        id: `obs-${randomHex(6)}`,
        deviceId: device.id,
        revision: report.revision,
        revisionId: report.revisionId,
        appliedAt: report.appliedAt,
        status: report.status,
        artifactDigest: report.artifactDigest,
        steps: report.steps,
        rollbackTo: report.rollbackTo,
      });
      const record = db.devices.find((d) => d.id === device.id);
      if (record && report.status === 'succeeded') {
        record.observedRevision = Math.max(record.observedRevision, report.revision);
        record.lastApplyResult = `r${report.revision} 已应用`;
      } else if (record) {
        record.lastApplyResult = `r${report.revision} ${report.status}`;
      }
    });
    return { body: { ok: true } };
  });

  router.post('/agent/commands/pull', (ctx) => {
    const device = authenticateAgent(ctx);
    const now = Date.now();
    const pending = store
      .commandsOf(device.id)
      .filter((command) => command.status === 'PENDING' && Date.parse(command.expiresAt) > now);
    return { body: { ok: true, commands: pending } };
  });

  router.post('/agent/commands/ack', (ctx) => {
    const device = authenticateAgent(ctx);
    const ack = CommandAckRequest.parse(ctx.json);
    const command = store.data.commands.find((c) => c.id === ack.commandId);
    if (!command) throw new AppError('NOT_FOUND', '命令不存在');
    if (command.deviceId !== device.id) throw new AppError('FORBIDDEN', '命令不属于本设备');
    store.mutate((db) => {
      const target = db.commands.find((c) => c.id === ack.commandId);
      if (!target) return;
      target.status = ack.status;
      target.result = {
        code: ack.code,
        message: ack.message,
        completedAt: new Date().toISOString(),
        observedRevision: ack.observedRevision,
      };
    });
    store.audit({
      actor: `agent:${device.id}`,
      action: `COMMAND_ACK:${command.type}`,
      target: device.id,
      reason: ack.message || '执行结果回报',
      result: ack.status === 'FAILED' ? 'failed' : 'ok',
      detail: `${command.id} ${ack.status} ${ack.code}`,
    });
    return { body: { ok: true } };
  });

  /* ------------------------------------------------- 门户（经设备代理） */

  /**
   * 门户跑在设备本地，但它不是事实来源：所有写操作都经设备签名转发到云端，
   * 由云端统一做校验、版本提升和审计。设备只是「可信的转发者」。
   */
  router.post('/portal/device-bindings', (ctx) => {
    const device = authenticateAgent(ctx);
    const body = (ctx.json ?? {}) as {
      username?: string;
      clientId?: string;
      routeProfileId?: string;
      validUntil?: string | null;
    };
    const account = store.data.portalAccounts.find((a) => a.username === body.username && !a.disabled);
    if (!account) throw new AppError('UNAUTHORIZED', '门户账号无效');
    if (!body.clientId || !body.routeProfileId) throw new AppError('BAD_REQUEST', '缺少设备或策略');
    const profile = store.data.routeProfiles.find((p) => p.id === body.routeProfileId);
    if (!profile) throw new AppError('NOT_FOUND', '线路策略不存在');
    const client = store.clientsOf(device.id).find((c) => c.id === body.clientId);
    if (!client) throw new AppError('NOT_FOUND', '设备不存在');

    const now = new Date().toISOString();
    store.mutate((db) => {
      for (const binding of db.bindings.filter((b) => b.deviceId === device.id && b.clientId === client.id)) {
        if (!binding.revokedAt) binding.revokedAt = now;
      }
      db.bindings.push({
        id: `bind-${randomHex(4)}`,
        deviceId: device.id,
        clientId: client.id,
        routeProfileId: body.routeProfileId!,
        validFrom: now,
        validUntil: body.validUntil ?? null,
        revokedAt: null,
        version: 1,
      });
      const record = db.clients.find((c) => c.id === client.id);
      if (record) {
        record.state = 'authorized';
        record.lastSeenAt = now;
      }
    });
    const revision = store.bumpRevision(device.id, `门户授权 ${client.label}`);
    store.audit({
      actor: `portal:${account.username}`,
      action: 'AUTHORIZE_DEVICE',
      target: `${device.id}/${client.id}`,
      reason: '客户在本地门户授权设备',
      result: 'ok',
      detail: `profile=${body.routeProfileId} revision=r${revision.revision}`,
    });
    return { body: { ok: true, revision: revision.revision } };
  });

  router.post('/portal/wifi', (ctx) => {
    const device = authenticateAgent(ctx);
    const body = (ctx.json ?? {}) as { username?: string; psk?: string };
    const account = store.data.portalAccounts.find((a) => a.username === body.username && !a.disabled);
    if (!account) throw new AppError('UNAUTHORIZED', '门户账号无效');
    if (account.role !== 'device_admin') throw new AppError('FORBIDDEN', '只有设备管理员可以修改 Wi-Fi 口令');
    const psk = String(body.psk ?? '');
    if (psk.length < 8 || psk.length > 63) throw new AppError('BAD_REQUEST', 'Wi-Fi 口令长度需为 8~63 位');

    const sealed = sealWithMaster(keys.masterKey, psk, `wifi:${device.id}`);
    store.mutate((db) => {
      db.deviceSecrets = db.deviceSecrets.filter((s) => s.deviceId !== device.id);
      db.deviceSecrets.push({ deviceId: device.id, wifiNonce: sealed.nonce, wifiCiphertext: sealed.ciphertext });
    });
    const revision = store.bumpRevision(device.id, '修改 Wi-Fi 口令');
    store.audit({
      actor: `portal:${account.username}`,
      action: 'CHANGE_WIFI_PSK',
      target: device.id,
      reason: '设备管理员在本地门户修改 Wi-Fi 口令',
      result: 'ok',
      detail: `revision=r${revision.revision}（口令不落日志）`,
    });
    return { body: { ok: true, revision: revision.revision } };
  });

  /* --------------------------------------------------------- 管理端 API */

  router.get('/api/admin/overview', (ctx) => {
    requireAdmin(ctx);
    const db = store.data;
    return {
      body: {
        ok: true,
        organization: db.organization,
        devices: db.devices.map((d) => ({
          id: d.id,
          model: d.model,
          hardware: d.hardware,
          state: d.state,
          health: d.health,
          revision: d.revision,
          observedRevision: d.observedRevision,
          lastSeenAt: d.lastSeenAt,
          proxyRunning: d.proxyRunning,
          lastApplyResult: d.lastApplyResult,
        })),
        counts: {
          devices: db.devices.length,
          clients: db.clients.length,
          authorized: db.clients.filter((c) => c.state === 'authorized').length,
          pending: db.clients.filter((c) => c.state === 'pending').length,
          lines: db.lines.length,
          commands: db.commands.length,
        },
      },
    };
  });

  router.get('/api/admin/routers/:id', (ctx) => {
    requireAdmin(ctx);
    const device = store.requireDevice(ctx.params.id ?? '');
    return {
      body: {
        ok: true,
        device,
        clients: store.clientsOf(device.id),
        bindings: store.bindingsOf(device.id),
        revisions: store.data.revisions.filter((r) => r.deviceId === device.id).slice(-20),
        observed: store.data.observed.filter((o) => o.deviceId === device.id).slice(-20),
        commands: store.commandsOf(device.id).slice(-20),
        lineGroups: store.data.lineGroups,
        routeProfiles: store.data.routeProfiles.map((p) => ({ id: p.id, name: p.name, mode: p.mode })),
      },
    };
  });

  router.post('/api/admin/routers/:id/device-authorizations', (ctx) => {
    const actor = requireAdmin(ctx);
    const deviceId = ctx.params.id ?? '';
    const device = store.requireDevice(deviceId);
    const body = (ctx.json ?? {}) as {
      clientId?: string;
      label?: string;
      ipAddress?: string;
      hostname?: string;
      routeProfileId?: string;
      validUntil?: string | null;
      reason?: string;
    };
    if (!body.routeProfileId) throw new AppError('BAD_REQUEST', '必须指定线路策略');
    const profile = store.data.routeProfiles.find((p) => p.id === body.routeProfileId);
    if (!profile) throw new AppError('NOT_FOUND', '线路策略不存在');

    const now = new Date().toISOString();
    let client = body.clientId
      ? store.clientsOf(deviceId).find((c) => c.id === body.clientId)
      : undefined;

    const created: ClientRecord = client ?? {
      id: `cl-${randomHex(4)}`,
      deviceId,
      label: body.label ?? body.hostname ?? '未命名设备',
      hostname: body.hostname ?? '',
      macHash: `sha256:${randomHex(4)}`,
      ipAddress: body.ipAddress ?? nextClientIp(deviceId),
      state: 'authorized',
      confidence: 'low',
      attachInterface: 'lan',
      firstSeenAt: now,
      lastSeenAt: now,
    };

    store.mutate((db) => {
      const existing = db.clients.find((c) => c.id === created.id);
      if (existing) {
        existing.state = 'authorized';
        existing.lastSeenAt = now;
        if (body.label) existing.label = body.label;
      } else {
        db.clients.push(created);
      }
      // 同一设备只保留一条生效绑定：撤旧的，建新的
      for (const binding of db.bindings.filter((b) => b.deviceId === deviceId && b.clientId === created.id)) {
        if (!binding.revokedAt) binding.revokedAt = now;
      }
      db.bindings.push({
        id: `bind-${randomHex(4)}`,
        deviceId,
        clientId: created.id,
        routeProfileId: body.routeProfileId!,
        validFrom: now,
        validUntil: body.validUntil ?? null,
        revokedAt: null,
        version: 1,
      });
    });

    const revision = store.bumpRevision(deviceId, `授权设备 ${created.label}`);
    store.audit({
      actor,
      action: 'AUTHORIZE_DEVICE',
      target: `${deviceId}/${created.id}`,
      reason: body.reason ?? '远程授权设备',
      result: 'ok',
      detail: `profile=${body.routeProfileId} revision=r${revision.revision}`,
    });
    return { body: { ok: true, client: created, revision: revision.revision } };
  });

  router.post('/api/admin/routers/:id/commands', (ctx) => {
    const actor = requireAdmin(ctx);
    const deviceId = ctx.params.id ?? '';
    const body = (ctx.json ?? {}) as { type?: string; params?: Record<string, unknown>; reason?: string };
    if (!body.type) throw new AppError('BAD_REQUEST', '缺少命令类型');
    const command = issueCommand({
      deviceId,
      type: body.type as DeviceCommand['type'],
      params: body.params ?? {},
      actor,
      reason: body.reason ?? '',
    });
    return { body: { ok: true, command } };
  });

  router.post('/api/admin/lines', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as {
      line?: Partial<Line>;
      credential?: LineCredential;
      credentialId?: string;
    };
    if (!body.line?.id || !body.credential) throw new AppError('BAD_REQUEST', '缺少线路或凭证');
    const credentialId = body.credentialId ?? `cred-${body.line.id}`;
    const line: Line = {
      id: body.line.id,
      name: body.line.name ?? body.line.id,
      region: body.line.region ?? '未标注',
      kind: body.credential.kind,
      server: body.line.server ?? '',
      port: body.line.port ?? 443,
      enabled: body.line.enabled ?? true,
      credentialId,
    };
    const sealed = sealWithMaster(keys.masterKey, body.credential, `cred:${credentialId}`);
    const stored: StoredCredential = {
      id: credentialId,
      lineId: line.id,
      keyVersion: 1,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
      rotatedAt: new Date().toISOString(),
    };
    store.mutate((db) => {
      db.lines = db.lines.filter((l) => l.id !== line.id);
      db.credentials = db.credentials.filter((c) => c.id !== credentialId);
      db.lines.push(line);
      db.credentials.push(stored);
    });
    const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
    if (target) store.bumpRevision(target.id, `新增线路 ${line.name}`);
    store.audit({
      actor,
      action: 'CREATE_LINE',
      target: line.id,
      reason: '录入自定义线路',
      result: 'ok',
      detail: `kind=${line.kind} credentialRef=${credentialId}`,
    });
    return { body: { ok: true, line: { ...line, credentialId } } };
  });

  router.get('/api/admin/lines', (ctx) => {
    requireAdmin(ctx);
    // 只回脱敏字段：凭证永远不出云端
    return {
      body: {
        ok: true,
        lines: store.data.lines.map((line) => ({
          id: line.id,
          name: line.name,
          region: line.region,
          kind: line.kind,
          server: line.server,
          port: line.port,
          enabled: line.enabled,
          lastProbe: store.data.probes[line.id] ?? null,
        })),
      },
    };
  });

  /**
   * 线路测速。
   *
   * 测的是云端到节点的 TCP/TLS 握手——能证明端口活着、证书/SNI 对得上，
   * 但证明不了凭证有效，也代表不了客户本地网络。这一点会在返回里明说，
   * 免得到时候把「测速通过」当成「客户能用」。
   */
  router.post('/api/admin/lines/probe', async (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as { ids?: string[]; timeoutMs?: number };
    const timeoutMs = Math.min(Math.max(Number(body.timeoutMs ?? 4000), 1000), 15000);
    const targets = store.data.lines.filter((line) => !body.ids || body.ids.includes(line.id));

    const jobs = targets.map((line) => {
      const stored = store.data.credentials.find((c) => c.id === line.credentialId);
      let credential: LineCredential | null = null;
      if (stored) {
        try {
          credential = openWithMaster<LineCredential>(keys.masterKey, stored.nonce, stored.ciphertext, `cred:${stored.id}`);
        } catch {
          credential = null;
        }
      }
      return { line, target: probeTargetOf(credential, { server: line.server, port: line.port }) };
    });

    const outcomes = await probeMany<{ line: Line; target: ProbeTarget }>(
      jobs,
      (job) => probeLine(job.target, timeoutMs),
      8,
    );

    const results = outcomes.map(({ item, outcome }) => {
      return { lineId: item.line.id, name: item.line.name, server: item.line.server, port: item.line.port, ...outcome };
    });

    store.mutate((db) => {
      for (const result of results) {
        db.probes[result.lineId] = {
          ok: result.ok,
          kind: result.kind,
          rttMs: result.rttMs,
          error: result.error,
          at: result.at,
        };
      }
    });
    store.audit({
      actor,
      action: 'PROBE_LINES',
      target: 'lines',
      reason: '线路测速',
      result: 'ok',
      detail: `total=${results.length} failed=${results.filter((r) => !r.ok).length}`,
    });

    return {
      body: {
        ok: true,
        results,
        summary: {
          total: results.length,
          reachable: results.filter((r) => r.ok).length,
          failed: results.filter((r) => !r.ok).length,
        },
        scope: '云端到节点的 TCP/TLS 握手；不代表客户本地链路与凭证有效性',
      },
    };
  });

  router.get('/api/admin/access-accounts', (ctx) => {
    requireAdmin(ctx);
    return {
      body: {
        ok: true,
        accessControl: store.data.accessControl,
        accounts: store.data.accessAccounts.map((account) => ({
          id: account.id,
          username: account.username,
          displayName: account.displayName,
          lineId: account.lineId,
          enabled: account.enabled,
          expiresAt: account.expiresAt,
          revokedAt: account.revokedAt,
        })),
        trustedDevices: store.data.trustedDevices,
        capacity: (() => {
          const device = store.data.devices[0];
          // 设备还没注册时按默认池估算，避免后台显示成「0 个地址」吓人
          const pool = device
            ? poolCapacity(device.lan.dhcpStart, device.lan.dhcpEnd)
            : poolCapacity('192.168.10.50', '192.168.10.250');
          const enabled = store.data.accessAccounts.filter((a) => a.enabled && !a.revokedAt);
          const perLine = new Map<string, number>();
          for (const account of enabled) perLine.set(account.lineId, (perLine.get(account.lineId) ?? 0) + 1);
          // 一条线路挂多个账号 = 共用同一个出口 IP，和「一人一 IP」卖点冲突，必须提示
          const shared = [...perLine.entries()].filter(([, count]) => count > 1);
          return {
            dhcpPool: pool,
            enabledAccounts: enabled.length,
            enough: pool >= enabled.length,
            sharedLines: shared.map(([lineId, count]) => ({ lineId, accounts: count })),
          };
        })(),
      },
    };
  });

  router.post('/api/admin/access-accounts', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as {
      username?: string;
      password?: string;
      displayName?: string;
      lineId?: string;
      expiresAt?: string | null;
    };
    const username = String(body.username ?? '').trim();
    const password = String(body.password ?? '');
    if (!username || username.length < 3) throw new AppError('BAD_REQUEST', '账号至少 3 位');
    if (password.length < 8) throw new AppError('BAD_REQUEST', '密码至少 8 位');
    if (!body.lineId) throw new AppError('BAD_REQUEST', '必须为账号绑定一条线路');
    const line = store.data.lines.find((l) => l.id === body.lineId);
    if (!line) throw new AppError('NOT_FOUND', '线路不存在');
    if (store.data.accessAccounts.some((a) => a.username === username)) {
      throw new AppError('CONFLICT', '账号已存在');
    }
    const account = {
      id: `acc-${randomHex(4)}`,
      username,
      displayName: String(body.displayName ?? username),
      passwordHash: hashPassword(password),
      lineId: line.id,
      enabled: true,
      expiresAt: body.expiresAt ?? null,
      revokedAt: null,
    };
    store.mutate((db) => {
      db.accessAccounts.push(account);
    });
    const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
    if (target) store.bumpRevision(target.id, `新增接入账号 ${username}`);
    store.audit({
      actor,
      action: 'CREATE_ACCESS_ACCOUNT',
      target: account.id,
      reason: '开通接入账号',
      result: 'ok',
      detail: `username=${username} line=${line.id}`,
    });
    return { body: { ok: true, account: { ...account, passwordHash: undefined } } };
  });

  router.patch('/api/admin/access-accounts/:id', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as { enabled?: boolean; revokedAt?: string | null; expiresAt?: string | null };
    const account = store.data.accessAccounts.find((a) => a.id === ctx.params.id);
    if (!account) throw new AppError('NOT_FOUND', '账号不存在');
    store.mutate(() => {
      if (typeof body.enabled === 'boolean') account.enabled = body.enabled;
      if (body.revokedAt !== undefined) account.revokedAt = body.revokedAt;
      if (body.expiresAt !== undefined) account.expiresAt = body.expiresAt;
    });
    const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
    if (target) store.bumpRevision(target.id, `更新接入账号 ${account.username}`);
    store.audit({
      actor,
      action: 'UPDATE_ACCESS_ACCOUNT',
      target: account.id,
      reason: '变更接入账号状态',
      result: 'ok',
      detail: JSON.stringify(body),
    });
    return { body: { ok: true } };
  });

  router.post('/api/admin/access-mode', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as { mode?: 'device_binding' | 'session'; graceMinutes?: number };
    if (body.mode !== 'device_binding' && body.mode !== 'session') {
      throw new AppError('BAD_REQUEST', '模式只能是 device_binding 或 session');
    }
    /*
     * 切到会话模式前必须已经有可用账号：否则编译出的配置没有任何入站，
     * 用户连上网会「Wi-Fi 已连接但完全打不开」，比不改还糟。
     */
    if (body.mode === 'session' && store.data.accessAccounts.filter((a) => a.enabled && !a.revokedAt).length === 0) {
      throw new AppError('CONFLICT', '请先创建至少一个启用的接入账号，再切到账号接入模式');
    }
    store.mutate((db) => {
      db.accessControl = {
        ...db.accessControl,
        mode: body.mode!,
        graceMinutes: body.graceMinutes ?? db.accessControl.graceMinutes,
      };
    });
    const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
    if (target) store.bumpRevision(target.id, `接入模式切换为 ${body.mode}`);
    store.audit({
      actor,
      action: 'SET_ACCESS_MODE',
      target: 'access-control',
      reason: '切换接入模式',
      result: 'ok',
      detail: body.mode,
    });
    return { body: { ok: true, accessControl: store.data.accessControl } };
  });

  /* ------------------------------------------------------- 批量导入 */

  router.post('/api/admin/import/lines', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as { csv?: string; overwrite?: boolean };
    const parsed = parseLinesCsv(String(body.csv ?? ''));
    const results: ImportRowResult[] = [...parsed.errors];
    for (const row of parsed.rows) {
      const exists = store.data.lines.some((l) => l.id === row.id);
      if (exists && !body.overwrite) {
        results.push({ line: row.line, status: 'skipped', message: `线路 ${row.id} 已存在（未勾选覆盖）` });
        continue;
      }
      let credential: LineCredential;
      try {
        credential = LineCredential.parse(row.credential);
      } catch {
        results.push({ line: row.line, status: 'error', message: '凭证字段不完整或格式不对' });
        continue;
      }
      const credentialId = `cred-${row.id}`;
      const sealed = sealWithMaster(keys.masterKey, credential, `cred:${credentialId}`);
      const line: Line = {
        id: row.id,
        name: row.name,
        region: row.region,
        kind: credential.kind,
        server: row.server,
        port: row.port,
        enabled: true,
        credentialId,
      };
      store.mutate((db) => {
        db.lines = db.lines.filter((l) => l.id !== line.id);
        db.credentials = db.credentials.filter((c) => c.id !== credentialId);
        db.lines.push(line);
        db.credentials.push({
          id: credentialId,
          lineId: line.id,
          keyVersion: 1,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
          rotatedAt: new Date().toISOString(),
        });
      });
      results.push({ line: row.line, status: exists ? 'created' : 'created', message: `已写入 ${line.id}` });
    }
    const created = results.filter((r) => r.status === 'created').length;
    if (created > 0) {
      const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
      if (target) store.bumpRevision(target.id, `批量导入 ${created} 条线路`);
    }
    store.audit({
      actor,
      action: 'IMPORT_LINES',
      target: 'lines',
      reason: '批量导入线路',
      result: results.some((r) => r.status === 'error') ? 'failed' : 'ok',
      detail: `created=${created} skipped=${results.filter((r) => r.status === 'skipped').length} error=${results.filter((r) => r.status === 'error').length}`,
    });
    return { body: { ok: true, created, results } };
  });

  router.post('/api/admin/import/accounts', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as { csv?: string };
    const parsed = parseAccountsCsv(String(body.csv ?? ''));
    const results: ImportRowResult[] = [...parsed.errors];
    const existing = new Set(store.data.accessAccounts.map((a) => a.username));
    const lineIds = new Set(store.data.lines.map((l) => l.id));
    const toCreate: typeof store.data.accessAccounts = [];
    for (const row of parsed.rows) {
      if (existing.has(row.username)) {
        results.push({ line: row.line, status: 'skipped', message: `账号 ${row.username} 已存在` });
        continue;
      }
      if (!lineIds.has(row.lineId)) {
        results.push({ line: row.line, status: 'error', message: `线路不存在：${row.lineId}` });
        continue;
      }
      toCreate.push({
        id: `acc-${randomHex(4)}`,
        username: row.username,
        displayName: row.displayName,
        passwordHash: hashPassword(row.password),
        lineId: row.lineId,
        enabled: true,
        expiresAt: row.expiresAt,
        revokedAt: null,
      });
      existing.add(row.username);
      results.push({ line: row.line, status: 'created', message: `已开通 ${row.username} → ${row.lineId}` });
    }
    if (toCreate.length > 0) {
      store.mutate((db) => {
        db.accessAccounts.push(...toCreate);
      });
      const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
      if (target) store.bumpRevision(target.id, `批量开通 ${toCreate.length} 个账号`);
    }
    store.audit({
      actor,
      action: 'IMPORT_ACCESS_ACCOUNTS',
      target: 'access-accounts',
      reason: '批量开通接入账号',
      result: results.some((r) => r.status === 'error') ? 'failed' : 'ok',
      detail: `created=${toCreate.length}`,
    });
    return { body: { ok: true, created: toCreate.length, results } };
  });

  /**
   * 粘贴分享链接 → 自动识别协议 → 一条线路一个账号（jy001…jy100）
   *
   * 这个接口是「开一百台手机」的唯一入口：机场/自建给的链接直接粘进来，
   * 不需要人工拆成表格，也不会因为一条写错就整批失败。
   */
  router.post('/api/admin/import/nodes', (ctx) => {
    const actor = requireAdmin(ctx);
    const body = (ctx.json ?? {}) as {
      text?: string;
      idPrefix?: string;
      accountPrefix?: string;
      createAccounts?: boolean;
      switchMode?: boolean;
      /** 统一密码：留空则每个账号随机生成 10 位 */
      password?: string;
    };
    const parsed = parseNodeList(String(body.text ?? ''), { idPrefix: body.idPrefix || 'line' });
    const fixedPassword = String(body.password ?? '').trim();
    if (fixedPassword && fixedPassword.length < 8) {
      throw new AppError('BAD_REQUEST', '统一密码至少 8 位');
    }
    const accountPrefix = (body.accountPrefix || 'jy').trim();
    const wantAccounts = body.createAccounts !== false;

    const created: { id: string; name: string; kind: string; server: string; port: number }[] = [];
    const accountRows: { username: string; password: string; lineId: string; lineName: string }[] = [];
    const skipped: { index: number; message: string }[] = [];
    const usedIds = new Set(store.data.lines.map((l) => l.id));
    const usedNames = new Set(store.data.accessAccounts.map((a) => a.username));
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    const newLines: Line[] = [];
    const newCreds: StoredCredential[] = [];
    const newAccounts = [] as typeof store.data.accessAccounts;

    for (const node of parsed.nodes) {
      // 同服务器同端口视为同一条线路：重复导入时复用，避免账号绑到看不见的线路上
      const existing = store.data.lines.find(
        (l) => l.server === node.server && l.port === node.port && l.kind === node.credential.kind,
      );
      let lineId = existing?.id ?? node.id;
      if (!existing) {
        let suffix = 1;
        while (usedIds.has(lineId)) {
          suffix += 1;
          lineId = `${node.id}-${suffix}`;
        }
        usedIds.add(lineId);
        const credentialId = `cred-${lineId}`;
        const sealed = sealWithMaster(keys.masterKey, node.credential, `cred:${credentialId}`);
        newLines.push({
          id: lineId,
          name: node.name,
          region: node.region,
          kind: node.credential.kind,
          server: node.server,
          port: node.port,
          enabled: true,
          credentialId,
        });
        newCreds.push({
          id: credentialId,
          lineId,
          keyVersion: 1,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
          rotatedAt: new Date().toISOString(),
        });
      }

      if (wantAccounts) {
        // 位数按本批节点总数决定：100 条 → jy001…jy100，不会出现 jy0001
        const username = accountNameFor(accountPrefix, accountRows.length + 1, parsed.nodes.length);
        if (usedNames.has(username)) {
          skipped.push({ index: node.index, message: `账号 ${username} 已存在，线路 ${lineId} 未配账号` });
          continue;
        }
        usedNames.add(username);
        let password = '';
        if (fixedPassword) {
          password = fixedPassword;
        } else {
          for (let i = 0; i < 10; i += 1) password += alphabet[randomInt(alphabet.length)];
        }
        newAccounts.push({
          id: `acc-${randomHex(4)}`,
          username,
          displayName: node.name,
          passwordHash: hashPassword(password),
          lineId,
          enabled: true,
          expiresAt: null,
          revokedAt: null,
        });
        accountRows.push({ username, password, lineId, lineName: node.name });
      }
      created.push({ id: lineId, name: node.name, kind: node.credential.kind, server: node.server, port: node.port });
    }

    if (newLines.length > 0 || newAccounts.length > 0) {
      store.mutate((db) => {
        db.lines.push(...newLines);
        db.credentials.push(...newCreds);
        db.accessAccounts.push(...newAccounts);
        if (body.switchMode !== false && db.accessAccounts.some((a) => a.enabled && !a.revokedAt)) {
          db.accessControl = { ...db.accessControl, mode: 'session' };
        }
      });
      const target = store.data.devices.find((d) => d.organizationId === store.data.organization.id);
      if (target) store.bumpRevision(target.id, `导入 ${created.length} 条线路与 ${newAccounts.length} 个账号`);
    }

    store.audit({
      actor,
      action: 'IMPORT_NODES',
      target: 'lines',
      reason: '粘贴分享链接批量开通',
      result: parsed.errors.length > 0 ? 'failed' : 'ok',
      detail: `lines=${newLines.length} accounts=${newAccounts.length} errors=${parsed.errors.length} dup=${parsed.duplicates.length}`,
    });

    return {
      body: {
        ok: true,
        detected: parsed.nodes.length,
        linesCreated: newLines.length,
        linesReused: created.length - newLines.length,
        accounts: accountRows,
        created,
        errors: parsed.errors,
        duplicates: parsed.duplicates,
        skipped,
        mode: store.data.accessControl.mode,
        /** 口令只在这里返回一次，之后不再可读 */
        hint: '账号口令仅本次返回，请立即复制保存；密码不会二次展示',
      },
    };
  });

  router.get('/api/admin/audit-logs', (ctx) => {
    requireAdmin(ctx);
    const limit = Math.min(Number(ctx.query.get('limit') ?? 100), 500);
    return { body: { ok: true, logs: store.data.audit.slice(-limit).reverse() } };
  });

  function nextClientIp(deviceId: string): string {
    const device = store.requireDevice(deviceId);
    const used = new Set(store.clientsOf(deviceId).map((c) => c.ipAddress));
    const base = device.lan.gateway.split('.').slice(0, 3).join('.');
    for (let host = 20; host < 100; host += 1) {
      const candidate = `${base}.${host}`;
      if (!used.has(candidate)) return candidate;
    }
    throw new AppError('CONFLICT', '局域网地址池已用尽');
  }

  const server = serve(router, { port: config.port, host: config.host, label: 'control' });

  return { router, store, keys, server, issueCommand, buildBundle };
}

