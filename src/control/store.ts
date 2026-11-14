/**
 * 云端存储：JSON 文件 + 原子写
 *
 * 为什么不上数据库：Phase 1 的目标是「先把闭环跑通并且可审计」。
 * 这里的接口刻意按仓储（repository）形态设计，换成 PostgreSQL 时
 * 只需要替换 Store 的实现，业务层不用改。
 *
 * 三条硬约束：
 * 1. 线路凭证只以密文落盘（master key 加密），数据库泄露不等于凭证泄露；
 * 2. 部署、探针、审计只追加，不覆盖；
 * 3. 每次写盘走临时文件 + rename，避免断电留下半截 JSON。
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomHex } from '../core/crypto.ts';
import type { AccessAccountRecord, AccessControlConfig, TrustedDeviceRecord } from '../core/schema.ts';
import type {
  Client,
  DeviceCommand,
  DeviceRouteBinding,
  FailoverPolicy,
  LanConfig,
  Line,
  LineGroup,
  PortalAccount,
  RouteProfile,
  WifiConfig,
} from '../core/schema.ts';

export type DeviceStateName = 'active' | 'maintenance' | 'revoked' | 'quarantined';

export type DeviceRecord = {
  id: string;
  organizationId: string;
  model: string;
  hardwareFingerprint: string;
  agentVersion: string;
  ed25519PublicKey: string;
  x25519PublicKey: string;
  state: DeviceStateName;
  enrolledAt: string;
  lastSeenAt: string | null;
  lastHeartbeatAt: string | null;
  /** 云端已签发到的版本号；每次业务变更 +1 */
  revision: number;
  observedRevision: number;
  health: 'healthy' | 'degraded' | 'failed' | 'maintenance' | 'unknown';
  proxyRunning: boolean;
  resources: {
    cpuLoad1: number;
    memoryUsedMb: number;
    memoryTotalMb: number;
    temperatureC: number | null;
    diskFreeMb: number;
  } | null;
  lastApplyResult: string;
  hardware: {
    model: string;
    arch: string;
    cpuModel: string;
    cpuCores: number;
    memoryTotalMb: number;
    hasWifi: boolean;
    nics: string[];
    initSystem: string;
    kernel: string;
  } | null;
  lan: LanConfig;
  wifi: WifiConfig;
};

export type EnrollmentTokenRecord = {
  tokenHash: string;
  organizationId: string;
  deviceId: string;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
};

export type StoredCredential = {
  id: string;
  lineId: string;
  keyVersion: number;
  /** master key 加密后的线路凭证 */
  nonce: string;
  ciphertext: string;
  rotatedAt: string;
};

export type ClientRecord = Client & { deviceId: string };
export type BindingRecord = DeviceRouteBinding & { deviceId: string };

export type RevisionRecord = {
  id: string;
  deviceId: string;
  revision: number;
  digest: string;
  createdAt: string;
  reason: string;
};

export type ObservedRecord = {
  id: string;
  deviceId: string;
  revision: number;
  revisionId: string;
  appliedAt: string;
  status: 'succeeded' | 'failed' | 'rolled_back';
  artifactDigest: string;
  steps: { name: string; status: string; detail: string; durationMs: number }[];
  rollbackTo: number | null;
};

export type AuditRecord = {
  id: string;
  at: string;
  actor: string;
  action: string;
  target: string;
  reason: string;
  result: 'ok' | 'failed';
  detail: string;
};

export type CloudDb = {
  schemaVersion: number;
  organization: { id: string; name: string };
  devices: DeviceRecord[];
  tokens: EnrollmentTokenRecord[];
  lines: Line[];
  credentials: StoredCredential[];
  lineGroups: LineGroup[];
  routeProfiles: RouteProfile[];
  failoverPolicies: FailoverPolicy[];
  clients: ClientRecord[];
  bindings: BindingRecord[];
  portalAccounts: PortalAccount[];
  /** 接入模式与接入账号（单 SSID + 账号登录 → 出口线路） */
  accessControl: AccessControlConfig;
  accessAccounts: AccessAccountRecord[];
  /** 预授权设备：编码器/NVR 这类没有浏览器的终端 */
  trustedDevices: TrustedDeviceRecord[];
  commands: DeviceCommand[];
  revisions: RevisionRecord[];
  observed: ObservedRecord[];
  /** 线路最近一次探测结果（云端侧 TCP/TLS 握手） */
  probes: Record<string, { ok: boolean; kind: 'tcp' | 'tls'; rttMs: number | null; error: string | null; at: string }>;
  audit: AuditRecord[];
  /** 无线口令等设备级秘密，master key 加密 */
  deviceSecrets: { deviceId: string; wifiNonce: string; wifiCiphertext: string }[];
};

export function emptyDb(): CloudDb {
  return {
    schemaVersion: 1,
    organization: { id: 'org-jiuye', name: '玖夜网络科技（演示）' },
    devices: [],
    tokens: [],
    lines: [],
    credentials: [],
    lineGroups: [],
    routeProfiles: [],
    failoverPolicies: [],
    clients: [],
    bindings: [],
    portalAccounts: [],
    accessControl: { mode: 'device_binding', graceMinutes: 5, loginPath: '/login' },
    accessAccounts: [],
    trustedDevices: [],
    commands: [],
    revisions: [],
    observed: [],
    probes: {},
    audit: [],
    deviceSecrets: [],
  };
}

export class Store {
  readonly dir: string;
  private readonly file: string;
  private db: CloudDb;

  constructor(dir: string) {
    this.dir = dir;
    this.file = path.join(dir, 'cloud-db.json');
    fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(this.file)) {
      this.db = JSON.parse(fs.readFileSync(this.file, 'utf8')) as CloudDb;
      // 老数据没有新字段：补齐默认值，避免读到 undefined 后到处判空
      this.db.probes = this.db.probes ?? {};
      this.db.accessControl = this.db.accessControl ?? { mode: 'device_binding', graceMinutes: 5, loginPath: '/login' };
      this.db.accessAccounts = this.db.accessAccounts ?? [];
      this.db.trustedDevices = this.db.trustedDevices ?? [];
    } else {
      this.db = emptyDb();
      this.flush();
    }
  }

  get data(): CloudDb {
    return this.db;
  }

  mutate<T>(fn: (db: CloudDb) => T): T {
    const result = fn(this.db);
    this.flush();
    return result;
  }

  private flush(): void {
    const tmp = `${this.file}.${randomHex(4)}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.db, null, 2), 'utf8');
    fs.renameSync(tmp, this.file);
  }

  /* -------------------------------------------------------------- 设备 */

  device(id: string): DeviceRecord | undefined {
    return this.db.devices.find((d) => d.id === id);
  }

  requireDevice(id: string): DeviceRecord {
    const device = this.device(id);
    if (!device) throw new Error(`设备不存在: ${id}`);
    return device;
  }

  clientsOf(deviceId: string): ClientRecord[] {
    return this.db.clients.filter((c) => c.deviceId === deviceId);
  }

  bindingsOf(deviceId: string): BindingRecord[] {
    return this.db.bindings.filter((b) => b.deviceId === deviceId);
  }

  commandsOf(deviceId: string): DeviceCommand[] {
    return this.db.commands.filter((c) => c.deviceId === deviceId);
  }

  /** 业务变更 → 提升版本号，触发设备重新拉取 */
  bumpRevision(deviceId: string, reason: string, digestHint = ''): RevisionRecord {
    return this.mutate((db) => {
      const device = db.devices.find((d) => d.id === deviceId);
      if (!device) throw new Error(`设备不存在: ${deviceId}`);
      device.revision += 1;
      const record: RevisionRecord = {
        id: `rev-${deviceId}-${device.revision}`,
        deviceId,
        revision: device.revision,
        digest: digestHint,
        createdAt: new Date().toISOString(),
        reason,
      };
      db.revisions.push(record);
      return record;
    });
  }

  audit(entry: Omit<AuditRecord, 'id' | 'at'>): void {
    this.mutate((db) => {
      db.audit.push({ id: `aud-${randomHex(6)}`, at: new Date().toISOString(), ...entry });
      // 审计只保留最近 2000 条，超出部分应落到外部日志系统（Phase 4）
      if (db.audit.length > 2000) db.audit.splice(0, db.audit.length - 2000);
    });
  }

  /* ---------------------------------------------------------- 演示数据 */

  /** 仅用于本地演示：真实部署由管理后台写入 */
  seedDemo(input: {
    deviceId: string;
    enrollmentTokenHash: string;
    tokenExpiresAt: string;
    lines: Line[];
    credentials: StoredCredential[];
    groups: LineGroup[];
    profiles: RouteProfile[];
    failoverPolicies: FailoverPolicy[];
    portalAccounts: PortalAccount[];
    clients: ClientRecord[];
    bindings: BindingRecord[];
    /** 演示用的接入账号与预授权设备；不传则留空 */
    accessAccounts?: AccessAccountRecord[];
    trustedDevices?: TrustedDeviceRecord[];
    tokenPlainHint: string;
  }): void {
    this.mutate((db) => {
      db.tokens = db.tokens.filter((t) => t.deviceId !== input.deviceId);
      db.tokens.push({
        tokenHash: input.enrollmentTokenHash,
        organizationId: db.organization.id,
        deviceId: input.deviceId,
        createdAt: new Date().toISOString(),
        expiresAt: input.tokenExpiresAt,
        usedAt: null,
      });
      db.lines = input.lines;
      db.credentials = input.credentials;
      db.lineGroups = input.groups;
      db.routeProfiles = input.profiles;
      db.failoverPolicies = input.failoverPolicies;
      db.portalAccounts = input.portalAccounts;
      db.accessAccounts = input.accessAccounts ?? [];
      db.trustedDevices = input.trustedDevices ?? [];
      db.clients = input.clients;
      db.bindings = input.bindings;
      db.devices = db.devices.filter((d) => d.id !== input.deviceId);
      db.audit.push({
        id: `aud-${randomHex(6)}`,
        at: new Date().toISOString(),
        actor: 'system:seed',
        action: 'SEED_DEMO',
        target: input.deviceId,
        reason: '本地演示数据初始化',
        result: 'ok',
        detail: `token=${input.tokenPlainHint ? '已生成' : '无'}`,
      });
    });
  }
}
