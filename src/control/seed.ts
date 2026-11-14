/**
 * 演示/联调种子数据
 *
 * 真实部署里这些内容来自管理后台，这里只是让「注册 → 下发 → 编译 → 应用」
 * 这条链路在没有后台 UI 的情况下也能跑起来。
 *
 * 注意：口令用 scrypt 哈希，线路凭证经 master key 加密后落盘，
 * 种子文件里出现的明文只存在于这个函数的局部变量作用域内。
 */
import { hashPassword, randomToken, sha256Hex } from '../core/crypto.ts';
import type { FailoverPolicy, Line, LineCredential, LineGroup, RouteProfile } from '../core/schema.ts';
import { sealWithMaster, type CloudKeys } from './keys.ts';
import type { Store } from './store.ts';

export type SeedResult = { deviceId: string; enrollmentToken: string };

const DEMO_CREDENTIALS: Record<string, LineCredential> = {
  'cred-hk-vless': {
    kind: 'vless',
    uuid: '8f3a1c2e-9a44-4d21-b7c3-51a0d2e6f901',
    flow: 'xtls-rprx-vision',
    tls: {
      serverName: 'hk1.line.example',
      alpn: ['h2', 'http/1.1'],
      allowInsecure: false,
      fingerprint: 'chrome',
      reality: { publicKey: 'mZ3kR2pQ8sT1vW4xY7aB0cD3eF6gH9jK2lM5nO8pQ1r=', shortId: 'a1b2c3d4' },
    },
    transport: { type: 'tcp' },
  },
  'cred-sg-trojan': {
    kind: 'trojan',
    password: 'Tj-SG-7xK2pQ9m',
    tls: { serverName: 'sg1.line.example', alpn: ['h2'], allowInsecure: false },
    transport: { type: 'ws', path: '/ray', host: 'sg1.line.example' },
  },
  'cred-us-ss': { kind: 'shadowsocks', method: 'aes-256-gcm', password: 'Ss-US-4mN8vB2x' },
};

const DEMO_LINES: Line[] = [
  {
    id: 'line-hk-1',
    name: '香港-01',
    region: '香港',
    kind: 'vless',
    server: '45.32.11.20',
    port: 443,
    enabled: true,
    credentialId: 'cred-hk-vless',
  },
  {
    id: 'line-sg-1',
    name: '新加坡-01',
    region: '新加坡',
    kind: 'trojan',
    server: '128.199.44.7',
    port: 443,
    enabled: true,
    credentialId: 'cred-sg-trojan',
  },
  {
    id: 'line-us-1',
    name: '洛杉矶-01',
    region: '美国',
    kind: 'shadowsocks',
    server: '104.224.8.55',
    port: 8388,
    enabled: true,
    credentialId: 'cred-us-ss',
  },
];

const DEMO_GROUPS: LineGroup[] = [
  { id: 'group-hk', name: '香港主备（港→新）', lineIds: ['line-hk-1', 'line-sg-1'], failoverPolicyId: 'fo-default' },
  { id: 'group-us', name: '美国专线', lineIds: ['line-us-1'], failoverPolicyId: 'fo-default' },
];

const DEMO_PROFILES: RouteProfile[] = [
  {
    id: 'profile-strict',
    name: '严格全局代理',
    mode: 'strict_global',
    primaryLineGroupId: 'group-hk',
    rules: [
      {
        id: 'rule-block-p2p',
        priority: 10,
        enabled: true,
        action: 'block',
        match: {
          port: [6881, 6882, 51413],
          domainSuffix: [],
          domainKeyword: [],
          ipCidr: [],
          clientIds: [],
          network: [],
        },
      },
    ],
  },
  {
    id: 'profile-cn',
    name: '大陆直连 / 其他代理',
    mode: 'cn_direct',
    primaryLineGroupId: 'group-hk',
    rules: [],
  },
];

const DEMO_POLICY: FailoverPolicy[] = [
  {
    id: 'fo-default',
    failureThreshold: 3,
    recoveryThreshold: 5,
    cooldownSeconds: 120,
    maxSwitchesPerHour: 4,
    probeIntervalSeconds: 30,
    probeTimeoutMs: 3000,
  },
];

export function seedDemo(
  store: Store,
  keys: CloudKeys,
  options: { deviceId?: string; tokenTtlMinutes?: number } = {},
): SeedResult {
  const deviceId = options.deviceId ?? 'dev-ax3000t-001';
  const token = randomToken(24);
  const tokenHash = sha256Hex(token);
  const expiresAt = new Date(Date.now() + (options.tokenTtlMinutes ?? 120) * 60 * 1000).toISOString();
  const now = new Date().toISOString();

  const credentials = Object.entries(DEMO_CREDENTIALS).map(([id, credential]) => {
    const line = DEMO_LINES.find((l) => l.credentialId === id);
    const sealed = sealWithMaster(keys.masterKey, credential, `cred:${id}`);
    return {
      id,
      lineId: line?.id ?? id,
      keyVersion: 1,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
      rotatedAt: now,
    };
  });

  store.seedDemo({
    deviceId,
    enrollmentTokenHash: tokenHash,
    tokenExpiresAt: expiresAt,
    tokenPlainHint: token,
    lines: DEMO_LINES,
    credentials,
    groups: DEMO_GROUPS,
    profiles: DEMO_PROFILES,
    failoverPolicies: DEMO_POLICY,
    portalAccounts: [
      {
        id: 'pa-admin',
        username: 'admin',
        displayName: '玖夜',
        role: 'device_admin',
        passwordHash: hashPassword('admin12345'),
        disabled: false,
      },
      {
        id: 'pa-client',
        username: 'client01',
        displayName: '客户 A',
        role: 'customer',
        passwordHash: hashPassword('client12345'),
        disabled: false,
      },
    ],
    accessAccounts: [
      {
        id: 'acc-demo-1',
        username: 'us01',
        displayName: '美国专线 01',
        passwordHash: hashPassword('us01-pass-123'),
        lineId: 'line-us-1',
        enabled: true,
        expiresAt: null,
        revokedAt: null,
      },
      {
        id: 'acc-demo-2',
        username: 'hk01',
        displayName: '香港线路 01',
        passwordHash: hashPassword('hk01-pass-123'),
        lineId: 'line-hk-1',
        enabled: true,
        expiresAt: null,
        revokedAt: null,
      },
    ],
    trustedDevices: [
      { id: 'td-encoder-1', label: '直播间编码器（演示）', macHash: 'sha256:demo-encoder', lineId: 'line-us-1' },
    ],
    clients: [
      {
        id: 'cl-codec',
        deviceId,
        label: '直播间-编码器',
        hostname: 'codec-01',
        macHash: 'sha256:0a1b2c3d',
        ipAddress: '192.168.10.20',
        state: 'pending',
        confidence: 'high',
        attachInterface: 'lan',
        firstSeenAt: now,
        lastSeenAt: now,
      },
      {
        id: 'cl-camera',
        deviceId,
        label: '摄像机-B',
        hostname: 'cam-b',
        macHash: 'sha256:4e5f6a7b',
        ipAddress: '192.168.10.21',
        state: 'pending',
        confidence: 'low',
        attachInterface: 'wifi',
        firstSeenAt: now,
        lastSeenAt: now,
      },
      {
        id: 'cl-laptop',
        deviceId,
        label: '笔记本（待授权）',
        hostname: 'macbook-pro',
        macHash: 'sha256:8c9d0e1f',
        ipAddress: '192.168.10.31',
        state: 'pending',
        confidence: 'low',
        attachInterface: 'wifi',
        firstSeenAt: now,
        lastSeenAt: now,
      },
    ],
    bindings: [],
  });

  // 演示：编码器已由客户在门户授权到严格全局策略
  store.mutate((db) => {
    db.bindings.push({
      id: 'bind-codec',
      deviceId,
      clientId: 'cl-codec',
      routeProfileId: 'profile-strict',
      validFrom: now,
      validUntil: null,
      revokedAt: null,
      version: 1,
    });
    const codec = db.clients.find((c) => c.id === 'cl-codec');
    if (codec) codec.state = 'authorized';
  });

  return { deviceId, enrollmentToken: token };
}
