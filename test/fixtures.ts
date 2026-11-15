/**
 * 测试夹具：一台真实形状的软路由配置
 *
 * 刻意做得「像真的」而不是最小化：两条可用线路 + 一条备用、三种分流模式、
 * 一台已授权的有线编码器、一台已授权的无线摄像机、一台待授权笔记本。
 */
import { hashPassword } from '../src/core/crypto.ts';
import type { DesiredState, Line, LineCredential } from '../src/core/schema.ts';

export const CREDENTIALS: Record<string, LineCredential> = {
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
  'cred-us-ss': {
    kind: 'shadowsocks',
    method: 'aes-256-gcm',
    password: 'Ss-US-4mN8vB2x',
  },
  'cred-wg-backup': {
    kind: 'wireguard',
    privateKey: 'WGpriv+9xQ2mK7pL4vN8bR1tY6uI3oP0aS5dF2gH7jK9lM=',
    peerPublicKey: 'WGpub+1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5c=',
    localAddress: '10.66.0.2/32',
    mtu: 1420,
  },
};

export const WIFI_PSK = 'LinkPilot-2026';

export const LINES: Line[] = [
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

export function buildFixtureState(overrides: Partial<DesiredState> = {}): DesiredState {
  const now = '2026-11-14T00:00:00.000Z';
  const state: DesiredState = {
    deviceId: 'dev-ax3000t-001',
    organizationId: 'org-jiuye',
    revision: 7,
    generatedAt: now,
    lan: {
      gateway: '192.168.10.1',
      cidr: '192.168.10.0/24',
      dhcpStart: '192.168.10.50',
      dhcpEnd: '192.168.10.250',
      portalPort: 8080,
      controlPort: 8081,
      wanInterface: 'wan',
      lanInterface: 'br-lan',
      // 夹具按 ARM 一体机形态：网桥由设备树固化，x86 用例自行覆盖
      lanPorts: [],
      wanPort: '',
      allowClientToClient: true,
      managementPorts: [22],
      allowWanManagement: false,
      tunName: 'lp-tun',
      tunCidr: '172.19.0.1/30',
      dnsPort: 5353,
      ipv6Enabled: false,
    },
    wifi: { enabled: true, ssid: 'LinkPilot-WiFi', hidden: false, band: '2.4+5' },
    // 默认按设备绑定模式：会话模式由专门用例覆盖
    accessControl: { mode: 'device_binding', graceMinutes: 5, loginPath: '/login' },
    accessAccounts: [],
    trustedDevices: [],
    portalAccounts: [
      {
        id: 'pa-1',
        username: 'admin',
        displayName: '玖夜',
        role: 'device_admin',
        passwordHash: hashPassword('admin12345'),
        disabled: false,
      },
      {
        id: 'pa-2',
        username: 'client01',
        displayName: '客户 A',
        role: 'customer',
        passwordHash: hashPassword('client12345'),
        disabled: false,
      },
    ],
    clients: [
      {
        id: 'cl-codec',
        label: '直播间-编码器',
        hostname: 'codec-01',
        macHash: 'sha256:0a1b2c3d',
        ipAddress: '192.168.10.20',
        state: 'authorized',
        confidence: 'high',
        attachInterface: 'lan',
        firstSeenAt: now,
        lastSeenAt: now,
      },
      {
        id: 'cl-camera',
        label: '摄像机-B',
        hostname: 'cam-b',
        macHash: 'sha256:4e5f6a7b',
        ipAddress: '192.168.10.21',
        state: 'authorized',
        confidence: 'low',
        attachInterface: 'wifi',
        firstSeenAt: now,
        lastSeenAt: now,
      },
      {
        id: 'cl-laptop',
        label: '笔记本（未授权）',
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
    bindings: [
      {
        id: 'bind-codec',
        clientId: 'cl-codec',
        routeProfileId: 'profile-strict',
        validFrom: '2026-11-01T00:00:00.000Z',
        validUntil: null,
        revokedAt: null,
        version: 2,
      },
      {
        id: 'bind-camera',
        clientId: 'cl-camera',
        routeProfileId: 'profile-cn',
        validFrom: '2026-11-01T00:00:00.000Z',
        validUntil: '2027-11-01T00:00:00.000Z',
        revokedAt: null,
        version: 1,
      },
    ],
    routeProfiles: [
      {
        id: 'profile-strict',
        name: '严格全局代理',
        mode: 'strict_global',
        primaryLineGroupId: 'group-hk',
        rules: [
          {
            id: 'rule-block-torrent',
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
        name: '大陆直连/其他代理',
        mode: 'cn_direct',
        primaryLineGroupId: 'group-hk',
        rules: [],
      },
    ],
    lineGroups: [
      {
        id: 'group-hk',
        name: '香港主备',
        lineIds: ['line-hk-1', 'line-sg-1'],
        failoverPolicyId: 'fo-default',
      },
      { id: 'group-us', name: '美国专线', lineIds: ['line-us-1'], failoverPolicyId: 'fo-default' },
    ],
    lines: LINES,
    failoverPolicies: [
      {
        id: 'fo-default',
        failureThreshold: 3,
        recoveryThreshold: 5,
        cooldownSeconds: 120,
        maxSwitchesPerHour: 4,
        probeIntervalSeconds: 30,
        probeTimeoutMs: 3000,
      },
    ],
  };
  return { ...state, ...overrides };
}
