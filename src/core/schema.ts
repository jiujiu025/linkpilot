/**
 * LinkPilot 领域模型（唯一事实来源）
 *
 * 约束（来自 docs/design）：
 * - 这里只描述业务模型，不出现任何执行器（sing-box/Xray/nftables）的原始配置结构。
 * - 线路凭证不进入 DesiredState 明文，只以 credentialId 引用，运行时由密钥封装下发。
 * - 所有结构都必须是「可编译为本地规则」的确定性输入，不含运行时回调或云端依赖。
 */
import { z } from 'zod';

/* ------------------------------------------------------------------ 基础枚举 */

export const ProtocolKind = z.enum([
  'vless',
  'vmess',
  'trojan',
  'shadowsocks',
  'hysteria2',
  'wireguard',
  'socks5',
  'http',
]);

export const TrafficAction = z.enum(['proxy', 'direct', 'block']);

/** 面向用户的三档分流语义，外加仅诊断可用的全直连 */
export const RouteMode = z.enum(['strict_global', 'cn_direct', 'custom', 'direct_only']);

export const ClientState = z.enum(['pending', 'authorized', 'revoked']);

export const ClientConfidence = z.enum(['high', 'low']);

export const PortalRole = z.enum(['customer', 'device_admin']);

export const DeviceState = z.enum(['active', 'maintenance', 'revoked', 'quarantined']);

/* ---------------------------------------------------------------- 协议参数 */

export const TlsOptions = z.object({
  serverName: z.string().min(1),
  alpn: z.array(z.string().min(1)).default([]),
  allowInsecure: z.boolean().default(false),
  fingerprint: z.string().min(1).optional(),
  reality: z
    .object({
      publicKey: z.string().min(1),
      shortId: z.string().min(1),
    })
    .optional(),
});

export const Transport = z.object({
  type: z.enum(['tcp', 'ws', 'grpc', 'httpupgrade']).default('tcp'),
  path: z.string().optional(),
  host: z.string().optional(),
  serviceName: z.string().optional(),
});

/**
 * 线路凭证。只在两个地方以明文出现：
 * 1. 云端加密前的短暂时窗；
 * 2. 设备侧用 X25519 解开之后的内存中。
 */
export const LineCredential = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('vless'),
    uuid: z.string().min(1),
    flow: z.enum(['', 'xtls-rprx-vision']).default(''),
    tls: TlsOptions.nullable().default(null),
    transport: Transport.default({ type: 'tcp' }),
  }),
  z.object({
    kind: z.literal('vmess'),
    uuid: z.string().min(1),
    /** VMess 的 alterId，AEAD 模式下必须为 0 */
    alterId: z.number().int().min(0).max(64).default(0),
    security: z.enum(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']).default('auto'),
    tls: TlsOptions.nullable().default(null),
    transport: Transport.default({ type: 'tcp' }),
  }),
  z.object({
    kind: z.literal('hysteria2'),
    password: z.string().min(1),
    /** 自签证书的节点必须允许不安全，否则连不上；默认关，由导入时显式声明 */
    tls: TlsOptions.nullable().default(null),
    obfs: z
      .object({ type: z.enum(['salamander']), password: z.string().min(1) })
      .nullable()
      .default(null),
  }),
  z.object({
    kind: z.literal('trojan'),
    password: z.string().min(1),
    tls: TlsOptions,
    transport: Transport.default({ type: 'tcp' }),
  }),
  z.object({
    kind: z.literal('shadowsocks'),
    method: z.enum([
      'aes-128-gcm',
      'aes-256-gcm',
      'chacha20-ietf-poly1305',
      '2022-blake3-aes-128-gcm',
      '2022-blake3-aes-256-gcm',
    ]),
    password: z.string().min(1),
  }),
  z.object({
    kind: z.literal('wireguard'),
    privateKey: z.string().min(1),
    peerPublicKey: z.string().min(1),
    presharedKey: z.string().optional(),
    /** 隧道内侧地址，由线路提供方分配 */
    localAddress: z.string().default('10.66.0.2/32'),
    mtu: z.number().int().min(1280).max(1500).default(1408),
  }),
  z.object({
    kind: z.literal('socks5'),
    username: z.string().optional(),
    password: z.string().optional(),
  }),
  z.object({
    kind: z.literal('http'),
    username: z.string().optional(),
    password: z.string().optional(),
  }),
]);

/* ---------------------------------------------------------------- 线路与策略 */

export const Line = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  /** 对客户展示的地区标签，例如「新加坡」「洛杉矶-家宽」 */
  region: z.string().min(1),
  kind: ProtocolKind,
  server: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  enabled: z.boolean().default(true),
  /** 关联到 secrets.credentials 的键，不含任何明文 */
  credentialId: z.string().min(1),
});

export const LineGroup = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  lineIds: z.array(z.string().min(1)).default([]),
  failoverPolicyId: z.string().min(1),
});

export const FailoverPolicy = z.object({
  id: z.string().min(1),
  failureThreshold: z.number().int().min(1).max(20).default(3),
  recoveryThreshold: z.number().int().min(1).max(20).default(5),
  cooldownSeconds: z.number().int().min(0).max(3600).default(120),
  maxSwitchesPerHour: z.number().int().min(0).max(60).default(4),
  probeIntervalSeconds: z.number().int().min(5).max(600).default(30),
  probeTimeoutMs: z.number().int().min(500).max(30000).default(3000),
});

export const RuleMatch = z.object({
  domainSuffix: z.array(z.string().min(1)).default([]),
  domainKeyword: z.array(z.string().min(1)).default([]),
  ipCidr: z.array(z.string().min(1)).default([]),
  port: z.array(z.number().int().min(1).max(65535)).default([]),
  /** 空数组表示「该 profile 下所有已授权设备」 */
  clientIds: z.array(z.string().min(1)).default([]),
  network: z.array(z.enum(['tcp', 'udp'])).default([]),
});

export const RoutingRule = z.object({
  id: z.string().min(1),
  /** 数字越小越先匹配；同优先级按 id 稳定排序 */
  priority: z.number().int().min(1).max(100000),
  enabled: z.boolean().default(true),
  action: TrafficAction,
  /** action=proxy 时可指定目标线路组，缺省用 profile 的主线路组 */
  lineGroupId: z.string().min(1).optional(),
  match: RuleMatch,
});

export const RouteProfile = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  mode: RouteMode,
  primaryLineGroupId: z.string().min(1),
  rules: z.array(RoutingRule).default([]),
});

/* ------------------------------------------------------------ 客户与授权 */

export const Client = z.object({
  id: z.string().min(1),
  /** 客户可见的标签，例如「直播间-编码器」 */
  label: z.string().min(1),
  hostname: z.string().default(''),
  /** 只保存不可逆摘要，禁止落明文 MAC */
  macHash: z.string().min(1),
  /** 由编译器落成 DHCP 静态租约，编入分流规则 */
  ipAddress: z.string().min(1),
  state: ClientState,
  confidence: ClientConfidence.default('high'),
  attachInterface: z.enum(['lan', 'wifi']).default('lan'),
  firstSeenAt: z.string().min(1),
  lastSeenAt: z.string().min(1),
});

export const DeviceRouteBinding = z.object({
  id: z.string().min(1),
  clientId: z.string().min(1),
  routeProfileId: z.string().min(1),
  validFrom: z.string().min(1),
  validUntil: z.string().nullable().default(null),
  revokedAt: z.string().nullable().default(null),
  /** 版本号用于乐观锁，避免门户/后台/自动切线同时写入 */
  version: z.number().int().min(1).default(1),
});

export const PortalAccount = z.object({
  id: z.string().min(1),
  username: z.string().min(1),
  displayName: z.string().min(1),
  role: PortalRole,
  /** scrypt$N$r$p$salt$hash，设备侧本地校验，不回落明文 */
  passwordHash: z.string().min(1),
  disabled: z.boolean().default(false),
});

/* ------------------------------------------------------------ 接入控制 */

/**
 * 接入控制模式
 *
 * - device_binding：设备在后台预先授权并绑定线路（原设计，适合固定设备、无人值守）
 * - session：单 SSID，用户连上后输账号密码，账号决定出口线路（适合一人一 IP 的出租场景）
 *
 * 两种模式共用同一套数据面原则：仍然按源地址分流，数据包路径不查账号库。
 * 区别只在「谁写这张源地址→线路的映射」：云端编译期写，还是设备运行期由登录动作写。
 */
export const AccessControlMode = z.enum(['device_binding', 'session']);

export const AccessControl = z.object({
  mode: AccessControlMode.default('device_binding'),
  /**
   * 会话宽限期（分钟）：设备离线超过这个时间，账号的「1 台设备」名额才释放。
   * 它不决定网络通断——离线期间会话仍在，回来按 macHash 自动恢复，不需要重登。
   */
  graceMinutes: z.number().int().min(1).max(1440).default(5),
  /** 未认证设备访问任意 HTTP 时跳转到的路径 */
  loginPath: z.string().default('/login'),
});

/**
 * 预授权设备：没有浏览器的设备（编码器、NVR、打印机）无法输账号密码，
 * 只能按 MAC 预先绑定线路。它们不参与「一账号一设备」的名额计算。
 */
export const TrustedDevice = z.object({
  id: z.string().min(1),
  label: z.string().default(''),
  /** 不可逆摘要，禁止落明文 MAC */
  macHash: z.string().min(1),
  lineId: z.string().min(1),
});

export const AccessAccount = z.object({
  id: z.string().min(1),
  username: z.string().min(1),
  displayName: z.string().default(''),
  /** scrypt$N$r$p$salt$hash，设备侧本地校验 */
  passwordHash: z.string().min(1),
  /** 账号固定绑一条线路：一人一 IP 的前提，不允许登录时随机分配 */
  lineId: z.string().min(1),
  enabled: z.boolean().default(true),
  /** 到期后降级为「仅门户」：Wi-Fi 可连，外网不通，可自助续费 */
  expiresAt: z.string().nullable().default(null),
  /** 手动踢下线标记：云端置 true 后，设备下次同步即撤销会话 */
  revokedAt: z.string().nullable().default(null),
});

export type AccessControlConfig = z.infer<typeof AccessControl>;
export type AccessAccountRecord = z.infer<typeof AccessAccount>;
export type TrustedDeviceRecord = z.infer<typeof TrustedDevice>;

/* ---------------------------------------------------------- 网络与门户配置 */

export const WifiConfig = z.object({
  /**
   * N100/x86 小主机通常没有无线模块，AP 由外部设备提供。
   * 关闭后编译器不再生成任何 wireless UCI——在无无线的设备上写 hostapd 配置
   * 会让 wifi reload 报错，进而拖垮整批配置的应用。
   */
  enabled: z.boolean().default(true),
  ssid: z.string().min(1).max(32),
  hidden: z.boolean().default(false),
  band: z.enum(['2.4+5', '2.4', '5']).default('2.4+5'),
});

export const LanConfig = z.object({
  gateway: z.string().min(1),
  cidr: z.string().min(1),
  dhcpStart: z.string().min(1),
  dhcpEnd: z.string().min(1),
  portalPort: z.number().int().min(1).max(65535).default(8080),
  controlPort: z.number().int().min(1).max(65535).default(8081),
  wanInterface: z.string().default('wan'),
  lanInterface: z.string().default('br-lan'),
  /**
   * LAN 侧物理网口列表，例如 ['lan1', 'lan2', 'lan3']。
   *
   * ARM 一体机（AX3000T）的 br-lan 由设备树固化，留空即可；
   * x86（N100）不会自动生成网桥，留空会导致 LAN 不通、门户与 DHCP 全部失效，
   * 因此 x86 档位必须在设备档案里显式给出，编译器据此生成 device 段。
   */
  lanPorts: z.array(z.string().min(1)).default([]),
  /** WAN 侧物理网口名；x86 上必须显式指定，ARM 上由 UCI 默认值 wan 承接 */
  wanPort: z.string().default(''),
  /**
   * 同网段客户端互访。
   *
   * 注意：单 SSID + 单网段时，同网段流量在二层交换机内完成，网关根本看不见，
   * 这个开关只影响「经网关三层转发的互访」（多网段/VLAN 场景）。
   * 也就是说：想让已认证设备互访，必须同时关掉 AP 的客户端隔离，不然二层就断了。
   */
  allowClientToClient: z.boolean().default(true),
  /**
   * 允许从 LAN 侧访问的管理端口（默认 22）。
   *
   * 这条不是可选项：转发链与入站链默认 drop，如果不放通 22，
   * Agent 一应用配置 SSH 立刻断，人只能抱着显示器去机房。
   */
  managementPorts: z.array(z.number().int().min(1).max(65535)).default([22]),
  /** 是否允许从 WAN 侧访问管理端口；默认关，只有明确需要远程运维时才开 */
  allowWanManagement: z.boolean().default(false),
  tunName: z.string().default('lp-tun'),
  tunCidr: z.string().default('172.19.0.1/30'),
  /** 代理出站统一使用的本地 DNS 监听端口 */
  dnsPort: z.number().int().min(1).max(65535).default(5353),
  ipv6Enabled: z.boolean().default(false),
});

/* ------------------------------------------------------- Desired State */

export const DesiredState = z.object({
  deviceId: z.string().min(1),
  organizationId: z.string().min(1),
  /** 单调递增，用于拒绝降级与错投 */
  revision: z.number().int().min(1),
  generatedAt: z.string().min(1),
  lan: LanConfig,
  wifi: WifiConfig,
  accessControl: AccessControl.default({ mode: 'device_binding', graceMinutes: 5, loginPath: '/login' }),
  accessAccounts: z.array(AccessAccount).default([]),
  trustedDevices: z.array(TrustedDevice).default([]),
  portalAccounts: z.array(PortalAccount).default([]),
  clients: z.array(Client).default([]),
  bindings: z.array(DeviceRouteBinding).default([]),
  routeProfiles: z.array(RouteProfile).default([]),
  lineGroups: z.array(LineGroup).default([]),
  lines: z.array(Line).default([]),
  failoverPolicies: z.array(FailoverPolicy).default([]),
});

/** 云端封装后随 bundle 下发的秘密材料（不含明文凭证） */
export const SealedSecrets = z.object({
  keyVersion: z.number().int().min(1),
  /** 本次封装使用的一次性 X25519 公钥（base64 raw） */
  ephemeralPublicKey: z.string().min(1),
  nonce: z.string().min(1),
  ciphertext: z.string().min(1),
});

export const SecretPayload = z.object({
  wifiPsk: z.string().min(8),
  credentials: z.record(z.string(), LineCredential),
});

export const ConfigBundle = z.object({
  deviceId: z.string().min(1),
  revision: z.number().int().min(1),
  revisionId: z.string().min(1),
  generatedAt: z.string().min(1),
  expiresAt: z.string().min(1),
  digest: z.string().min(1),
  payload: DesiredState,
  secrets: SealedSecrets,
  /** 云端 Ed25519 对签名信封的签名（base64） */
  signature: z.string().min(1),
});

export const BundleSigningEnvelope = z.object({
  deviceId: z.string().min(1),
  revision: z.number().int().min(1),
  revisionId: z.string().min(1),
  generatedAt: z.string().min(1),
  expiresAt: z.string().min(1),
  digest: z.string().min(1),
});

/* ------------------------------------------------------------- 固定命令 */

export const CommandType = z.enum([
  'AUTHORIZE_DEVICE',
  'CHANGE_ROUTE_PROFILE',
  'SWITCH_LINE',
  'REVOKE_DEVICE',
  'RESTART_PROXY',
  'RESTART_NETWORK',
  'ROLLBACK_CONFIG',
  'ROTATE_CREDENTIAL',
  'ENTER_MAINTENANCE',
  'UPGRADE_FIRMWARE',
  'CHANGE_WIFI_PSK',
]);

export const CommandParams = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('AUTHORIZE_DEVICE'),
    clientId: z.string().min(1),
    routeProfileId: z.string().min(1),
    validUntil: z.string().nullable().default(null),
  }),
  z.object({
    type: z.literal('CHANGE_ROUTE_PROFILE'),
    clientId: z.string().min(1),
    routeProfileId: z.string().min(1),
  }),
  z.object({
    type: z.literal('SWITCH_LINE'),
    clientId: z.string().min(1).nullable().default(null),
    targetLineId: z.string().min(1),
  }),
  z.object({ type: z.literal('REVOKE_DEVICE'), clientId: z.string().min(1) }),
  z.object({ type: z.literal('RESTART_PROXY') }),
  z.object({ type: z.literal('RESTART_NETWORK') }),
  z.object({
    type: z.literal('ROLLBACK_CONFIG'),
    toRevision: z.number().int().min(1).nullable().default(null),
  }),
  z.object({ type: z.literal('ROTATE_CREDENTIAL'), credentialId: z.string().min(1) }),
  z.object({ type: z.literal('ENTER_MAINTENANCE'), enabled: z.boolean() }),
  z.object({ type: z.literal('UPGRADE_FIRMWARE'), artifactId: z.string().min(1) }),
  z.object({ type: z.literal('CHANGE_WIFI_PSK'), psk: z.string().min(8).max(63) }),
]);

export const CommandStatus = z.enum([
  'PENDING',
  'ACCEPTED',
  'RUNNING',
  'SUCCEEDED',
  'FAILED',
  'EXPIRED',
  'CANCELLED',
]);

export const DeviceCommand = z.object({
  id: z.string().min(1),
  deviceId: z.string().min(1),
  type: CommandType,
  params: z.record(z.string(), z.unknown()),
  actor: z.string().min(1),
  reason: z.string().min(1),
  createdAt: z.string().min(1),
  expiresAt: z.string().min(1),
  /** 幂等键：重复提交返回已有结果，不重复执行 */
  idempotencyKey: z.string().min(1),
  nonce: z.string().min(1),
  status: CommandStatus,
  signature: z.string().min(1),
  result: z
    .object({
      code: z.string().min(1),
      message: z.string().default(''),
      completedAt: z.string().min(1),
      observedRevision: z.number().int().min(0).default(0),
    })
    .nullable()
    .default(null),
});

/* ------------------------------------------------------- Agent 通道 DTO */

export const EnrollmentRequest = z.object({
  token: z.string().min(1),
  deviceModel: z.string().min(1),
  agentVersion: z.string().min(1),
  hardwareFingerprint: z.string().min(1),
  ed25519PublicKey: z.string().min(1),
  x25519PublicKey: z.string().min(1),
});

export const EnrollmentResponse = z.object({
  deviceId: z.string().min(1),
  organizationId: z.string().min(1),
  /** 云端签名公钥，Agent 用它验 bundle 与命令签名 */
  cloudEd25519PublicKey: z.string().min(1),
  heartbeatIntervalSeconds: z.number().int().min(5),
  pollIntervalSeconds: z.number().int().min(5),
});

export const HeartbeatRequest = z.object({
  agentVersion: z.string().min(1),
  uptimeSeconds: z.number().min(0),
  observedRevision: z.number().int().min(0),
  health: z.enum(['healthy', 'degraded', 'failed', 'maintenance']),
  resources: z.object({
    cpuLoad1: z.number().min(0),
    memoryUsedMb: z.number().min(0),
    memoryTotalMb: z.number().min(0),
    temperatureC: z.number().nullable().default(null),
    diskFreeMb: z.number().min(0),
  }),
  proxyRunning: z.boolean(),
  lastApplyResult: z.string().default(''),
  /** 硬件档位：云端据此判断是 AX3000T 还是 N100，不用人工登记 */
  hardware: z
    .object({
      model: z.string().default(''),
      arch: z.string().default(''),
      cpuModel: z.string().default(''),
      cpuCores: z.number().int().min(1).default(1),
      memoryTotalMb: z.number().min(0).default(0),
      hasWifi: z.boolean().default(false),
      nics: z.array(z.string()).default([]),
      initSystem: z.string().default('none'),
      kernel: z.string().default(''),
    })
    .optional(),
});

export const ObservedStateReport = z.object({
  revisionId: z.string().min(1),
  revision: z.number().int().min(1),
  appliedAt: z.string().min(1),
  status: z.enum(['succeeded', 'failed', 'rolled_back']),
  steps: z.array(
    z.object({
      name: z.string().min(1),
      status: z.enum(['ok', 'failed', 'skipped']),
      detail: z.string().default(''),
      durationMs: z.number().min(0).default(0),
    }),
  ),
  /** 脱敏摘要，禁止出现凭证 */
  artifactDigest: z.string().default(''),
  rollbackTo: z.number().int().min(0).nullable().default(null),
});

export const CommandAckRequest = z.object({
  commandId: z.string().min(1),
  status: z.enum(['ACCEPTED', 'RUNNING', 'SUCCEEDED', 'FAILED']),
  code: z.string().min(1),
  message: z.string().default(''),
  observedRevision: z.number().int().min(0).default(0),
});

/* ----------------------------------------------------------------- 类型导出 */

export type ProtocolKind = z.infer<typeof ProtocolKind>;
export type TrafficAction = z.infer<typeof TrafficAction>;
export type RouteMode = z.infer<typeof RouteMode>;
export type ClientState = z.infer<typeof ClientState>;
export type PortalRole = z.infer<typeof PortalRole>;
export type DeviceState = z.infer<typeof DeviceState>;
export type TlsOptions = z.infer<typeof TlsOptions>;
export type Transport = z.infer<typeof Transport>;
export type LineCredential = z.infer<typeof LineCredential>;
export type Line = z.infer<typeof Line>;
export type LineGroup = z.infer<typeof LineGroup>;
export type FailoverPolicy = z.infer<typeof FailoverPolicy>;
export type RuleMatch = z.infer<typeof RuleMatch>;
export type RoutingRule = z.infer<typeof RoutingRule>;
export type RouteProfile = z.infer<typeof RouteProfile>;
export type Client = z.infer<typeof Client>;
export type DeviceRouteBinding = z.infer<typeof DeviceRouteBinding>;
export type PortalAccount = z.infer<typeof PortalAccount>;
export type WifiConfig = z.infer<typeof WifiConfig>;
export type LanConfig = z.infer<typeof LanConfig>;
export type DesiredState = z.infer<typeof DesiredState>;
export type SealedSecrets = z.infer<typeof SealedSecrets>;
export type SecretPayload = z.infer<typeof SecretPayload>;
export type ConfigBundle = z.infer<typeof ConfigBundle>;
export type BundleSigningEnvelope = z.infer<typeof BundleSigningEnvelope>;
export type CommandType = z.infer<typeof CommandType>;
export type CommandParams = z.infer<typeof CommandParams>;
export type DeviceCommand = z.infer<typeof DeviceCommand>;
export type EnrollmentRequest = z.infer<typeof EnrollmentRequest>;
export type EnrollmentResponse = z.infer<typeof EnrollmentResponse>;
export type HeartbeatRequest = z.infer<typeof HeartbeatRequest>;
export type HardwareReport = NonNullable<HeartbeatRequest['hardware']>;
export type ObservedStateReport = z.infer<typeof ObservedStateReport>;
export type CommandAckRequest = z.infer<typeof CommandAckRequest>;
