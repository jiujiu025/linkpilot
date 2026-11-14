# 云端后台、数据模型与 API

## 1. 数据模型原则

- 所有租户资源带 `organization_id`，服务端执行资源归属校验。
- 密码只保存 Argon2id 哈希；线路凭证只保存密文、Nonce、密钥版本和摘要。
- 设备、账号、线路、配置和绑定使用唯一约束、状态和有效期。
- 部署、探针、故障和审计采用追加记录，不直接覆盖历史。
- 高并发绑定、切线和部署使用事务、乐观锁/行锁、幂等键和 fencing token。
- 统计快照与计费账本分离；V1 即使暂不计费，也保留边界。

## 2. 实体分组

### 租户与身份

`Organization`、`User`、`Role`、`Permission`、`UserRole`、`Session`、`MfaCredential`。

### 设备与授权

`RouterDevice`、`DeviceIdentity`、`DeviceCredential`、`DeviceSession`、`DiscoveredClient`、`DeviceRouteBinding`、`DeviceRevocation`。

### 线路与策略

`Provider`、`Server`、`CustomLine`、`ProtocolProfile`、`LineGroup`、`RouteProfile`、`RoutingRule`、`DomainRule`、`IpRule`、`FailoverPolicy`。

### 配置与任务

`DesiredState`、`ObservedState`、`ConfigRevision`、`Deployment`、`DeploymentStep`、`Command`、`Job`、`JobAttempt`、`Outbox`、`DeadLetter`。

### 探针与审计

`Probe`、`ProbeCheck`、`HealthSnapshot`、`Incident`、`Alert`、`AuditLog`、`SecurityEvent`、`CredentialRotation`、`ImpersonationSession`。

## 3. 核心关系

```text
Organization
  ├─ User / PortalAccount
  ├─ RouterDevice
  │    ├─ DiscoveredClient
  │    ├─ DeviceSession
  │    └─ DeviceRouteBinding → RouteProfile → LineGroup → CustomLine
  ├─ RoutingRule / FailoverPolicy
  └─ ConfigRevision → Deployment → ObservedState
```

`DeviceRouteBinding` 是账号、接入设备、RouterDevice 和 RouteProfile 的业务连接点，必须记录生效区间、撤销原因和版本。

## 4. API 分层

### 本地门户 API

```text
GET   /api/portal/me
GET   /api/portal/devices
GET   /api/portal/discovered-clients
GET   /api/portal/lines
GET   /api/portal/health
GET   /api/portal/traffic
PATCH /api/portal/wifi
POST  /api/portal/device-bindings
POST  /api/portal/line-switch
POST  /api/portal/logout
```

### 云端运营 API

```text
GET   /api/admin/routers
GET   /api/admin/routers/{id}/diagnostics
POST  /api/admin/routers/{id}/device-authorizations
POST  /api/admin/routers/{id}/commands
POST  /api/admin/lines
PATCH /api/admin/route-profiles/{id}
POST  /api/admin/deployments
POST  /api/admin/deployments/{id}/rollback
POST  /api/admin/routers/{id}/impersonation-sessions
GET   /api/admin/audit-logs
```

### Agent API

```text
POST /agent/enrollment
POST /agent/heartbeat
POST /agent/desired-state/pull
POST /agent/observed-state
POST /agent/commands/ack
POST /agent/probe-results
```

Agent API 使用独立 mTLS/设备身份和消息模型，不能接受门户 Cookie。所有输入使用统一 schema 校验；请求必须处理鉴权、租户、资源归属、状态转换、重放和幂等。

## 5. 权限模型

推荐 RBAC + 资源范围：

| 角色 | 范围 |
|---|---|
| 客户用户 | 自身账号、被授权设备和线路摘要 |
| 设备管理员 | 一台绑定的 RouterDevice 及其待授权设备、Wi-Fi 和线路绑定 |
| 运营管理员 | 被授权组织/设备范围 |
| 线路管理员 | 线路、协议、健康策略和分配，不默认拥有客户密码或设备 Shell |
| 审计人员 | 只读设备、部署、命令、探针和安全审计 |
| 超级管理员 | 全局资源、权限、密钥策略和系统设置 |

高风险动作包括线路切换、撤销设备、修改 Wi-Fi、修改策略、回滚、凭证轮换、维护模式和 OTA。必须二次确认、校验操作原因、记录结果并支持超时。

## 6. 审计要求

审计记录至少包含：操作者、租户、角色、动作、目标资源、目标版本、请求来源、原因、二次确认结果、前后状态摘要、结果、失败码、时间和关联命令/部署 ID。

禁止记录密码、UUID、私钥、订阅链接、完整线路地址和完整凭证。审计日志采用追加写入、访问分权、保留策略和完整性校验；“不可篡改”必须通过实际存储和权限方案验证，不能仅靠前端展示。

## 7. 管理员模拟客户门户

```text
管理员完成 MFA 和资源授权
  → 云端签发一次性短期 impersonation token
  → Token 绑定管理员、租户、指定 RouterDevice、权限和过期时间
  → Agent 或本地门户验证 Token
  → 建立默认只读模拟会话
  → 页面显示运维提示、当前设备和剩余时间
  → 高风险操作重新确认并单独审计
```

模拟会话不读取或保存客户明文密码，不能横向访问其他设备或租户。默认只读；写操作按最小权限逐项放行。
