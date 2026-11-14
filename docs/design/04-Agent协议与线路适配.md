# Router Agent、配置部署与线路适配

## 1. Router Agent 边界

Router Agent 是唯一业务控制入口，负责设备身份、出站加密连接、配置获取、签名校验、固定命令、状态上报和回滚编排。

Agent 不执行任意 Shell，不读取云端数据库，不复用客户门户 Cookie，不向前端返回线路凭证。

需要重启网络、代理核心或更新防火墙时，由最小权限 Agent 调用本地白名单 Helper。Helper 只接受结构化动作和严格参数，不接受可执行字符串。

## 2. 设备身份和连接

### 首次激活

```text
工厂或运营后台生成一次性 Enrollment Token
  → 设备本地生成独立密钥对
  → Agent 使用 Token 完成登记
  → 云端校验 Token 哈希、有效期和设备状态
  → 签发设备证书或建立受控 TLS 身份
  → Token 立即失效
```

生产方案优先使用设备独立身份和 mTLS；在样机阶段可以先使用受保护 TLS 身份，但接口和数据模型要预留证书轮换、吊销和风险隔离。

## 3. 固定命令模型

V1 仅允许：

```text
AUTHORIZE_DEVICE
CHANGE_ROUTE_PROFILE
SWITCH_LINE
REVOKE_DEVICE
RESTART_PROXY
RESTART_NETWORK
ROLLBACK_CONFIG
ROTATE_CREDENTIAL
ENTER_MAINTENANCE
UPGRADE_FIRMWARE
```

每条命令至少包含：命令 ID、目标设备 ID、目标配置版本、过期时间、随机数、幂等键、操作者、操作原因和数字签名。Agent 必须检查签名、时间窗口、设备状态、命令权限、Nonce 是否重复和目标版本关系。

命令状态：`PENDING → ACCEPTED → RUNNING → SUCCEEDED/FAILED/EXPIRED/CANCELLED`。重复命令返回已有结果，不重复执行。

## 4. Desired State 与 Observed State

```text
云端 Desired State
  → 配置编译和能力检查
  → 生成 ConfigRevision
  → 摘要、签名和发布
  → Agent 下载并本地校验
  → 临时目录原子写入
  → 启动或切换执行器
  → 本地 Probe 健康验证
  → 上报 Observed State
  → 成功设为稳定版本，失败自动回滚
```

设备至少保留：当前稳定版本、上一个稳定版本、待验证版本。待验证失败时先恢复上一个稳定版本，再恢复默认拒绝和门户可用状态。

配置版本必须绑定设备能力、策略资源版本、执行器版本和生成来源，避免同一业务配置在不同硬件上产生不可预期结果。

## 5. 配置安全

- 云端使用密钥管理系统保存签名私钥和线路加密密钥。
- 设备只验证签名公钥，不接收云端签名私钥。
- 配置包使用版本号、设备 ID、有效期、内容摘要和签名防止重放和错投。
- 线路敏感字段在数据库中使用密文、Nonce、密钥版本和摘要；普通日志只记录资源 ID 和结果码。
- 配置写入使用临时文件、权限校验、fsync 或等效持久化保障和原子替换。
- 降级必须有明确的允许策略，OTA 默认拒绝低于安全基线的版本。

## 6. 自定义线路和协议适配

### 适配模型

```text
ProtocolProfile
  → 参数校验和规范化
  → 能力矩阵检查
  → ExecutorAdapter
  → 执行器配置
  → 本地语法校验
  → 协议握手探针
```

业务层只认识线路、协议能力、用途、地区、健康策略和凭证引用，不认识某个执行器的原始 JSON 或订阅格式。

### V1 能力优先级

| 协议 | 执行器 | 优先级 |
|---|---|---|
| VLESS | sing-box 或 Xray | 第一批真实验证 |
| Trojan | sing-box 或 Xray | 第一批真实验证 |
| Shadowsocks | sing-box | 第一批真实验证 |
| WireGuard | WireGuard | 第一批真实验证 |
| SOCKS5、HTTP/HTTPS Proxy | sing-box | 第一批真实验证 |
| VMess | Xray 或 sing-box | 兼容验证 |
| Hysteria2、TUIC | sing-box | 硬件和版本验证后 |
| NaiveProxy | 视执行器和 OpenWrt 包成熟度 | 暂不作为 V1 必选 |

PassWall 导入只做受限解析和人工确认：识别协议、地址、端口、传输和安全参数，过滤未知字段，禁止把完整订阅链接或敏感原文写入日志。

## 7. OTA 边界

OTA 由云端发布受签名的固件/Agent 包，设备侧完成：兼容性检查、空间检查、签名验证、分区写入、重启、启动自检和失败回退。

样机阶段先验证单设备升级和回退闭环；量产阶段再验证双分区、断电恢复、救砖路径、证书保留和配置迁移。未经真实恢复测试，不宣称具备量产级 OTA。
