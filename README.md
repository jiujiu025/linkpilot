# LinkPilot 定制软路由

面向直播与跨境办公场景的可远程管理软路由。当前仓库是 **Phase 1～4 的垂直切片**：控制面、Router Agent、策略编译器、本地门户四块已经能跑通端到端闭环，但**尚未在真实硬件和真实线路上验证**。

当前交付形态为 **N100 网关 + 外置 AP**（不是 AX3000T 一体机），系统基线与稳定性设计见 `docs/design/10`；单 SSID 下「账号登录 → 指定出口线路」的接入模型见 `docs/design/11`。

**要把这套跑到真机上**：装完 Debian，`sudo bash scripts/install.sh` 一条命令搞定（Node、sing-box、网桥、服务、自检全包）。
细节见 `docs/ops/N100部署手册.md`；日常操作（后台、批量导入、测速、账号）见 `docs/ops/操作手册.md`。

设计与边界以 `docs/软路由产品设计方案.md` 与 `docs/design/` 为准；本文只讲代码怎么跑、哪里能改。

## 目录

```
src/core/          领域模型、密码学原语、配置包信封（云端与设备共用）
src/compiler/      策略编译器：DesiredState → sing-box + nftables + UCI
src/control/       云端控制面（设备注册、配置下发、固定命令、审计）
src/agent/         Router Agent + 本地门户
test/              单元测试与安全边界测试（48 项）
scripts/           demo / 预览 / 产物检查
image/             x86_64 固件构建（ImageBuilder + overlay，产物 dist/）
docs/              产品与架构设计、实现状态、真机验收清单
```

固件构建与刷机见 `image/README.md`；N100 + 三 AP 的组网方案见 `docs/design/10-N100-三AP-系统方案.md`。

## 快速开始

```bash
npm install

npm test          # 编译、签名、重放、越权、锁线等 37 项测试
npm run demo      # 端到端：注册 → 下发 → 验签 → 编译 → 应用 → 门户 → 切线 → 断网
```

`npm run demo` 会在 `runtime/demo/` 下产出一次完整运行的真实数据（云端数据库、设备产物、审计记录），跑完会逐条打印每一步的结论。

单独运行两个进程：

```bash
npm start                                  # 控制面，默认 127.0.0.1:18080
LP_ENROLL_TOKEN=<令牌> npm run agent        # Agent，默认门户 127.0.0.1:8088
```

首个控制面启动时会写入演示数据，并把一次性注册令牌打印到 `runtime/cloud/enrollment-token.txt`。

其他脚本：

```bash
npm run typecheck                 # tsc --noEmit
node scripts/preview.ts           # 只跑编译器，看生成的 sing-box / nftables 产物
node scripts/portal-preview.ts    # 生成门户静态预览页（注入样例快照）
```

## 已实现

| 能力 | 位置 | 说明 |
|---|---|---|
| 领域模型与校验 | `src/core/schema.ts` | zod 单一事实来源，云端/设备共用 |
| 设备身份与请求签名 | `src/core/bundle-envelope.ts` | Ed25519 逐请求签名 + 时间窗 + nonce 防重放 |
| 凭证封装 | `src/core/secrets.ts` | X25519 + HKDF + AES-GCM，AAD 绑定设备与版本 |
| 策略编译器 | `src/compiler/*` | 按源地址分流、DNS 接管、IPv6 阻断、Kill Switch |
| 产物不变量校验 | `src/compiler/validate.ts` | 9 类反向断言，不通过就拒绝生成配置 |
| 控制面 | `src/control/*` | 注册、心跳、下发、回报、固定命令、审计、门户转发接口 |
| Router Agent | `src/agent/*` | 验签、解封、本地编译、原子应用、失败回滚、失败版本拉黑 |
| 本地门户 | `src/agent/portal-*` | 统一登录（scrypt）、待授权设备、线路切换、诊断 |
| 手动锁线 | `schemas/pins` | 按设备生效，不影响同组其他设备 |

## 明确未实现

- ARM 档位（AX3000T）固件构建与 uboot 适配；x86/64 的固件构建见 `image/`（
  已能产出可刷镜像，**但尚未在真实 N100 上验证**）；
- sing-box / Xray 进程守护与真实流量转发（`dry-run` 只落盘与校验，不启动核心）；
- 探针采集与主备自动切线状态机（Phase 5）；
- 云端运营后台 UI、模拟客户视图、OTA（Phase 6～7）；
- 数据库、消息队列、KMS（当前为 JSON 文件 + 本地密钥，接口已按可替换设计）。

## 关键设计决策

1. **按源地址分流，不按账号**：数据包路径不可能查账号库。因此每台已授权设备必须有稳定 DHCP 静态租约地址，编译器把 `source_ip_cidr` 写进 sing-box 路由规则。
2. **`route.final` 必须指向 `block` 出站，并在规则末尾再压一条无条件 `reject`**：sing-box 的 `final` 为空时会退化成「第一个出站」，出站顺序一变就等于默认直连，这是最隐蔽的泄露路径。
3. **线路凭证双层加密**：云端数据库里是 master key 加密的密文；下发时再用一次性 X25519 对设备公钥重新封装。数据库泄露 ≠ 线路泄露。
4. **云端只下发固定命令**：命令集合是枚举，参数走 zod 判别联合；`EXEC_SHELL` 这类请求在参数校验阶段就 400。
5. **失败版本拉黑**：应用失败或主动回滚过的版本进入 `failedRevisions`，云端重复下发也不会再被应用，避免「坏配置把设备反复搞挂」。
6. **控制通道直连**：Agent 与云端地址、NTP 走 `direct` 并在 nftables 里显式放行。代理挂了还要能被运维，这是可运营性的底线。

## 集成真实组件时要改哪里

| 需求 | 改动点 |
|---|---|
| 新增协议 | `src/core/schema.ts` 的 `LineCredential` 联合 + `src/compiler/singbox.ts` 的 `buildOutbound` |
| 新增分流语义 | `src/compiler/plan.ts` 的规则解析 + `src/compiler/singbox.ts` 的规则发射 |
| 防火墙上真机 | `src/compiler/nftables.ts`（保持 `policy drop` 与 DNS 劫持两条不变量） |
| 换成 PostgreSQL | `src/control/store.ts` 的 `Store` 实现，业务层不动 |
| 换成 KMS | `src/control/keys.ts`，`sealWithMaster` / `openWithMaster` 接口不变 |

## 安全边界（不可通过改配置绕开）

- 门户不提供任何系统管理入口，不返回口令哈希与线路凭证；
- 云端不下发 shell，不接受未签名/过期/重放请求；
- 转发链默认 `drop`，未授权设备只能访问门户；
- 任何一条不变量不成立，编译器拒绝出产物——半残配置比没有配置更危险。
