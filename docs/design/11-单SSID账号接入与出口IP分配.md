# 单 SSID + 账号认证 + 出口 IP 分配

> 状态：设计草案（2026-11-14）；编译期骨架与设备侧会话存储已实现，门户接线与运行期应用待做（见 §12）
> 前置：`10-N100-系统基线与稳定性设计.md`（N100 网关 + 外置 AP）
> 本文回答一件事：**一个 SSID、连上后输账号密码、拿到对应出口 IP，怎么落地才不掉链子**

## 0. 结论

需求可以做到，现有架构**不用重写**——底层仍然是「按源地址分流」，和现在的 `source_ip_cidr` 模型一致。但要改三个地方，其中一个是硬伤：

1. **身份维度从「设备」改成「会话」**：账号登录 → 给这个源 IP 绑定一条线路 → 出口 IP 随之确定。设备只是载体，换账号只换映射。
2. **换账号不能重启 sing-box**（硬伤）：现在的实现是「编译期按源 IP 展开路由规则」，任何一个人登录都会触发重新编译 + 重启代理，**全网其他人一起掉线**。必须改成 per-line 入站 + nftables 会话映射，改一条规则即可生效。
3. **Captive Portal 自动弹窗现在没有**：未授权设备的 DNS 都不劫持，手机连上不会弹登录页，只能手输 `http://192.168.10.1:8080`。要补 HTTP 劫持。

好消息：**单 SSID 正好绕开了雅典娜的短板**。之前那套「多 SSID + VLAN + isolation」它做不到，但这个需求只要一个 SSID、一个二层域，谁上网由网关按账号放行，二层隔离不再是必要条件。

## 1. 需求转译

| 用户说法 | 系统语言 |
|---|---|
| 单 SSID | AP 只发一个 SSID，桥接到 N100 的 `br-lan`；网关不参与无线配置 |
| 手机连上 Wi-Fi | DHCP 由 N100 分配地址，此时**未认证**，除门户以外全部拦截 |
| 输账号密码 | 门户校验（scrypt，设备本地），通过后建立一条 **Session** |
| 连接上对应的 IP | Session 绑定一条 `Line`，该源 IP 的流量全部走这条线路的出口 |
| 换账号 | 同一源 IP 改绑另一条线路，**只改映射，不动设备、不重启代理** |

## 2. 与现有实现的差距

| 维度 | 现在 | 需要 |
|---|---|---|
| 授权单位 | `Client`（设备，靠 macHash + 静态 IP） | `Session`（账号 × 源 IP × 线路 × 有效期） |
| 线路绑定 | `DeviceRouteBinding`（设备 → RouteProfile，编译期静态） | 账号 → 线路，**运行时可变** |
| 门户账号 | `PortalAccount`（管理员/客户，登录只看状态） | 增加「接入账号」角色，登录即决定出口 |
| 未认证体验 | `pending_v4` 直接 reject，DNS 也不劫持 | 允许访问门户，且能自动弹窗 |
| 变更生效 | 重新编译 → 校验 → 重启 sing-box → 全网闪断 | 改 nftables map，毫秒级，不影响他人 |

## 3. 目标形态

```text
        ┌─────────┐  单 SSID   ┌──────────────────────────────┐
手机 ───│ 雅典娜  │─── 桥接 ──→│  N100（网关）                 │
平板 ───│  AP 模式│            │  DHCP / 门户 / nftables       │
编码器 ─┘         └────────────│  sing-box（每线路一个入站）    │
                              └──────────┬───────────────────┘
                                         │ 按 session 选线路
                          ┌──────────────┼──────────────┐
                      线路 A          线路 B          线路 C
                    出口 IP 1       出口 IP 2       出口 IP 3
```

关键点：**分流依据永远是「这个源 IP 当前属于哪条线路」**，而这条映射由登录动作写入。数据面不查账号库，所以不需要动现有「按源地址分流」的原则（`docs/design/01` 冲突 B 的约束仍然成立）。

## 4. 核心决策：per-line 入站 + nftables 会话映射

### 4.1 为什么不能沿用现在的做法

现在 `singbox.ts` 为每台设备的每条规则生成一条 `source_ip_cidr` 规则，配置体量是 **O(客户端 × 规则)**。10 个账号 8 条规则就是 80 条；更严重的是**改一个账号的线路必须重编译 + 重启 sing-box**，正在看直播、正在推流的所有人一起断。这在「随时有人登录」的场景里不可接受。

### 4.2 改成什么样

- 每条**线路**一个 `tproxy` 入站，端口固定（`line A → 10001`、`line B → 10002`…），入站 tag 与线路一一对应。
- nftables 用一张 **map** 保存「源 IP → 目标端口」：

```nft
map sessions {
    type ipv4_addr : inet_service
    elements = { 192.168.10.101 : 10001,   # 账号 alice → 线路 A
                 192.168.10.102 : 10002 }  # 账号 bob   → 线路 B
}

chain prerouting {
    type filter hook prerouting priority mangle - 5; policy accept;
    iifname "br-lan" ip saddr @sessions meta l4proto { tcp, udp } \
        tproxy ip to ip saddr map @sessions meta mark set 1
}
```

- sing-box 路由规则从「按源 IP × 业务规则展开」变成 **O(线路)**：`{ inbound: ["in:line-A"], outbound: "line:A" }`。
- 登录/登出/换号 = **原子替换这张 map**，不重启、不断其他连接，只影响新连接。

### 4.3 代价（说清楚，别当免费的）

1. **DNS 也要跟着走**：现在 DNS 是按 `source_ip_cidr` 分到各线路解析器，改成 tproxy 后要按入站区分，`dns.rules` 里改用 `inbound` 匹配。漏了就会出现「IP 出口是 A，DNS 解析走 B」——这等于自己把出口一致性卖了。
2. **业务级精细规则会被削弱**：现在可以按「设备 + 域名」组合定制，改成按入站后，只剩「线路级 + 全局规则」。真要保留设备级精细控制，得给该线路单独开一个入站，或接受规则集合并。**V1 建议只做线路级**。
3. **`strict_route` 与 tproxy 的配合要实测**：tun + auto_route + tproxy 同时在跑容易出环路，V1 建议**只用 tproxy，不用 tun**，先在一台机器上验证 24 小时。

## 5. 会话生命周期

### 5.1 先明确一件事：会话跟 MAC 走，不跟 IP 走

源 IP 只是「当前落点」，真正的身份是设备的 MAC 摘要。映射写成两层：

- `deviceSessions`：`macHash → accountId`，登录成功后写入，**这是"记住这台设备"**
- `ipSessions`：`srcIp → linePort`，供 nftables 数据面查，**这是真正生效的那张表**

好处：手机重连拿了新 IP，只要 MAC 还能对上，网关自动把新 IP 挂回原账号，用户无感，不需要重登。

### 5.2 正常使用不会断

登录一次之后，这台手机就被记住了。以后连上 Wi-Fi **自动登录**，不弹窗、不重输密码。只有四种情况需要重新认证：

| 情况 | 是否要重登 |
|---|---|
| 锁屏、休眠、走出覆盖再回来 | 不需要（自动按 MAC 恢复） |
| 网关重启 / 断电 | 不需要（session 持久化在磁盘） |
| 手动登出、换账号 | 需要（本来就是要换） |
| 账号到期 / 被踢 / 换了一台新手机 | 需要 |

### 5.3 那"宽限期"到底是什么

它**不负责"断网"，只负责"名额什么时候收回"**。这两个概念别混。

因为一账号限 1 台设备，就有一个现实问题：客户的手机下午 3 点关机了，这个账号的名额什么时候释放？

- 宽限期 = 0：关机瞬间名额就释放，晚上他在另一台设备登录，立刻能用。但代价是——他手机只是锁屏 10 分钟、或者 AP 重启一下，名额就被回收，回来要重新登录。**体验会很差。**
- 宽限期 = 30 分钟（建议）：离线 30 分钟内名额保留，回来直接恢复；超过 30 分钟才释放。
- 做直播的客户建议 2 小时：编码器偶尔重启、线路抖动，不该因此丢会话。

所以答案是：**手机正常用不会断；宽限期只影响"你离线多久后，这个账号可以被别的设备占用"。**

### 5.4 状态机

| 事件 | 行为 |
|---|---|
| 登录成功 | 写 `deviceSessions`（macHash→account）+ `ipSessions`（ip→linePort）；门户显示当前出口 IP |
| 设备重新上线、IP 变了 | 按 macHash 找回账号，更新 `ipSessions` 里旧的 IP 条目 |
| 换账号（同设备） | 原子替换 `ipSessions` 中该 IP 的端口，旧账号作废，其他用户无感 |
| 账号到期 / 流量用尽 | 删 `ipSessions` 条目 → 该设备回到「仅门户」，Wi-Fi 不断 |
| 账号在另一台设备登录 | 后登踢前登：旧设备立刻回到「仅门户」，并提示原因 |
| 离线超过宽限期 | 释放名额（保留 `deviceSessions` 记忆，下次接入可自动登录） |
| 一账号多设备 | **只允许 1 台**（已定）；后登踢前登，不做并发 |

工程细节：**DHCP 仍按 MAC 固定地址**（保留现有静态租约思路）。这能让 90% 的重连都落在同一个 IP 上，减少 `ipSessions` 迁移的次数。

## 6. 门户与自动弹窗（现在缺）

现状：`nftables.ts` 里 `pending_v4` 直接 `reject`，而且 DNS 劫持对未授权设备是 `return`（不劫持）。结果就是手机连上 Wi-Fi 后**什么都打不开，也不会弹窗**，用户根本不知道要去哪登录。

必须补三件事：

1. **未授权设备允许 DNS**：至少能解析门户域名，或干脆把 53 全劫持到本地，只答门户相关。
2. **HTTP 80 劫持到门户**：`tcp dport 80 → DNAT 到门户`，返回 302 跳 `http://<网关>:<端口>/login`，各家系统的探测请求会因此触发「需要登录」弹窗：
   - iOS/macOS：`captive.apple.com/hotspot-detect.html`
   - Android：`connectivitycheck.gstatic.com/generate_204`
   - Windows：`www.msftconnecttest.com/connecttest.txt`
3. **HTTPS 不劫持**：443 直接 reject 即可。硬劫持会触发证书错误，反而让用户以为网络坏了。

另外门户要显示「当前出口 IP」——用固定查询接口（如 `ip.sb`）比对，让用户自己验证「我确实拿到了这个 IP」。这是产品说服力的一部分，别省。

## 7. 账号与线路的容量关系

| 模式 | 说明 | 适用 |
|---|---|---|
| 1 账号 ↔ 1 线路 | 每个账号独占一条线路的出口 IP | 「一人一 IP、不超售」的默认卖点 |
| N 账号 → 1 线路 | 多人共享同一出口 IP | 只在明确告知客户时使用，否则等着被投诉「为什么我和别人同 IP」 |
| 1 账号 → N 线路 | 一个账号可切换线路 | 高级套餐；门户加一个「切换线路」按钮 |

**必须显式建模容量**：`Line.maxSessions`。否则账号数一多，两个人同时分到同一出口 IP，客户一查就穿帮。

## 8. 已定的产品规则（2026-11-14 确认）

| # | 规则 | 决定 | 影响 |
|---|---|---|---|
| 1 | 一账号几台设备 | **1 台**，后登踢前登 | schema 里 `AccessAccount.maxDevices` 固定为 1；不需要并发逻辑，省一堆边界情况 |
| 2 | 账号绑线路还是线路池 | **绑线路**（1:1） | 「一人一 IP」口径成立；登录后出口 IP 恒定，客户可自行核对 |
| 3 | 会话宽限期 | **5 分钟**（2026-11-14 定） | 只影响名额释放，不影响正常使用，见 §5.3。代价：同一账号在两台设备间频繁切换会互相踢，属于预期行为 |
| 4 | 账号到期行为 | **Wi-Fi 可连，IP 无网，仅门户可访问以便续费** | 直接复用现有 `pending_v4` 语义：移出 `ipSessions` 即落回待授权状态，只放通门户与 DNS |

第 4 条的实现注意：现有 `pending_v4` 连 DNS 都不放通（`nftables.ts:64`），到期设备会表现为"Wi-Fi 已连接但完全打不开"。必须同时补 §6 的 DNS 放通与 HTTP 80 劫持，否则客户会认为"断网了"，而不是"该续费了"。

## 9. 代码改动清单

| 模块 | 改动 | 量级 |
|---|---|---|
| `core/schema.ts` | 新增 `AccessAccount`（绑 lineId、`maxDevices` 固定 1、配额、到期）、`DeviceSession`（macHash→account）、`IpSession`（ip→linePort）；`Line` 加 `maxSessions` | 小 |
| `compiler/singbox.ts` | tun 入站改成 **per-line tproxy 入站**；路由规则改按 `inbound` 匹配；DNS 规则同步 | **大** |
| `compiler/nftables.ts` | 新增 `ipSessions` map + tproxy 规则；补 HTTP 80 劫持；未授权放通 DNS | 中 |
| `compiler/plan.ts` | plan 从「设备 × 规则」改成「线路级 + 会话表」 | 中 |
| `agent/portal.ts` | 新增 `/api/portal/login`（接入认证）→ 写两张会话表 → 下发 nft 原子更新；`/api/portal/logout`；到期续费页 | 中 |
| `agent/main.ts` | 会话持久化（断电恢复）、按 macHash 迁移 IP、宽限期清理、按需刷新 nft | 中 |
| `compiler/validate.ts` | 新增不变量：未认证 IP 不得出现在 sessions 里；session 指向的线路必须存在 | 小 |
| 测试 | 换号不断他人、宽限期、到期踢线、DNS 与出口一致 | 中 |

## 10. 验收（新增，与 10 号文档的清单并列）

| # | 测试 | 通过标准 |
|---|---|---|
| 1 | A 登录后，B 换号 | A 的现有连接**不断**，B 的新连接走新线路 |
| 2 | 手机锁屏 10 分钟再解锁 | 无需重登，出口 IP 不变 |
| 2b | DHCP 换了 IP 但 MAC 不变 | 按 macHash 自动挂回原账号，用户无感 |
| 3 | 账号到期 | 立刻回到「仅门户」，页面提示续费 |
| 4 | 两台设备用同一账号 | 后登的生效，先登的被踢并提示原因 |
| 5 | 出口 IP 一致性 | 门户显示的公网 IP = 实际访问外网看到的 IP |
| 6 | 未认证设备 | 连上即弹登录页；除门户外全不通；DNS 不泄露 |
| 7 | 断电重启 | session 从持久化恢复，用户无需重登 |

第 5 条最容易被忽略，但它恰恰是客户验货的第一件事：**他自己会去查 IP。**

## 11. 和雅典娜 AP 的关系

- 单 SSID ✅ 正好，不需要多 SSID、不需要 VLAN，**之前"客户端隔离做不到"这条在本方案里不致命**——能不能上网由网关按账号放行，不是靠二层隔离。
- AP 仍按 `10` 号文档 §14 配置：AP 模式、关 DHCP、关 IPv6、信道固定、关自动升级、关积分。
- 仍需注意：同网段内已认证设备之间可以互访（二层隔离做不到）。如果客户对此敏感（例如同一办公室两家公司共用），只能靠 VLAN 方案另做，本方案不覆盖。

## 12. 实现进度（2026-11-14）

已完成（`npm test` 60 项通过，含新增 12 项会话用例）：

| 部分 | 落点 | 说明 |
|---|---|---|
| 接入模型 | `core/schema.ts` 的 `AccessControl` / `AccessAccount` | `mode=session` 才切换形态，默认仍是设备绑定，不影响存量 |
| 线路端口 | `compiler/plan.ts` 的 `linePorts` | 线路 → 固定 tproxy 端口（10000 起），编译期确定、运行期不变 |
| 防火墙骨架 | `compiler/nftables.ts` | 每线路一个集合 + `tproxy ip to :port` + `authed_v4` 总集合 + HTTP 80 跳门户 + DNS 指网关 + input 放通 tproxy 端口 |
| 代理入站 | `compiler/singbox.ts` | 会话模式改为 per-line `tproxy` 入站，路由与 DNS 都按 `inbound` 匹配；不再生成 tun |
| 运行期脚本 | `compiler/sessions.ts` | `renderSessionsNft()`：先 flush 再 add，换号不会残留旧地址 |
| 会话存储 | `agent/sessions.ts` | 一账号一设备（后登踢前登）、按 MAC 迁移 IP、5 分钟宽限、持久化、账号级撤销 |
| 不变量 | `compiler/validate.ts` | 新增 TPROXY_INBOUND_MISSING / TPROXY_PORT_MISMATCH / TPROXY_ROUTE_MISSING / NFT_TPROXY_MISSING / CAPTIVE_REDIRECT_MISSING 等 |

本轮补齐（2026-11-14 第二轮）：

| 部分 | 落点 | 说明 |
|---|---|---|
| 接入登录接口 | `agent/portal.ts` | `POST /api/portal/access-login`、`GET /api/portal/access-state`、`POST /api/portal/access-logout`；客户端地址取自 socket，**不接受自报** |
| 登录页 | `agent/portal-ui.ts` | 会话模式下整页只做接入登录（账号/密码 → 已连接 → 显示当前出口线路 → 退出），不暴露管理功能 |
| 身份识别 | `agent/netinfo.ts` + `core/crypto.hashMacAddress` | ARP 表按 IP 反查 MAC；查不到退化为按 IP 生成稳定标识，避免「密码对但登不上」 |
| 门户 DNS | `agent/portal-dns.ts` | 任意 A 记录答网关地址，AAAA 答空，支持 EDNS0；只在会话模式启动，只监听 LAN |
| 热更新 | `agent/supervisor.ts` 的 `applySessions` | 只 `nft -f` 会话脚本，不重启 sing-box |
| 预授权设备 | `agent/main.ts` 的 `syncTrustedDevices` | 按 MAC 从 dnsmasq 租约找 IP，常驻会话表 |
| 策略路由 | `compiler/openwrt.ts` | 补 `ip rule fwmark 1 lookup 100` + `ip route replace local default dev lo table 100`，**tproxy 的内核必需项，漏了就是流量黑洞** |

第三轮（批量运营）：

| 部分 | 落点 | 说明 |
|---|---|---|
| 批量导入 | `control/import.ts` + `POST /api/admin/import/{lines,accounts}` | CSV（逗号/Tab），逐行返回结果与行号；一行错不拖垮整批 |
| 后台界面 | `control/admin-ui.ts` | 两个粘贴框 + 结果提示；地址池/账号数实时核对，共用线路标黄 |
| 容量核对 | `GET /api/admin/access-accounts` 的 `capacity` | 地址池 201（50–250）、启用账号数、共用线路数 |
| 门户在线视图 | `agent/portal.ts` 的 `access` + `POST /api/portal/access-kick` | 设备管理员能看到在线用户并踢下线，只清会话不封号 |
| 局域网访问 | `LP_CONTROL_HOST` + 已有 nft input 放通 | 门户本来就对 br-lan 开放；后台默认只听本机，需显式放开 |

实测：导入 100 个账号后，编译产物仍是 **2 个 tproxy 入站 + 114 行 nft**——入站按线路算不按设备算，这是 per-line 设计的直接收益。

仍未完成：

1. **到期降级定时器**：账号到期目前只在登录时拒绝，已在线的会话不会被自动摘除。
2. **DHCP 静态租约与 MAC 记忆的联动**：现在靠 MAC 迁移兜底，还没把「登录过的设备」写回静态租约。
3. **真实环境验证**：tproxy + 策略路由 + DNS 劫持的组合**一次都没在真机跑过**。单元测试只证明产物结构正确，不证明内核行为正确。这是当前最大的未知。

## 13. 同网段互访与有线接入（2026-11-14 追加需求）

需求：**同网段内已认证设备之间要能互访；电脑插网线也要能用。**

### 13.1 互访：能通，但有一个绕不过去的真相

单 SSID + 单网段时，客户端之间的流量在二层交换就完成了，**根本不经过 N100**。所以：

- 互访本来是通的，之前那条 `iifname br-lan oifname br-lan reject` 只对「经网关三层转发」的流量生效（多网段/VLAN 场景）。
- 现在把它做成开关 `lan.allowClientToClient`，**默认 true（放行）**，只有显式要求隔离时才生成拒绝链。
- **必须同时关掉 AP 的客户端隔离**，否则二层就断了——这一条与 10 号文档 §14.1/§14.2 的方案 A 直接冲突，以本节为准。

绕不过去的真相：**做不到「只让已认证设备互访」。**

二层没有身份概念。你在网关做三层认证，能控制「谁能出公网」，但控制不了「谁能访问隔壁那台机器」。未登录设备一样能被访问、也一样能访问别人。想要精确控制只有两条路，都不便宜：

| 做法 | 条件 | 代价 |
|---|---|---|
| 每账号一个 VLAN，网关做三层转发 + nft 只放行 authed↔authed | AP 支持多 SSID + VLAN trunk | 雅典娜做不到；换商用 AP 后可行 |
| 802.1X / WPA-Enterprise，认证就在二层 | AP + RADIUS | 手机要装证书，体验重，且不支持 PCDN 类老固件 |

**接受互访 = 接受网内横向可达**。对租售场景要写进交付告知：一个客户设备中招，可能横向扫到其他客户设备。这是拓扑的代价，不是配置没做对。

### 13.2 有线接入：和无线同一套规则

- N100 的有线网口与 AP 上联口放进同一个 `br-lan`（`lan.lanPorts` 已支持），有线客户端与无线在同一网段、同一 DHCP 池。
- 认证走同一套：未登录 → 只能到门户；登录 → 写入会话表 → tproxy 到对应线路端口。
- Windows/macOS 的有线连接同样会发 HTTP 探测请求，`tcp 80` 跳门户的规则对它们一样生效，会自动弹登录页。
- 需要注意：**有线口不要接到 AP 的 WAN 口**，否则会多一层 NAT，客户端源地址不再是 N100 分配的那个。

### 13.3 没有浏览器的设备怎么办

编码器、NVR、打印机没法输账号密码。硬要它们走门户登录是不现实的，所以加了**预授权设备**：

```ts
trustedDevices: [{ id, label, macHash, lineId }]
```

- 设备侧按 MAC 摘要匹配 DHCP 租约，拿到 IP 后直接 `seedTrusted()` 写进会话表，`pinned: true`。
- 预授权设备**不参与「一账号一设备」的名额**，也**不会被 5 分钟宽限期清理**。
- 线路在编译期就要有入站端口，所以 `trustedDevices` 里的 `lineId` 会一并纳入 `linePorts`。

这条不是可选项：直播场景里编码器就是主力终端，它上不了网，整个产品没意义。

### 13.4 顺带修掉的一个真实风险

`tproxy` 链最前面加了 `ip daddr <lan.cidr> accept`。原因是：如果内核开了 `br_netfilter`（部分发行版默认开），二层转发的同网段流量会经过 netfilter 的 prerouting，**可能被 tproxy 劫进 sing-box**，表现为「互访时好时坏」。把同网段目标直接放行，成本一条规则，省掉一类玄学故障。
