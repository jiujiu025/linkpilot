# LinkPilot 固件层（image/）

这一层解决 `docs/impl/实现状态与差距.md` 里挂着的「真实 OpenWrt 固件工程、镜像构建、分区与启动链适配」。
目标只有一个：**把仓库里的代码变成一块能插电就用的系统盘**，N100 刷上它就能当网关。

产物是 x86_64 的 OpenWrt 镜像（UEFI 引导 + squashfs 根 + 2GB overlay），里面已经包含：

- Agent 单文件（`/opt/linkpilot/agent.mjs`，esbuild 打包，含 zod，不依赖目标机的 TS 能力）；
- procd 托管的自启服务 `/etc/init.d/linkpilot`；
- 首启基线：主机名/时区/NTP、WAN-LAN 网口划分、LAN 桥接、DHCP 池、IPv6 三层关闭；
- sing-box、nftables、dnsmasq-full、诊断工具；
- 现场三件套：`lp-status` / `lp-rescue` / `lp-enroll`。

## 一键构建

```bash
# 宿主机只需要 Docker（Windows 装 Docker Desktop，Linux/macOS 装 docker）
bash image/build.sh

# 想把云端地址和一次性令牌直接烧进固件（量产/批量交付用）
LP_CLOUD_URL=https://cloud.example.com LP_ENROLL_TOKEN=<令牌> bash image/build.sh
```

产物落在 `dist/<IMAGE_TAG>/`：

```
openwrt-24.10.8-x86-64-generic-squashfs-combined-efi.img.gz
manifest.txt        实际装进去的包（对数用的，不是给人读的）
BUILD-INFO.txt      版本、包清单、构建时间
SHA256SUMS
```

构建过程全部在 `node:22-bookworm-slim` 容器里跑（ImageBuilder 只能在 Linux 上执行），
宿主机不需要交叉编译链，也不会被改写 `node_modules`。首次构建约 10–20 分钟，主要时间花在下载 ImageBuilder 和软件包。

可选环境变量：`OPENWRT_VERSION`（默认 24.10.8）、`ROOTFS_PARTSIZE`（默认 2048MB，150MB 的默认值装不下 node）、`IMAGE_TAG`。

## overlay 里有什么

| 文件 | 作用 |
|---|---|
| `etc/uci-defaults/10-linkpilot-base` | 首启基线：识别物理网口 → eth0 作 WAN、其余全进 br-lan；LAN 192.168.88.1/24；DHCP 100–199；DNS 指向网关；IPv6 三层关闭 |
| `etc/uci-defaults/20-linkpilot-agent` | 目录与权限、注册 Agent 自启 |
| `etc/init.d/linkpilot` | procd 服务：崩溃重启（5 秒内连崩 5 次才放弃）、`/etc/linkpilot/paused` 时不起 |
| `etc/linkpilot/agent.env` | 设备级配置：云端地址、注册令牌、门户端口、日志级别 |
| `usr/sbin/lp-agent-run` | 启动包装：`set -a` 导入 env 后 exec node，密钥不出现在 `ps` 里 |
| `usr/sbin/lp-status` | 现场自检，一根 SSH 判断机器好坏 |
| `usr/sbin/lp-rescue` | 救急：暂停 Agent、清 nftables、恢复 fw4 与直连 |
| `usr/sbin/lp-enroll` | 现场写入云端地址+令牌并重启 Agent |
| `etc/sysctl.d/11-linkpilot.conf` | IPv6 内核关闭、转发、conntrack 262144、队列缓冲 |

构建时还会做两件事：把 `agent.mjs` 拷进 `opt/linkpilot/`，建好 `/etc/rc.d/S99linkpilot` 符号链接
（uci-defaults 在 boot 阶段执行，那时 rcS 的启动列表已经展开了，靠 `enable` 赶不上本次启动）。

## 刷机

1. 用 balenaEtcher / Rufus（DD 模式）把 `.img.gz` 写到 U 盘或 mSATA/SSD；
   Linux 下：`gunzip -c xxx.img.gz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress`
2. N100 进 BIOS 关掉 Secure Boot，启动模式选 UEFI，把系统盘设为第一启动项；
   **建议同时打开「来电自启 / AC Power Loss → Power On」**，现场断电后没人去按电源键。
3. 首次上电约 30–60 秒，网口全部接上后从 LAN 侧访问 `http://192.168.88.1`（LuCI）或 SSH `root@192.168.88.1`。

> 没有显示器时：把笔记本插到 LAN 口，等 DHCP 拿到 `192.168.88.x` 即可 SSH。拿不到地址就接 HDMI 看控制台。

## 首次开机后验收

```sh
lp-status          # 逐项看，任何 [!!] 都要解决再谈交付
```

必须为 `[ok]` 的项：

- 网口：WAN 有 link 且拿到上游地址，其余 LAN 口 link 正常（2.5G 掉成 100M 是本批硬件的高频问题，`ethtool ethX` 看 Speed）；
- IPv6 已关闭（无全局地址）；
- Agent 进程运行中；
- 云端可达（`HTTP 200/401/404` 都算可达，`000` 是不通）；
- 注册成功后有 `deviceId`；
- `sing-box` 运行中、`nftables` 规则已加载、门户 8088 有响应——这三项要等云端下发第一版配置后才会全绿。

没注册时前两项会红，属正常：执行

```sh
lp-enroll https://<云端地址> <一次性令牌>
```

注册成功后令牌建议清空（一次性）：

```sh
sed -i 's/^LP_ENROLL_TOKEN=.*/LP_ENROLL_TOKEN=/' /etc/linkpilot/agent.env
```

## 现场排障

| 现象 | 先看什么 | 处理 |
|---|---|---|
| 开机后 LAN 拿不到 IP | `lp-status` 的网口段、`/etc/linkpilot/nic-warning` | 网口没识别到（少于 2 个）：`uci show network` 手工补 `brlan.ports`，或换口重试 |
| SSH/门户突然全断，但设备还在跑 | 是不是刚下发过配置 | `lp-rescue` 暂停 Agent、清规则、恢复直连；修完 `lp-rescue resume` |
| Agent 起不来 | `logread -e linkpilot`、`/usr/bin/node -v` | node 缺失说明固件不完整，重刷；`agent.mjs` 缺失同理 |
| 云端一直不可达 | `curl -v $LP_CLOUD_URL`、`date` | 时钟偏差会导致签名失败（`DIGEST_MISMATCH`/`EXPIRED`），先 `ntpd -q -p ntp.aliyun.com` |
| 门户 8088 打不开 | `nft list ruleset \| grep 8088` | 规则里门户只放行 br-lan；从 WAN 侧访问不通是设计如此 |
| 2.5G 只跑 100M | `ethtool ethX` | 换线（很多随机附带的线是 100M 线）、换口，确认对端也是 2.5G |
| 温度高/降频 | `sensors`、`cat /proc/loadavg` | 无风扇 N100 长跑要限功耗或加散热，BIOS 里把 PL1 调低 |

## 量产前必须改的三件事

1. **每台设备独立令牌**：`LP_ENROLL_TOKEN` 烧进固件等于密钥随镜像分发，量产出厂要么按设备注入，要么出厂不烧、现场 `lp-enroll`。
2. **去掉 LuCI**（可选）：`image/packages.list` 里删掉 `luci`、`luci-app-firewall`，客户侧只留门户，减少暴露面。
3. **版本可追溯**：`dist/<TAG>/BUILD-INFO.txt` 与 `manifest.txt` 要和固件一起归档，出问题才能确认那台机器到底跑的是哪版。

## 还没做的

- OTA：Phase 7，当前升级靠重刷或 `sysupgrade`（`/etc/linkpilot/data` 在 overlay 上，sysupgrade 保留配置需自行确认）；
- 分区自动扩容：镜像固定 2GB overlay，换更大盘后需要手工 `resize2fs`（`opkg` 装 `parted`/`e2fsprogs` 后用 `fdisk` 扩分区）；
- ARM 档位（AX3000T）的固件构建：本套流程只覆盖 x86/64，ARM 需要单独的 image profile 与 uboot 适配。
