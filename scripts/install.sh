#!/usr/bin/env bash
#
# LinkPilot 一键部署（Debian 12 / Ubuntu 22.04+，x86_64 / arm64）
#
# 一条命令做完：依赖 → Node 22 → sing-box → 云端（可选同机）→ 网络基线
#              → systemd 服务 → 启动 → 自检
#
# 最省事的用法（云端和网关跑在同一台 N100 上，零配置）：
#   sudo bash install.sh
#
# 其他用法：
#   sudo bash install.sh --cloud http://1.2.3.4:18080 --token xxxx --yes
#   sudo bash install.sh --wan enp1s0 --lan "enp2s0 enp3s0" --skip-network
#
set -euo pipefail

CLOUD_URL="${LP_CLOUD_URL:-}"
ENROLL_TOKEN="${LP_ENROLL_TOKEN:-}"
PORTAL_PORT="${LP_PORTAL_PORT:-8080}"
CONTROL_PORT="${LP_CONTROL_PORT:-18080}"
ADMIN_TOKEN="${LP_ADMIN_TOKEN:-}"
GATEWAY_IP="${GATEWAY_IP:-192.168.10.1}"
WAN_IF=""
LAN_IFS=""
ASSUME_YES=0
SKIP_NETWORK=0
LOCAL_CLOUD=""          # "" 未决定 / 1 同机 / 0 远程
NODE_VERSION="${NODE_VERSION:-22.22.0}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.11.15}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_ROOT="${DATA_ROOT:-/var/lib/linkpilot}"

cyan() { printf '\n\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ask()  { printf '  %s' "$1"; read -r _ans; echo "$_ans"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --cloud) CLOUD_URL="$2"; LOCAL_CLOUD=0; shift 2 ;;
    --token) ENROLL_TOKEN="$2"; shift 2 ;;
    --port) PORTAL_PORT="$2"; shift 2 ;;
    --wan) WAN_IF="$2"; shift 2 ;;
    --lan) LAN_IFS="$2"; shift 2 ;;
    --local-cloud) LOCAL_CLOUD=1; shift ;;
    --skip-network) SKIP_NETWORK=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) die "未知参数：$1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo bash $0"

printf '\033[1mLinkPilot 一键部署\033[0m\n'
echo "  代码目录  $REPO_DIR"
echo "  数据目录  $DATA_ROOT"

# ---------------------------------------------------------------- 1. 依赖
cyan "[1/7] 系统依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates xz-utils nftables dnsmasq iproute2 jq >/dev/null
ok "nftables / dnsmasq / iproute2 就绪"

# ---------------------------------------------------------------- 2. Node
cyan "[2/7] Node 运行时"
NODE_OK=0
if command -v node >/dev/null 2>&1 \
   && node -e 'const[a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=18)?0:1)'; then
  NODE_OK=1
  ok "已有 Node v$(node -p 'process.versions.node')"
fi
if [ "$NODE_OK" -eq 0 ]; then
  case "$(uname -m)" in
    x86_64|amd64) NA=x64 ;;
    aarch64|arm64) NA=arm64 ;;
    *) die "不支持的架构：$(uname -m)" ;;
  esac
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NA}.tar.xz" -o /tmp/node.tar.xz \
    || die "下载 Node 失败；离线安装请把 tarball 放到 /tmp/node.tar.xz 后重跑"
  mkdir -p /usr/local/lib/nodejs
  tar -xJf /tmp/node.tar.xz -C /usr/local/lib/nodejs
  ln -sf "/usr/local/lib/nodejs/node-v${NODE_VERSION}-linux-${NA}/bin/node" /usr/local/bin/node
  ln -sf "/usr/local/lib/nodejs/node-v${NODE_VERSION}-linux-${NA}/bin/npm" /usr/local/bin/npm
  rm -f /tmp/node.tar.xz
  ok "已安装 Node v$NODE_VERSION"
fi

# ---------------------------------------------------------------- 3. sing-box
cyan "[3/7] 代理内核"
if [ -x /usr/local/bin/sing-box ]; then
  ok "已存在 $(/usr/local/bin/sing-box version 2>/dev/null | head -1)"
else
  case "$(uname -m)" in
    x86_64|amd64) SA=amd64 ;;
    aarch64|arm64) SA=arm64 ;;
    *) die "不支持的架构：$(uname -m)" ;;
  esac
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SA}.tar.gz" -o /tmp/sb.tar.gz \
    || die "下载 sing-box 失败"
  tar -xzf /tmp/sb.tar.gz -C /tmp
  install -m 0755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SA}/sing-box" /usr/local/bin/sing-box
  rm -rf /tmp/sb.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SA}"
  ok "已安装 sing-box v$SINGBOX_VERSION"
fi

mkdir -p "$DATA_ROOT/agent" "$DATA_ROOT/cloud" /etc/linkpilot

# ---------------------------------------------------------------- 4. 云端
cyan "[4/7] 云端控制面"
if [ -z "$LOCAL_CLOUD" ]; then
  if [ -z "$CLOUD_URL" ]; then
    echo "  云端和网关是否跑在同一台机器上？"
    echo "    y = 是（最省事，本机既管设备又做网关）"
    echo "    n = 否（已有独立云端，等下让你填地址）"
    _answer="$(ask '选择 [Y/n]：')"
    case "$_answer" in n|N) LOCAL_CLOUD=0 ;; *) LOCAL_CLOUD=1 ;; esac
  else
    LOCAL_CLOUD=0
  fi
fi

if [ "$LOCAL_CLOUD" -eq 1 ]; then
  if [ -z "$ADMIN_TOKEN" ]; then
    ADMIN_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
  fi
  cat > /etc/linkpilot/cloud.env <<EOF
LP_DATA_DIR=$DATA_ROOT/cloud
LP_CONTROL_PORT=$CONTROL_PORT
LP_CONTROL_HOST=0.0.0.0
LP_ADMIN_TOKEN=$ADMIN_TOKEN
EOF
  chmod 600 /etc/linkpilot/cloud.env

  cat > /etc/systemd/system/linkpilot-cloud.service <<EOF
[Unit]
Description=LinkPilot Control Plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
EnvironmentFile=/etc/linkpilot/cloud.env
ExecStart=/usr/local/bin/node $REPO_DIR/src/control/main.ts
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable -q linkpilot-cloud
  systemctl restart linkpilot-cloud
  sleep 3

  # 首次启动会 seed 并写出注册令牌，直接拿来用，不用人肉复制
  for _ in 1 2 3 4 5; do
    [ -f "$DATA_ROOT/cloud/enrollment-token.txt" ] && break
    sleep 1
  done
  if [ -f "$DATA_ROOT/cloud/enrollment-token.txt" ]; then
    ENROLL_TOKEN="$(cat "$DATA_ROOT/cloud/enrollment-token.txt")"
    CLOUD_URL="http://127.0.0.1:${CONTROL_PORT}"
    ok "云端已启动，注册令牌已自动读取"
  else
    warn "云端已启动但没读到注册令牌，稍后到后台重新签发"
  fi
  ADMIN_URL="http://${GATEWAY_IP}:${CONTROL_PORT}/admin"
else
  while [ -z "$CLOUD_URL" ]; do
    CLOUD_URL="$(ask '云端地址（如 http://1.2.3.4:18080）：')"
  done
  if [ -z "$ENROLL_TOKEN" ]; then
    ENROLL_TOKEN="$(ask '注册令牌（可留空，稍后填 agent.env）：')"
  fi
  ok "使用远程云端 $CLOUD_URL"
  ADMIN_URL="http://${CLOUD_URL#http://}"
fi

# ---------------------------------------------------------------- 5. 网络
cyan "[5/7] 网络基线"
if [ "$SKIP_NETWORK" -eq 1 ]; then
  warn "按参数跳过（假定网络已配好）"
  ALLOW_NO_UCI=0
else
  ALLOW_NO_UCI=1
  auto_wan="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  [ -n "$WAN_IF" ] || WAN_IF="$auto_wan"
  [ -n "$WAN_IF" ] || die "找不到默认路由网口，请用 --wan 指定"
  if [ -z "$LAN_IFS" ]; then
    LAN_IFS="$(ip -br link | awk '$1 ~ /^(en|eth)/ {print $1}' | grep -v "^${WAN_IF}$" | tr '\n' ' ')"
  fi
  [ -n "$LAN_IFS" ] || die "找不到可用 LAN 网口，请用 --lan 指定"

  echo "  WAN: $WAN_IF"
  echo "  LAN: $LAN_IFS"
  if [ "$ASSUME_YES" -eq 0 ]; then
    _answer="$(ask "将把上述 LAN 口建成网桥、网关设为 $GATEWAY_IP，继续？[Y/n]：")"
    case "$_answer" in n|N) die "已取消" ;; esac
  fi

  cat > /etc/sysctl.d/90-linkpilot.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
  sysctl --system >/dev/null

  BR=br0
  ip link show "$BR" >/dev/null 2>&1 || ip link add name "$BR" type bridge
  ip link set "$BR" up
  ip addr flush dev "$BR" || true
  ip addr add "${GATEWAY_IP}/24" dev "$BR"
  for port in $LAN_IFS; do
    ip link set "$port" master "$BR" 2>/dev/null || true
    ip link set "$port" up
  done
  ip link set "$WAN_IF" up

  # 开机要把网桥重新建起来：ip 命令不持久化，只写 interfaces 文件在 Debian 13 上
  # 还需要 bridge-utils，出问题时表现为「重启后 LAN 没了、手机拿不到 IP」。
  # 这里用一条 oneshot 单元重放同样的命令，幂等且不依赖 ifupdown 的实现细节。
  cat > /usr/local/sbin/linkpilot-network.sh <<NETEOF
#!/bin/sh
set -e
BR=$BR
ip link show \$BR >/dev/null 2>&1 || ip link add name \$BR type bridge
ip link set \$BR up
ip addr flush dev \$BR || true
ip addr add ${GATEWAY_IP}/24 dev \$BR
for port in $LAN_IFS; do
  ip link set \$port master \$BR 2>/dev/null || true
  ip link set \$port up
done
ip link set $WAN_IF up
NETEOF
  chmod 0755 /usr/local/sbin/linkpilot-network.sh

  cat > /etc/systemd/system/linkpilot-network.service <<'UNITEOF'
[Unit]
Description=LinkPilot network baseline (bridge + LAN address)
After=network.target
Before=dnsmasq.service linkpilot-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/linkpilot-network.sh

[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload
  systemctl enable -q linkpilot-network

  cat > /etc/dnsmasq.d/linkpilot.conf <<EOF
interface=$BR
bind-dynamic
except-interface=$WAN_IF
dhcp-range=192.168.10.50,192.168.10.250,12h
dhcp-option=option:router,$GATEWAY_IP
dhcp-option=option:dns-server,$GATEWAY_IP
port=0
no-hosts
EOF
  systemctl restart dnsmasq
  ok "网桥 $BR = $GATEWAY_IP · DHCP 192.168.10.50–250 · 转发开启 · IPv6 关闭"

  # WAN 没拿到地址就是没外网，装完也拉不到云端，必须当场提示
  if ! ip -4 addr show "$WAN_IF" | grep -q "inet "; then
    warn "WAN($WAN_IF) 还没有 IPv4 地址：如果是光猫拨号，请确认该网口已配置 DHCP；PPPoE 需另配 pppoeconf"
  fi
  warn "刻意不配 NAT：出网必须走代理，配了就绕过 Kill Switch"
fi

# ---------------------------------------------------------------- 6. Agent
cyan "[6/7] Router Agent"
cat > /etc/linkpilot/agent.env <<EOF
LP_AGENT_DIR=$DATA_ROOT/agent
LP_CLOUD_URL=$CLOUD_URL
LP_ENROLL_TOKEN=$ENROLL_TOKEN
LP_DRY_RUN=0
LP_PORTAL_HOST=0.0.0.0
LP_PORTAL_PORT=$PORTAL_PORT
LP_ALLOW_NO_UCI=$ALLOW_NO_UCI
EOF
chmod 600 /etc/linkpilot/agent.env

cat > /usr/local/bin/linkpilot-singbox <<'EOF'
#!/bin/sh
set -e
ROOT="${LP_AGENT_DIR:-/var/lib/linkpilot/agent}/routing"
[ -f "$ROOT/active.json" ] || { echo "还没有 active 版本，等 Agent 首次下发" >&2; exit 0; }
REV="$(sed -n 's/.*"revision":[[:space:]]*\([0-9]\+\).*/\1/p' "$ROOT/active.json" | head -1)"
CONF="$ROOT/revisions/r${REV}/singbox.json"
[ -f "$CONF" ] || { echo "配置不存在：$CONF" >&2; exit 1; }
exec /usr/local/bin/sing-box run -c "$CONF"
EOF
chmod 0755 /usr/local/bin/linkpilot-singbox

cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=LinkPilot sing-box (active revision)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/linkpilot-singbox
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/linkpilot-agent.service <<EOF
[Unit]
Description=LinkPilot Router Agent
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
EnvironmentFile=/etc/linkpilot/agent.env
ExecStart=/usr/local/bin/node $REPO_DIR/src/agent/main.ts
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/linkpilot <<'EOF'
#!/bin/sh
case "${1:-status}" in
  status)
    systemctl --no-pager --lines=0 status linkpilot-agent sing-box 2>/dev/null | grep -E 'Active:|●' || true
    systemctl is-active linkpilot-cloud >/dev/null 2>&1 && echo "  云端：运行中"
    ip -br addr show br0 2>/dev/null || echo "  （没有 br0）"
    ;;
  logs) journalctl -u linkpilot-agent -f ;;
  update)
    if [ ! -d "$REPO_DIR/.git" ]; then
      echo "代码目录不是 git 仓库，无法自动更新：$REPO_DIR" >&2
      exit 1
    fi
    git -C "$REPO_DIR" fetch --depth 1 origin main && git -C "$REPO_DIR" reset --hard FETCH_HEAD
    systemctl restart linkpilot-agent
    echo "已更新到最新代码并重启 Agent"
    ;;
  restart) systemctl restart linkpilot-agent; echo "已重启" ;;
  check)
    echo "--- 防火墙 ---"; nft list table inet linkpilot 2>/dev/null | head -20 || echo "规则未加载"
    echo "--- 会话 ---"; nft list set inet linkpilot authed_v4 2>/dev/null | head -10
    echo "--- 端口 ---"; ss -lnptu 2>/dev/null | grep -E ':(10000|10001|8080|53)\b' || true
    ;;
  *) echo "用法: linkpilot {status|logs|check|restart|update}" ;;
esac
EOF
chmod 0755 /usr/local/bin/linkpilot

systemctl daemon-reload
systemctl enable -q sing-box linkpilot-agent
systemctl start sing-box
systemctl restart linkpilot-agent
sleep 6
ok "Agent 已启动"

# ---------------------------------------------------------------- 7. 自检
cyan "[7/7] 自检"
AGENT_STATE="$(systemctl is-active linkpilot-agent || true)"
printf '  Agent：%s\n' "$AGENT_STATE"
journalctl -u linkpilot-agent -n 6 --no-pager | sed 's/^/    /'
printf '  门户 %s：' "$PORTAL_PORT"
ss -lnptu 2>/dev/null | grep -q ":${PORTAL_PORT}" && echo "监听中" || echo "未监听（看日志）"

IP_ADDR="$(ip -4 -o addr show br0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
[ -n "$IP_ADDR" ] || IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"

cat <<EOF

══════════════════════════════════════════
 部署完成
══════════════════════════════════════════
 客户门户   http://${IP_ADDR}:${PORTAL_PORT}
 运营后台   ${ADMIN_URL}
 管理令牌   ${ADMIN_TOKEN:-（远程云端，用你自己的令牌）}
 运维命令   linkpilot status | logs | check | restart | update

 接着做四件事（顺序别乱）：
   1. 打开运营后台，粘贴一百条线路 → 自动生成 jy001–jy100
   2. 点「全部测速」，把失败的线路停用
   3. 手机连 AP 的 Wi-Fi，应自动弹登录页，输 jy001 看 IP 是否变化
   4. 拔电源 30 秒再插上，确认自启、手机不用重登

 出问题：linkpilot check 看防火墙与会话，linkpilot logs 看详细日志
EOF
