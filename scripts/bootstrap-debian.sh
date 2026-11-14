#!/usr/bin/env bash
#
# LinkPilot 设备侧一键部署（Debian 12 / Ubuntu 22.04+，x86_64 或 arm64）
#
# 为什么先给 Debian 而不是 OpenWrt：
#   OpenWrt 的软件源里没有 Node 22，官方 Node 二进制又是 glibc 构建，在 musl 上跑不起来。
#   验证阶段用 Debian 能当天跑通数据面；量产再换 OpenWrt + A/B 双槽（见 docs/design/10）。
#
# 用法（root）：
#   REPO_DIR=/opt/linkpilot bash scripts/bootstrap-debian.sh
#   LP_CLOUD_URL=http://1.2.3.4:18080 LP_ENROLL_TOKEN=xxxx bash scripts/bootstrap-debian.sh
#
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/linkpilot}"
NODE_VERSION="${NODE_VERSION:-22.22.0}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.11.15}"
DATA_ROOT="${DATA_ROOT:-/var/lib/linkpilot}"
CLOUD_URL="${LP_CLOUD_URL:-http://127.0.0.1:18080}"
ENROLL_TOKEN="${LP_ENROLL_TOKEN:-}"
PORTAL_PORT="${LP_PORTAL_PORT:-8080}"
# 网络由 network-baseline.sh 预先配好，所以允许 agent 跳过 UCI 步骤
ALLOW_NO_UCI="${LP_ALLOW_NO_UCI:-1}"

log() { printf '\033[36m[bootstrap]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[bootstrap] %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) NODE_ARCH="x64"; SB_ARCH="amd64" ;;
  aarch64|arm64) NODE_ARCH="arm64"; SB_ARCH="arm64" ;;
  *) die "不支持的架构：$ARCH" ;;
esac

log "系统依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates xz-utils nftables dnsmasq iproute2 jq >/dev/null

# ---------------------------------------------------------------- Node 22
need_node=""
if command -v node >/dev/null 2>&1; then
  CURRENT="$(node -p 'process.versions.node')"
  # 项目用原生 TS 类型擦除，22.18 以下跑不起来
  if node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=18)?0:1)'; then
    log "已有 Node v$CURRENT，跳过安装"
  else
    need_node="1"
  fi
else
  need_node="1"
fi

if [ -n "$need_node" ]; then
  log "安装 Node v$NODE_VERSION（官方二进制）"
  TMP="$(mktemp -d)"
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" -o "$TMP/node.tar.xz" \
    || die "下载 Node 失败，检查网络或改用离线包"
  mkdir -p /usr/local/lib/nodejs
  tar -xJf "$TMP/node.tar.xz" -C /usr/local/lib/nodejs
  ln -sf "/usr/local/lib/nodejs/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/node" /usr/local/bin/node
  ln -sf "/usr/local/lib/nodejs/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/npm" /usr/local/bin/npm
  rm -rf "$TMP"
fi
node -v

# ---------------------------------------------------------------- sing-box
if [ ! -x /usr/local/bin/sing-box ]; then
  log "安装 sing-box v$SINGBOX_VERSION"
  TMP="$(mktemp -d)"
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz" -o "$TMP/sb.tar.gz" \
    || die "下载 sing-box 失败；可手工放到 /usr/local/bin/sing-box"
  tar -xzf "$TMP/sb.tar.gz" -C "$TMP"
  install -m 0755 "$TMP/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
  rm -rf "$TMP"
fi
/usr/local/bin/sing-box version | head -2

# ---------------------------------------------------------------- 目录与配置
log "创建目录 $DATA_ROOT"
mkdir -p "$DATA_ROOT/agent" "$DATA_ROOT/cloud" /etc/linkpilot

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

# ---------------------------------------------------------------- sing-box 包装器
# active 指针是原子的 JSON，配置路径会随版本变，所以不能把路径写死在 unit 里
cat > /usr/local/bin/linkpilot-singbox <<'EOF'
#!/bin/sh
set -e
ROOT="${LP_AGENT_DIR:-/var/lib/linkpilot/agent}/routing"
if [ ! -f "$ROOT/active.json" ]; then
  echo "没有 active 版本，等待 Agent 首次下发" >&2
  exit 0
fi
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

cat > /etc/systemd/system/linkpilot-agent.service <<'EOF'
[Unit]
Description=LinkPilot Router Agent
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/linkpilot
EnvironmentFile=/etc/linkpilot/agent.env
ExecStart=/usr/local/bin/node /opt/linkpilot/src/agent/main.ts
Restart=always
RestartSec=5
# 首次注册需要联网；之后云端不可达也会继续本地转发，所以不要设成 on-failure 就放弃

[Install]
WantedBy=multi-user.target
EOF

[ -d "$REPO_DIR" ] || die "代码目录不存在：$REPO_DIR（先把仓库拷进来）"
ln -sfn "$REPO_DIR" /opt/linkpilot

systemctl daemon-reload
systemctl enable sing-box linkpilot-agent >/dev/null

log "部署完成"
cat <<EOF

接下来：
  1. 配网络（只做一次）：bash $REPO_DIR/scripts/network-baseline.sh <WAN口> <LAN口...>
  2. 启动：systemctl start sing-box linkpilot-agent
  3. 看日志：journalctl -u linkpilot-agent -f
  4. 浏览器打开 http://<这台机器的局域网IP>:${PORTAL_PORT}

注意：
  - LP_ENROLL_TOKEN 只在首次注册需要，注册成功后可以从 /etc/linkpilot/agent.env 删掉
  - 本脚本不配 NAT。这是刻意的：所有出网必须走代理，Kill Switch 才有意义
EOF
