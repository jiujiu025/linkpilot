#!/usr/bin/env bash
#
# 网关网络基线（Debian 12 / Ubuntu，只跑一次）
#
# 做四件事：建 LAN 网桥、配网关地址、开 DHCP、关 IPv6。
# 刻意不做 NAT：所有出网必须经代理，否则「Kill Switch」就是一句空话。
#
# 用法：bash network-baseline.sh <WAN口> <LAN口> [更多LAN口...]
#   例：bash network-baseline.sh enp1s0 enp2s0 enp3s0 enp4s0
#
set -euo pipefail

GATEWAY_IP="${GATEWAY_IP:-192.168.10.1}"
CIDR="${CIDR:-24}"
DHCP_START="${DHCP_START:-192.168.10.50}"
DHCP_END="${DHCP_END:-192.168.10.250}"
BRIDGE="${BRIDGE:-br0}"

log() { printf '\033[36m[net]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[net] %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
[ $# -ge 2 ] || die "用法：$0 <WAN口> <LAN口> [更多LAN口...]"

WAN="$1"; shift
LAN_PORTS="$*"

for iface in $WAN $LAN_PORTS; do
  ip link show "$iface" >/dev/null 2>&1 || die "网口不存在：$iface（先跑 ip -br link 看实际名字）"
done

log "WAN=$WAN  LAN=$LAN_PORTS  网桥=$BRIDGE  网关=$GATEWAY_IP/$CIDR"

# ---------------------------------------------------------------- 转发与 IPv6
cat > /etc/sysctl.d/90-linkpilot.conf <<EOF
net.ipv4.ip_forward=1
# tproxy 需要：允许把标了 mark 的包交给本机
net.ipv4.conf.all.route_localnet=1
# IPv6 全关：本产品不做 IPv6 代理，开着就是绕过策略的口子
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
sysctl --system >/dev/null
log "已写入 sysctl（转发开启 / IPv6 关闭）"

# ---------------------------------------------------------------- 网桥
if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
  ip link add name "$BRIDGE" type bridge
  log "已创建网桥 $BRIDGE"
fi
ip link set "$BRIDGE" up
ip addr flush dev "$BRIDGE" || true
ip addr add "${GATEWAY_IP}/${CIDR}" dev "$BRIDGE"
for port in $LAN_PORTS; do
  ip link set "$port" master "$BRIDGE" || true
  ip link set "$port" up
done

# WAN 只保证链路起来；地址由上游（光猫/DHCP）决定
ip link set "$WAN" up

# ---------------------------------------------------------------- DHCP
# dnsmasq 只做 DHCP：DNS 由 LinkPilot 的门户应答器接管（port=0 关掉自带解析）
cat > /etc/dnsmasq.d/linkpilot.conf <<EOF
interface=$BRIDGE
bind-dynamic
except-interface=$WAN
dhcp-range=${DHCP_START},${DHCP_END},12h
dhcp-option=option:router,${GATEWAY_IP}
dhcp-option=option:dns-server,${GATEWAY_IP}
# 关掉自带 DNS：未登录设备的解析由门户应答器处理，已登录的由 tproxy 转给对应线路
port=0
# 不要读 /etc/hosts 干扰
no-hosts
EOF
systemctl restart dnsmasq
log "dnsmasq 已按 $DHCP_START–$DHCP_END 下发 DHCP"

# ---------------------------------------------------------------- 持久化
if [ -d /etc/network/interfaces.d ]; then
  cat > /etc/network/interfaces.d/linkpilot.cfg <<EOF
# 由 LinkPilot 生成：LAN 网桥
auto $BRIDGE
iface $BRIDGE inet static
    address ${GATEWAY_IP}/${CIDR}
    bridge_ports $LAN_PORTS
    bridge_stp off
    bridge_fd 0
EOF
  log "已写入 /etc/network/interfaces.d/linkpilot.cfg（重启后仍生效）"
else
  log "未找到 ifupdown；若用 systemd-networkd，请把上面的网桥配置改写成 .netdev/.network"
fi

cat <<EOF

完成。检查：
  ip -br addr show $BRIDGE          # 应看到 ${GATEWAY_IP}/${CIDR}
  ip route                          # 默认路由应指向 WAN
  systemctl status dnsmasq --no-pager

接下来启动 LinkPilot：
  systemctl start sing-box linkpilot-agent
  journalctl -u linkpilot-agent -f
EOF
