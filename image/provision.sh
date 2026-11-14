#!/bin/sh
#
# 在已刷好的官方 OpenWrt 上落地 LinkPilot（现场装配路径，不依赖构建机）
#
#   ./provision.sh                          # 装包 + 铺 overlay + 自启
#   ./provision.sh --cloud https://x --token abc   # 顺便注册
#
# 幂等：重复执行只会覆盖文件与重装包，不会破坏 /etc/linkpilot/data 里的身份与版本。
# 前提：设备能出网（opkg 要下载包），根分区剩余空间 >= 90MB。

set -e

KIT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT="$KIT_DIR/root"
CLOUD_URL=""
TOKEN=""

while [ $# -gt 0 ]; do
	case "$1" in
		--cloud) CLOUD_URL="$2"; shift 2 ;;
		--token) TOKEN="$2"; shift 2 ;;
		-h|--help)
			echo "用法: $0 [--cloud <云端地址>] [--token <令牌>]"
			exit 0 ;;
		*) echo "未知参数: $1" >&2; exit 1 ;;
	esac
done

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

say "环境检查"
[ -f /etc/openwrt_release ] || die "这不是 OpenWrt，别在这台机器上跑"
. /etc/openwrt_release
echo "  $DISTRIB_DESCRIPTION"
echo "  架构 $DISTRIB_ARCH"
case "$DISTRIB_ARCH" in
	x86_64) ;;
	*) echo "  警告：本包按 x86_64 目标准备，其他架构需要重新打包" ;;
esac
[ -d "$ROOT" ] || die "缺少 $ROOT，压缩包不完整"

AVAIL_KB=$(df -k /overlay 2>/dev/null | awk 'NR==2 {print $4}')
echo "  根分区可用 ${AVAIL_KB:-?}KB"
if [ "${AVAIL_KB:-0}" -lt 90000 ]; then
	echo "  警告：可用空间不足 90MB，node + sing-box 可能装不下。"
	echo "        建议改用 image/build.sh 产出大分区固件（ROOTFS_PARTSIZE=2048）。"
fi

say "安装软件包"
# 包清单来自 image/packages.list；这里跳过 LuCI（现场装配省空间，需要时手工 opkg install luci）
PKGS=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$KIT_DIR/packages.list" | grep -v '^[[:space:]]*$' | tr '\n' ' ')
echo "  $PKGS"
opkg update
# shellcheck disable=SC2086
opkg install $PKGS || die "装包失败（先确认能出网：ping -c1 downloads.openwrt.org）"

say "铺设 overlay"
cp -a "$ROOT"/. /
for f in /etc/init.d/linkpilot /usr/sbin/lp-agent-run /usr/sbin/lp-status /usr/sbin/lp-rescue /usr/sbin/lp-enroll; do
	[ -f "$f" ] && chmod 0755 "$f"
done
chmod 600 /etc/linkpilot/agent.env 2>/dev/null
mkdir -p /etc/linkpilot/data/routing
chmod 700 /etc/linkpilot/data

say "执行首启基线（uci-defaults 不会自动重跑，这里手工执行一次）"
for f in /etc/uci-defaults/*linkpilot*; do
	[ -f "$f" ] || continue
	echo "  $(basename "$f")"
	sh "$f" && rm -f "$f"
done

say "启用服务"
mkdir -p /etc/rc.d
ln -sf ../init.d/linkpilot /etc/rc.d/S99linkpilot
/etc/init.d/network reload 2>/dev/null || true
/etc/init.d/linkpilot enable 2>/dev/null || true
/etc/init.d/linkpilot restart 2>/dev/null || true

if [ -n "$CLOUD_URL" ] && [ -n "$TOKEN" ]; then
	say "注册到云端"
	/usr/sbin/lp-enroll "$CLOUD_URL" "$TOKEN" || true
fi

say "完成"
cat <<EOF
下一步：
  1. 网口划分已按"eth0=WAN、其余=LAN"写入，LAN 地址 192.168.88.1
     （官方镜像原本是 192.168.1.1，改完请用新地址访问）
  2. 若需要 LuCI：opkg install luci && /etc/init.d/uhttpd restart
  3. 自检：lp-status
  4. 注册：lp-enroll <云端地址> <一次性令牌>
  5. 失联救急：lp-rescue
EOF
