#!/usr/bin/env bash
#
# 在 Linux 容器内执行的实际构建流程。由 build.sh 调用，也可以在任意 Linux 机器上直接跑：
#   OPENWRT_VERSION=24.10.8 bash image/build-inner.sh
#
# 步骤：装依赖 → 打包 Agent 单文件 → 下载 ImageBuilder → 组装 overlay → 生成固件 → 校验产物。
# 任一步失败即中止：宁可没有固件，也不要一个"看起来能刷"的半成品。
#
set -euo pipefail

OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.8}"
IMAGE_TAG="${IMAGE_TAG:-linkpilot-dev}"
ROOTFS_PARTSIZE="${ROOTFS_PARTSIZE:-2048}"
TARGET_SUB="x86/64"
PROFILE="generic"
BUILD_ROOT=/tmp/lpbuild
ART_SUBDIR="bin/targets/x86/64"

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\n!! %s\n' "$*" >&2; exit 1; }

[ -d /work ] || die "找不到 /work（应在仓库根目录挂载）"
[ -f /work/image/packages.list ] || die "找不到 image/packages.list"

say "1/6 安装构建依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  curl ca-certificates xz-utils zstd make gawk python3 file unzip >/dev/null

say "2/6 打包 Agent（esbuild 单文件，避免依赖目标机的 TS 运行时能力）"
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT/srcroot" "$BUILD_ROOT/bundle" "$BUILD_ROOT/overlay"

# 复制到临时目录再安装依赖：node_modules 是 bind mount 进来的宿主机目录，
# 在容器里装包会把它改写成 Linux 版本，污染开发机。
( cd /work && tar -cf - src package.json package-lock.json tsconfig.json ) \
  | ( cd "$BUILD_ROOT/srcroot" && tar -xf - )

cd "$BUILD_ROOT/srcroot"
npm ci --omit=dev --no-audit --no-fund --loglevel=error
npm install --no-save --no-audit --no-fund --loglevel=error esbuild@latest

npx --no-install esbuild src/agent/main.ts \
  --bundle \
  --platform=node \
  --target=node18 \
  --format=esm \
  --legal-comments=none \
  --outfile="$BUILD_ROOT/bundle/agent.mjs"

SIZE=$(stat -c%s "$BUILD_ROOT/bundle/agent.mjs")
[ "$SIZE" -gt 10000 ] || die "打包产物只有 ${SIZE}B，esbuild 没有真正打进依赖"
echo "   agent.mjs  ${SIZE} 字节"

# 模块可加载性检查：能 import 且导出了 runAgent，说明依赖图完整、没有裸模块漏网
cat > "$BUILD_ROOT/bundle/check.mjs" <<'CHECK'
const mod = await import('./agent.mjs');
if (typeof mod.runAgent !== 'function') {
  console.error('bundle 缺少 runAgent 导出');
  process.exit(3);
}
console.log('bundle ok: runAgent 已导出');
CHECK
( cd "$BUILD_ROOT/bundle" && node check.mjs ) || die "打包产物无法在 Node 下加载"

say "3/6 下载 ImageBuilder $OPENWRT_VERSION"
IB_NAME="openwrt-imagebuilder-${OPENWRT_VERSION}-x86-64.Linux-x86_64"
IB_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${TARGET_SUB}/${IB_NAME}.tar.zst"
curl -fSL --retry 3 --connect-timeout 20 -o "$BUILD_ROOT/ib.tar.zst" "$IB_URL" \
  || die "下载 ImageBuilder 失败：$IB_URL"
tar --zstd -xf "$BUILD_ROOT/ib.tar.zst" -C "$BUILD_ROOT"
IB_DIR="$BUILD_ROOT/$IB_NAME"
[ -d "$IB_DIR" ] || die "解压后没有 $IB_NAME 目录"

say "4/6 组装 overlay"
cp -a /work/image/files/. "$BUILD_ROOT/overlay/"
install -m 0755 "$BUILD_ROOT/bundle/agent.mjs" "$BUILD_ROOT/overlay/opt/linkpilot/agent.mjs"
printf '%s\n' "$IMAGE_TAG" > "$BUILD_ROOT/overlay/etc/linkpilot/version"
printf 'openwrt-%s\n' "$OPENWRT_VERSION" > "$BUILD_ROOT/overlay/etc/linkpilot/openwrt-version"

# 脚本可执行位：Windows 上 git 检出的文件权限不可靠，这里统一纠正
for f in etc/uci-defaults/* etc/init.d/* usr/sbin/*; do
  [ -f "$BUILD_ROOT/overlay/$f" ] && chmod 0755 "$BUILD_ROOT/overlay/$f"
done

# 开机自启：直接建好 rc.d 符号链接，保证首次开机就跑起来。
# 依赖 uci-defaults 里的 enable 会赶不上本次 boot（rcS 的启动列表在循环前已展开）。
mkdir -p "$BUILD_ROOT/overlay/etc/rc.d"
ln -sf ../init.d/linkpilot "$BUILD_ROOT/overlay/etc/rc.d/S99linkpilot"

# 可选：把云端地址与一次性令牌烧进固件（量产按设备注入；不传则首启后 lp-enroll 现场写入）
ENV_FILE="$BUILD_ROOT/overlay/etc/linkpilot/agent.env"
if [ -n "${LP_CLOUD_URL:-}" ]; then
  sed -i "s|^LP_CLOUD_URL=.*|LP_CLOUD_URL=${LP_CLOUD_URL}|" "$ENV_FILE"
  echo "   云端地址 ${LP_CLOUD_URL}"
fi
if [ -n "${LP_ENROLL_TOKEN:-}" ]; then
  sed -i "s|^LP_ENROLL_TOKEN=.*|LP_ENROLL_TOKEN=${LP_ENROLL_TOKEN}|" "$ENV_FILE"
  echo "   已注入注册令牌（固件内含密钥，分发需受控）"
fi

say "5/6 生成固件（ImageBuilder）"
PKGS=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' /work/image/packages.list | grep -v '^[[:space:]]*$' | tr -d '\r' | tr '\n' ' ')
# dnsmasq-full 与镜像自带的 dnsmasq 冲突，先显式移除
PKGS="-dnsmasq $PKGS"

cd "$IB_DIR"
make image \
  PROFILE="$PROFILE" \
  PACKAGES="$PKGS" \
  FILES="$BUILD_ROOT/overlay" \
  ROOTFS_PARTSIZE="$ROOTFS_PARTSIZE" \
  EXTRA_IMAGE_NAME="$IMAGE_TAG" \
  >"$BUILD_ROOT/make.log" 2>&1 || {
    echo "---- make.log 末尾 ----" >&2
    tail -40 "$BUILD_ROOT/make.log" >&2
    die "ImageBuilder 构建失败"
  }

say "6/6 校验并收集产物"
ls "$IB_DIR/$ART_SUBDIR"/*.img.gz >/dev/null 2>&1 || die "没有生成 .img.gz"

MANIFEST=$(ls "$IB_DIR/$ART_SUBDIR"/*.manifest | head -1)
for must in node sing-box nftables dnsmasq-full; do
  grep -qE "^${must}( |$)" "$MANIFEST" || die "产物清单里缺少 $must，固件不完整"
done
grep -qE '^kmod-tun ' "$MANIFEST" || die "产物清单里缺少 kmod-tun（sing-box tun 需要）"

OUT="/work/dist/$IMAGE_TAG"
mkdir -p "$OUT"
cp "$IB_DIR/$ART_SUBDIR"/*.img.gz "$OUT/"
cp "$IB_DIR/$ART_SUBDIR"/*.manifest "$OUT/manifest.txt"
( cd "$OUT" && sha256sum ./*.img.gz > SHA256SUMS )

{
  echo "image_tag      $IMAGE_TAG"
  echo "openwrt        $OPENWRT_VERSION"
  echo "target         $TARGET_SUB ($PROFILE)"
  echo "rootfs_partsize ${ROOTFS_PARTSIZE}MB"
  echo "built_at       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "agent_bytes    $SIZE"
  echo "packages       $PKGS"
} > "$OUT/BUILD-INFO.txt"

echo
echo "产物："
ls -lh "$OUT"
