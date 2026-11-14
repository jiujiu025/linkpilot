#!/usr/bin/env bash
#
# LinkPilot 固件一键构建（宿主机侧，Windows Git Bash / macOS / Linux 通用）
#
# 做的事：把源码打包成单文件 Agent → 拷进 OpenWrt overlay → 用 ImageBuilder 生成
# x86_64 固件 → 产物落到 dist/。全程在 Docker 里跑，宿主机不需要 Linux 环境、
# 不需要交叉编译链。
#
# 用法：
#   bash image/build.sh
#   LP_ENROLL_TOKEN=<令牌> LP_CLOUD_URL=https://cloud.example.com bash image/build.sh
#
# 环境变量：
#   OPENWRT_VERSION   目标版本，默认 24.10.8
#   IMAGE_TAG         产物名后缀，默认 linkpilot-<日期>
#   ROOTFS_PARTSIZE   根分区大小(MB)，默认 2048（node+sing-box 占 40MB+，150MB 默认值不够用）
#   LP_CLOUD_URL      写进固件的云端地址
#   LP_ENROLL_TOKEN   写进固件的一次性注册令牌（量产按设备注入，不要外泄）
#
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.8}"
IMAGE_TAG="${IMAGE_TAG:-linkpilot-$(date +%Y%m%d)}"
ROOTFS_PARTSIZE="${ROOTFS_PARTSIZE:-2048}"
DOCKER_IMAGE="${DOCKER_IMAGE:-node:22-bookworm-slim}"

# Windows 下 Git Bash 的 /c/... 路径 Docker 不认，优先取 -W（Windows 形式）
HOST_ROOT="$(pwd -W 2>/dev/null || pwd)"

echo "== 检查 Docker =="
if ! docker info >/dev/null 2>&1; then
  echo "!! Docker 不可用。构建依赖 Linux 容器（ImageBuilder 不能在 Windows/macOS 直接跑）。" >&2
  echo "   请启动 Docker Desktop 后重试；没有 Docker 时可在任意 Linux 机器上执行 image/build-inner.sh。" >&2
  exit 1
fi

echo "== 参数 =="
echo "   仓库     $REPO_ROOT"
echo "   OpenWrt  $OPENWRT_VERSION (x86/64)"
echo "   产物名   $IMAGE_TAG"
echo "   根分区   ${ROOTFS_PARTSIZE}MB"

# MSYS 会把容器里的绝对路径（/work、/tmp）改写成 Windows 路径，必须关掉
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOST_ROOT:/work" \
  -w /work \
  -e OPENWRT_VERSION="$OPENWRT_VERSION" \
  -e IMAGE_TAG="$IMAGE_TAG" \
  -e ROOTFS_PARTSIZE="$ROOTFS_PARTSIZE" \
  -e LP_CLOUD_URL="${LP_CLOUD_URL:-}" \
  -e LP_ENROLL_TOKEN="${LP_ENROLL_TOKEN:-}" \
  "$DOCKER_IMAGE" \
  bash /work/image/build-inner.sh

echo
echo "== 完成 =="
ls -lh "dist/$IMAGE_TAG" 2>/dev/null || true
