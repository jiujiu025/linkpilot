#!/usr/bin/env bash
#
# 现场装配包（不依赖 Docker）
#
# 用途：在没有 Linux 构建环境时，先把 Agent 与 overlay 打成一个小包，
# scp 到已经刷好官方 OpenWrt 的 N100 上执行 provision.sh 落地。
#
# 与 firmware 构建的区别：
#   - 快（十几秒），现在就能用，适合软件层验证与现场补丁；
#   - 但用的是官方默认分区（104MB 根分区），装不下太多东西，量产仍应走 image/build.sh。
#
# 用法：
#   bash image/make-kit.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."
TAG="${IMAGE_TAG:-kit-$(date +%Y%m%d-%H%M)}"
OUT="dist/$TAG"
KIT="$OUT/linkpilot"

echo "== 打包 Agent =="
rm -rf "$OUT"
mkdir -p "$KIT/root/opt/linkpilot"

npx --yes esbuild@0.25.10 src/agent/main.ts \
  --bundle --platform=node --target=node18 --format=esm \
  --legal-comments=none \
  --outfile="$KIT/root/opt/linkpilot/agent.mjs"

SIZE=$(wc -c < "$KIT/root/opt/linkpilot/agent.mjs")
[ "$SIZE" -gt 10000 ] || { echo "打包产物异常（${SIZE}B）" >&2; exit 1; }

echo "== 组装 overlay =="
cp -a image/files/. "$KIT/root/"
printf '%s\n' "$TAG" > "$KIT/root/etc/linkpilot/version"
cp image/provision.sh image/packages.list "$KIT/"
chmod +x "$KIT/provision.sh"

echo "== 生成压缩包 =="
( cd "$OUT" && tar -czf "../$TAG.tar.gz" linkpilot )

cat > "$OUT/HOWTO.txt" <<EOF
1) 在 N100 上刷官方 OpenWrt 24.10.8 x86/64（squashfs-combined-efi），开机联网
2) scp $TAG.tar.gz root@192.168.1.1:/tmp/
3) ssh root@192.168.1.1
   cd /tmp && tar xzf $TAG.tar.gz && cd linkpilot && ./provision.sh
4) 装配完执行 lp-status 自检；注册用 lp-enroll <云端地址> <令牌>
EOF

echo
echo "产物： dist/$TAG.tar.gz  ($(du -h "dist/$TAG.tar.gz" | cut -f1))"
cat "$OUT/HOWTO.txt"
