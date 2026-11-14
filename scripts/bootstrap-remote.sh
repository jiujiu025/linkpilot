#!/usr/bin/env bash
#
# 从 GitHub 拉取并部署（干净机器上的一条命令）
#
# 公开仓库：
#   curl -fsSL https://raw.githubusercontent.com/<owner>/linkpilot/main/scripts/bootstrap-remote.sh | sudo bash
#
# 私有仓库（推荐，仓库里有业务口径）：
#   sudo GH_TOKEN=ghp_xxxx bash -c 'curl -fsSL -H "Authorization: token $GH_TOKEN" \
#     https://raw.githubusercontent.com/<owner>/linkpilot/main/scripts/bootstrap-remote.sh | bash'
#
# 也可以直接 scp 这个脚本上去跑：sudo REPO_URL=... bash bootstrap-remote.sh
#
set -euo pipefail

SLUG="${SLUG:-jiujiu025/linkpilot}"
BRANCH="${BRANCH:-main}"
TARGET="${TARGET:-/opt/linkpilot}"

cyan() { printf '\n\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo）"

cyan "[1/3] 准备 git"
if ! command -v git >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq git ca-certificates >/dev/null
fi
ok "$(git --version)"

# 私有仓库用 token 走 https；公开仓库不需要 token
if [ -n "${GH_TOKEN:-}" ]; then
  REPO_URL="https://x-access-token:${GH_TOKEN}@github.com/${SLUG}.git"
  ok "使用 GH_TOKEN 访问私有仓库 ${SLUG}"
else
  REPO_URL="${REPO_URL:-https://github.com/${SLUG}.git}"
  ok "使用公开地址 ${REPO_URL}"
fi

cyan "[2/3] 获取代码 → ${TARGET}"
if [ -d "${TARGET}/.git" ]; then
  # 已部署过：强制对齐远端，避免本地改动导致后续升级一直冲突
  git -C "$TARGET" fetch --depth 1 origin "$BRANCH"
  git -C "$TARGET" reset --hard FETCH_HEAD
  ok "已更新到最新 ${BRANCH}"
else
  rm -rf "$TARGET"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TARGET"
  ok "已克隆到 ${TARGET}"
fi
# 不要把 token 留在远程地址里
git -C "$TARGET" remote set-url origin "https://github.com/${SLUG}.git"

cyan "[3/3] 开始部署"
exec bash "${TARGET}/scripts/install.sh" "$@"
