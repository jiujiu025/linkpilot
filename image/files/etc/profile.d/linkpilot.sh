# LinkPilot 登录提示（/etc/profile 会 source 本目录下所有 *.sh）
[ -n "$PS1" ] || return 0

echo ""
echo "  LinkPilot $(cat /etc/linkpilot/version 2>/dev/null || echo dev)  ·  $(uci -q get system.@system[0].hostname 2>/dev/null)"
if [ -f /etc/linkpilot/paused ]; then
	echo "  ** Agent 处于暂停状态（lp-rescue resume 恢复）**"
fi
echo "  自检 lp-status   ·   救急 lp-rescue   ·   注册 lp-enroll"
echo ""
