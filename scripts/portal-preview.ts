/**
 * 生成门户静态预览页（不启动 Agent）
 *
 * 用途：在没有设备、没有云端的情况下评审 UI 与信息结构。
 * 预览页里注入了一个只读的 fetch stub，数据和真实快照同构。
 */
import fs from 'node:fs';
import path from 'node:path';
import { renderPortalHtml } from '../src/agent/portal-ui.ts';

const snapshot = {
  device: {
    id: 'dev-ax3000t-001',
    model: 'N100 小主机（4×2.5G 网口）',
    health: 'healthy',
    activeRevision: 7,
    digestShort: 'cb2bb19d8fc9',
    lastApply: 'r7 已应用（dry-run）',
    cloudReachable: true,
  },
  wifi: { enabled: false, ssid: 'LinkPilot-WiFi', band: '2.4+5' },
  exit: { lineName: '香港-01', region: '香港' },
  clients: [
    {
      id: 'cl-codec',
      label: '直播间-编码器',
      ip: '192.168.10.20',
      state: 'authorized',
      attach: 'lan',
      primaryLine: '香港-01',
      primaryLineId: 'line-hk-1',
      standbyLine: '新加坡-01',
      profileName: '严格全局代理',
    },
    {
      id: 'cl-camera',
      label: '摄像机-B',
      ip: '192.168.10.21',
      state: 'authorized',
      attach: 'wifi',
      primaryLine: '香港-01',
      primaryLineId: 'line-hk-1',
      standbyLine: '新加坡-01',
      profileName: '大陆直连 / 其他代理',
    },
    {
      id: 'cl-laptop',
      label: '笔记本（待授权）',
      ip: '192.168.10.31',
      state: 'pending',
      attach: 'wifi',
      primaryLine: null,
      primaryLineId: null,
      standbyLine: null,
      profileName: null,
    },
  ],
  profiles: [
    { id: 'profile-strict', name: '严格全局代理' },
    { id: 'profile-cn', name: '大陆直连 / 其他代理' },
  ],
  lines: [
    { id: 'line-hk-1', name: '香港-01', region: '香港' },
    { id: 'line-sg-1', name: '新加坡-01', region: '新加坡' },
    { id: 'line-us-1', name: '洛杉矶-01', region: '美国' },
  ],
  diagnostics: [
    { name: '云端控制通道', detail: '签名通道正常', status: 'ok' },
    { name: '配置签名与版本', detail: '当前 r7 · cb2bb19d8fc9', status: 'ok' },
    { name: '代理核心', detail: 'dry-run 模式：未启动代理核心', status: 'warn' },
    { name: 'IPv6 与 DNS 防泄露', detail: 'IPv6 默认关闭，DNS 强制接管', status: 'ok' },
    { name: '未授权设备隔离', detail: '转发链默认拒绝，未授权设备仅可访问门户', status: 'ok' },
  ],
};

const me = { username: 'admin', role: 'device_admin', displayName: '玖夜', exp: Date.now() + 3600_000 };

const stub = `<script>
/* 预览模式：仅本地静态评审用，数据为样例快照，无任何真实凭证 */
(function () {
  var me = ${JSON.stringify(me)};
  var snapshot = ${JSON.stringify(snapshot)};
  window.fetch = function (url, options) {
    var body = { ok: true };
    if (String(url).indexOf('/api/portal/me') === 0) body = { ok: true, me: me };
    else if (String(url).indexOf('/api/portal/state') === 0) body = { ok: true, me: me, snapshot: snapshot };
    return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve(body); } });
  };
})();
</script>
`;

const html = renderPortalHtml();
const marker = '<script>\n(function () {';
if (!html.includes(marker)) throw new Error('门户模板结构变化，预览注入点失效');

const outDir = path.resolve('runtime/preview');
fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, 'portal.html');
fs.writeFileSync(outFile, html.replace(marker, `${stub}${marker}`), 'utf8');
console.log(`门户预览已生成：${outFile}`);
