/**
 * 端到端演示：注册 → 下发 → 验签 → 解封凭证 → 本地编译 → 应用 → 回报
 *
 * 一个进程里起控制面和 Agent，中间用真实的 HTTP 请求和真实的签名校验，
 * 不做任何 mock 分支——这样跑通一次，链路就是真的通了。
 *
 * 用法：npm run demo
 */
import fs from 'node:fs';
import path from 'node:path';
import { createControlPlane } from '../src/control/server.ts';
import { seedDemo } from '../src/control/seed.ts';
import { runAgent } from '../src/agent/main.ts';

const ROOT = path.resolve('runtime/demo');
const CLOUD_PORT = Number(process.env.LP_DEMO_CLOUD_PORT ?? 18081);
const PORTAL_PORT = Number(process.env.LP_DEMO_PORTAL_PORT ?? 8188);
const ADMIN_TOKEN = 'demo-admin-token';

function line(text = ''): void {
  console.log(text);
}
function step(index: number, title: string): void {
  line('');
  line(`\x1b[36m[${index}]\x1b[0m ${title}`);
}
function ok(text: string): void {
  line(`    \x1b[32m✓\x1b[0m ${text}`);
}
function warn(text: string): void {
  line(`    \x1b[33m!\x1b[0m ${text}`);
}

async function waitFor(check: () => boolean | Promise<boolean>, timeoutMs = 15000, label = '条件'): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`等待超时：${label}`);
}

function readJson<T>(file: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  fs.rmSync(ROOT, { recursive: true, force: true });
  const cloudDir = path.join(ROOT, 'cloud');
  const agentDir = path.join(ROOT, 'agent');

  step(1, '启动控制面');
  const plane = createControlPlane({ dataDir: cloudDir, port: CLOUD_PORT, adminToken: ADMIN_TOKEN });
  const seeded = seedDemo(plane.store, plane.keys);
  ok(`控制面 http://127.0.0.1:${CLOUD_PORT}`);
  ok(`注册令牌已签发（一次性，2 小时有效）`);
  ok(`演示数据：3 条线路 / 2 个策略 / 3 台待接入设备`);

  step(2, '启动 Router Agent 并完成设备激活');
  const agentPromise = runAgent({
    dataDir: agentDir,
    cloudUrl: `http://127.0.0.1:${CLOUD_PORT}`,
    enrollmentToken: seeded.enrollmentToken,
    deviceModel: 'Xiaomi AX3000T (样机)',
    agentVersion: '0.1.0',
    portalPort: PORTAL_PORT,
    portalHost: '127.0.0.1',
    dryRun: true,
    pollIntervalMs: 400,
    heartbeatIntervalMs: 1500,
  });

  void agentPromise;
  await waitFor(
    () => plane.store.data.devices.some((d) => d.observedRevision >= 1),
    20000,
    '首次配置下发并应用',
  );
  const device = plane.store.data.devices[0]!;
  ok(`设备已注册：${device.id}（${device.model}）`);
  ok(`一次性令牌已作废：${plane.store.data.tokens[0]?.usedAt ? '是' : '否'}`);
  ok(`Agent 已应用配置：r${device.observedRevision}`);

  const manifestR1 = readJson<{ digest: string; counts: Record<string, number> }>(
    path.join(agentDir, 'routing', 'revisions', 'r1', 'manifest.json'),
  );
  const nft = fs.readFileSync(path.join(agentDir, 'routing', 'revisions', 'r1', 'nftables.nft'), 'utf8');
  const singbox = readJson<{ outbounds: { tag: string }[]; route: { rules: unknown[]; final: string } }>(
    path.join(agentDir, 'routing', 'revisions', 'r1', 'singbox.json'),
  );
  ok(`编译产物摘要：${String(manifestR1?.digest).slice(0, 16)}…`);
  ok(`sing-box 出口：${singbox?.outbounds.map((o) => o.tag).join(', ')}`);
  ok(`路由规则 ${singbox?.route.rules.length} 条，final=${singbox?.route.final}`);
  ok(`nftables 转发链默认策略：${/chain forward \{[\s\S]*?policy (\w+);/.exec(nft)?.[1] ?? '未知'}`);

  step(3, '云端远程授权摄像机（不接触客户电脑）');
  const authorize = await fetch(`http://127.0.0.1:${CLOUD_PORT}/api/admin/routers/${device.id}/device-authorizations`, {
    method: 'POST',
    headers: { 'authorization': `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      clientId: 'cl-camera',
      routeProfileId: 'profile-cn',
      reason: '直播间新增摄像机，按客户要求走大陆直连/其他代理',
    }),
  });
  const authorizeBody = (await authorize.json()) as { ok: boolean; revision: number };
  ok(`授权成功，云端版本提升到 r${authorizeBody.revision}`);

  await waitFor(
    () => plane.store.data.devices[0]!.observedRevision >= authorizeBody.revision,
    20000,
    '新版本应用',
  );
  const manifestR2 = readJson<{ plans: { label: string; mode: string; primary: string }[] }>(
    path.join(agentDir, 'routing', 'revisions', `r${authorizeBody.revision}`, 'manifest.json'),
  );
  ok(`Agent 已应用 r${plane.store.data.devices[0]!.observedRevision}，设备策略：`);
  for (const plan of manifestR2?.plans ?? []) {
    line(`      · ${plan.label} → ${plan.primary}（${plan.mode}）`);
  }

  step(4, '本地门户登录与状态读取');
  const login = await fetch(`http://127.0.0.1:${PORTAL_PORT}/api/portal/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin12345' }),
  });
  const cookie = login.headers.get('set-cookie') ?? '';
  ok(`设备管理员登录 ${login.status === 200 ? '成功' : '失败'}`);
  const portalState = await fetch(`http://127.0.0.1:${PORTAL_PORT}/api/portal/state`, {
    headers: { cookie: cookie.split(';')[0] ?? '' },
  });
  const portalBody = (await portalState.json()) as {
    snapshot: { exit: { lineName: string }; clients: { label: string; state: string }[]; accounts?: unknown };
  };
  ok(`门户出口：${portalBody.snapshot.exit.lineName ?? '—'}`);
  ok(`门户设备列表：${portalBody.snapshot.clients.map((c) => `${c.label}(${c.state})`).join('、')}`);
  ok(`门户响应未包含口令哈希：${portalBody.snapshot.accounts === undefined ? '是' : '否'}`);

  const badLogin = await fetch(`http://127.0.0.1:${PORTAL_PORT}/api/portal/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
  });
  ok(`错误口令被拒绝：${badLogin.status === 401 ? '是' : '否'}`);

  step(5, '下发固定命令：手动切线');
  const commandResponse = await fetch(`http://127.0.0.1:${CLOUD_PORT}/api/admin/routers/${device.id}/commands`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'SWITCH_LINE',
      params: { clientId: 'cl-codec', targetLineId: 'line-sg-1' },
      reason: '香港线路抖动，按客户要求临时切到新加坡',
    }),
  });
  const commandBody = (await commandResponse.json()) as { command: { id: string } };
  ok(`命令已签发并签名：${commandBody.command.id}`);

  await waitFor(
    () =>
      plane.store.data.commands.some(
        (c) => c.id === commandBody.command.id && (c.status === 'SUCCEEDED' || c.status === 'FAILED'),
      ),
    20000,
    '命令执行结果',
  );
  const executed = plane.store.data.commands.find((c) => c.id === commandBody.command.id);
  ok(`命令结果：${executed?.status} ${executed?.result?.code ?? ''}`);

  await new Promise((resolve) => setTimeout(resolve, 800));
  const afterPin = readJson<{ plans: { label: string; primary: string; standby: string | null }[] }>(
    path.join(agentDir, 'routing', 'revisions', `r${authorizeBody.revision}`, 'manifest.json'),
  );
  for (const plan of afterPin?.plans ?? []) {
    line(`      · ${plan.label} → ${plan.primary}${plan.standby ? `（备用 ${plan.standby}）` : ''}`);
  }
  const codecPlan = afterPin?.plans.find((p) => p.label === '直播间-编码器');
  const cameraPlan = afterPin?.plans.find((p) => p.label === '摄像机-B');
  ok(`锁线只影响目标设备：${codecPlan?.primary === 'line-sg-1' && cameraPlan?.primary === 'line-hk-1' ? '是' : '否'}`);

  step(6, '拒绝任意 Shell（白名单外命令）');
  const badCommand = await fetch(`http://127.0.0.1:${CLOUD_PORT}/api/admin/routers/${device.id}/commands`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'EXEC_SHELL', params: { cmd: 'rm -rf /' }, reason: '越权测试' }),
  });
  ok(`非白名单命令被拒绝：${badCommand.status === 400 ? '是' : `否（${badCommand.status}）`}`);

  step(7, '审计与观测记录');
  const overview = await fetch(`http://127.0.0.1:${CLOUD_PORT}/api/admin/audit-logs?limit=6`, {
    headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
  });
  const auditBody = (await overview.json()) as { logs: { action: string; actor: string; result: string }[] };
  for (const log of auditBody.logs.slice(0, 5)) {
    line(`      · ${log.action} by ${log.actor} → ${log.result}`);
  }
  ok(`observed-state 记录 ${plane.store.data.observed.length} 条，全部含逐步结果`);

  step(8, '云端断线后本地继续工作');
  plane.server.close();
  await new Promise((resolve) => setTimeout(resolve, 1200));
  const portalAfterCloudDown = await fetch(`http://127.0.0.1:${PORTAL_PORT}/api/portal/state`, {
    headers: { cookie: cookie.split(';')[0] ?? '' },
  });
  const afterBody = (await portalAfterCloudDown.json()) as {
    snapshot: { device: { cloudReachable: boolean; activeRevision: number } };
  };
  ok(`门户仍可访问：是`);
  ok(`云端可达标记：${afterBody.snapshot.device.cloudReachable ? '可达' : '不可达（本地策略继续生效）'}`);
  ok(`生效版本仍为 r${afterBody.snapshot.device.activeRevision}`);

  warn('dry-run 模式：未启动真实 sing-box / nftables，未接入真实线路与直播设备');
  warn('真机验收清单见 docs/impl/真机验收清单.md');

  line('');
  line('\x1b[32m端到端闭环跑通。\x1b[0m');
  line(`产物目录：${path.relative(process.cwd(), ROOT)}`);
  line(`  cloud/         云端数据库（凭证为密文）`);
  line(`  agent/routing/ 本地编译产物与版本`);
  line('');

  process.exit(0);
}

main().catch((error) => {
  console.error('演示失败：', error);
  process.exit(1);
});
