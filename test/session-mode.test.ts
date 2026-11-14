/**
 * 会话模式（单 SSID + 账号登录 → 出口线路）
 *
 * 这组用例守的是「换号不能影响别人」这个核心行为：
 * 编译期只产出骨架，运行期只改集合，绝不因为一次登录就重载代理配置。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { compileDesiredState } from '../src/compiler/compile.ts';
import { AUTHED_SET, renderSessionsNft, sessionSetName } from '../src/compiler/sessions.ts';
import { SessionStore } from '../src/agent/sessions.ts';
import { SESSION_PORT_BASE } from '../src/compiler/plan.ts';
import { hashPassword } from '../src/core/crypto.ts';
import { CREDENTIALS, buildFixtureState } from './fixtures.ts';

const NOW = Date.parse('2026-11-14T02:00:00.000Z');

function sessionState() {
  const base = buildFixtureState();
  return {
    ...base,
    accessControl: { mode: 'session' as const, graceMinutes: 5, loginPath: '/login' },
    accessAccounts: [
      {
        id: 'acc-alice',
        username: 'alice',
        displayName: 'Alice',
        passwordHash: hashPassword('alice-pass-1'),
        lineId: 'line-hk-1',
        enabled: true,
        expiresAt: null,
        revokedAt: null,
      },
      {
        id: 'acc-bob',
        username: 'bob',
        displayName: 'Bob',
        passwordHash: hashPassword('bob-pass-1'),
        lineId: 'line-sg-1',
        enabled: true,
        expiresAt: null,
        revokedAt: null,
      },
    ],
  };
}

function compileSession() {
  return compileDesiredState({
    state: sessionState(),
    credentials: CREDENTIALS,
    controlEndpoints: ['10.0.0.8'],
    now: NOW,
  });
}

describe('会话模式：编译产物骨架', () => {
  it('每条线路分配一个固定 tproxy 端口，端口从基数递增', () => {
    const result = compileSession();
    assert.deepEqual(
      result.plan.linePorts.map((p) => p.lineId),
      ['line-hk-1', 'line-sg-1'],
    );
    assert.equal(result.plan.linePorts[0]?.port, SESSION_PORT_BASE);
    assert.equal(result.plan.linePorts[1]?.port, SESSION_PORT_BASE + 1);
  });

  it('nftables 生成 tproxy 分流、会话集合与 tproxy 入站放通', () => {
    const nft = compileSession().artifacts.nftables;
    assert.ok(nft.includes(`set ${AUTHED_SET} {`), '必须有会话总集合');
    assert.ok(nft.includes(`set ${sessionSetName('line-hk-1')} {`), '每线路一个集合');
    assert.match(nft, /tproxy ip to :10000 meta mark set 1/);
    assert.match(nft, /th dport \{ 10000, 10001 \} counter accept/);
  });

  it('未登录设备的 HTTP 与 DNS 都被导向门户，才能触发登录弹窗', () => {
    const nft = compileSession().artifacts.nftables;
    // 任意 HTTP 跳到门户
    assert.match(nft, /ip saddr != @authed_v4 meta l4proto tcp th dport 80 counter dnat ip to 192\.168\.10\.1:8080/);
    // DNS 指向网关（门户解析器），否则手机连弹窗都不会出现
    assert.match(nft, /th dport 53 counter dnat ip to 192\.168\.10\.1:53/);
    assert.ok(nft.includes('未登录设备禁止出网'));
  });

  it('sing-box 用 tproxy 入站取代 tun，路由按入站而不是源地址展开', () => {
    const config = compileSession().artifacts.singbox as {
      inbounds: { type: string; tag: string; listen_port: number }[];
      route: { rules: Record<string, unknown>[] };
      dns: { rules: Record<string, unknown>[] };
    };
    assert.deepEqual(
      config.inbounds.map((i) => [i.type, i.tag, i.listen_port]),
      [
        ['tproxy', 'in:line-hk-1', SESSION_PORT_BASE],
        ['tproxy', 'in:line-sg-1', SESSION_PORT_BASE + 1],
      ],
    );
    assert.equal(config.inbounds.some((i) => i.type === 'tun'), false, '会话模式不应再留 tun，避免与 tproxy 抢流量');
    const routeByInbound = config.route.rules.filter((r) => Array.isArray(r.inbound));
    assert.equal(routeByInbound.length, 2);
    assert.deepEqual(routeByInbound[0], { inbound: ['in:line-hk-1'], outbound: 'line:line-hk-1' });
    // DNS 必须跟着入站走，否则会出现「出口是 A、解析走 B」
    const dnsByInbound = config.dns.rules.filter((r) => Array.isArray(r.inbound));
    assert.ok(dnsByInbound.some((r) => r.server === 'dns:line-hk-1'));
    assert.ok(dnsByInbound.some((r) => r.server === 'dns:line-sg-1'));
  });

  it('默认的设备绑定模式不产生任何会话产物（回归）', () => {
    const result = compileDesiredState({
      state: buildFixtureState(),
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: NOW,
    });
    assert.equal(result.plan.sessionMode, false);
    assert.equal(result.plan.linePorts.length, 0);
    assert.equal(result.artifacts.nftables.includes('tproxy'), false);
    const config = result.artifacts.singbox as { inbounds: { type: string }[] };
    assert.equal(config.inbounds[0]?.type, 'tun');
  });
});

describe('同网段互访与有线接入', () => {
  it('默认允许客户端互访，不再生成拒绝链', () => {
    const nft = compileSession().artifacts.nftables;
    assert.equal(nft.includes('客户端之间禁止互访'), false);
  });

  it('显式要求隔离时才生成拒绝链', () => {
    const base = sessionState();
    const result = compileDesiredState({
      state: { ...base, lan: { ...base.lan, allowClientToClient: false } },
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: NOW,
    });
    assert.ok(result.artifacts.nftables.includes('客户端之间禁止互访'));
  });

  it('同网段流量在 tproxy 之前被放行，不会被劫进代理', () => {
    const nft = compileSession().artifacts.nftables;
    const bypass = nft.indexOf('ip daddr 192.168.10.0/24 accept');
    const proxy = nft.indexOf('tproxy ip to :');
    assert.ok(bypass > 0, '必须有同网段旁路规则');
    assert.ok(proxy > bypass, '旁路规则必须排在 tproxy 之前，否则互访会被代理吃掉');
  });

  it('预授权设备（编码器/NVR）即使不登录也占一条线路入站', () => {
    const base = sessionState();
    const result = compileDesiredState({
      state: {
        ...base,
        accessAccounts: [],
        trustedDevices: [{ id: 'td-1', label: '直播间编码器', macHash: 'mac-enc-1', lineId: 'line-us-1' }],
      },
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: NOW,
    });
    assert.deepEqual(result.plan.linePorts.map((p) => p.lineId), ['line-us-1']);
  });
});

describe('会话模式：运行期集合更新', () => {
  it('每条线路先 flush 再 add，避免旧地址残留成第二个会话', () => {
    const script = renderSessionsNft({
      linePorts: [
        { lineId: 'line-hk-1', port: 10000 },
        { lineId: 'line-sg-1', port: 10001 },
      ],
      sessions: [
        { srcIp: '192.168.10.101', lineId: 'line-hk-1', accountId: 'acc-alice', macHash: 'm1' },
        { srcIp: '192.168.10.102', lineId: 'line-sg-1', accountId: 'acc-bob', macHash: 'm2' },
      ],
    });
    assert.match(script, /flush set inet linkpilot sess_line_hk_1\s+add element inet linkpilot sess_line_hk_1 \{ 192\.168\.10\.101 \}/);
    assert.match(script, /add element inet linkpilot authed_v4 \{ 192\.168\.10\.101, 192\.168\.10\.102 \}/);
  });

  it('没有会话时也要 flush，否则登出后旧会话仍在放通', () => {
    const script = renderSessionsNft({ linePorts: [{ lineId: 'line-hk-1', port: 10000 }], sessions: [] });
    assert.match(script, /flush set inet linkpilot sess_line_hk_1/);
    assert.match(script, /flush set inet linkpilot authed_v4/);
    assert.equal(script.includes('add element'), false);
  });
});

describe('会话存储：一账号一设备与宽限期', () => {
  function store() {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sess-')), 'sessions.json');
    return new SessionStore({ file, graceMinutes: 5 });
  }

  const alice = { id: 'acc-alice', username: 'alice', lineId: 'line-hk-1' };

  it('同账号第二台设备登录，第一台被踢下线', () => {
    const s = store();
    s.login({ account: alice, srcIp: '192.168.10.101', macHash: 'phone-1', now: NOW });
    const second = s.login({ account: alice, srcIp: '192.168.10.120', macHash: 'phone-2', now: NOW + 1000 });
    assert.equal(second.evicted.length, 1);
    assert.equal(second.evicted[0]?.macHash, 'phone-1');
    assert.deepEqual(
      s.sessions().map((x) => x.srcIp),
      ['192.168.10.120'],
    );
  });

  it('设备换了 IP 但 MAC 不变：自动迁移，不需要重新登录', () => {
    const s = store();
    s.login({ account: alice, srcIp: '192.168.10.101', macHash: 'phone-1', now: NOW });
    const rebound = s.rebind('phone-1', '192.168.10.150', NOW + 2000);
    assert.equal(rebound?.srcIp, '192.168.10.150');
    assert.equal(s.entries()[0]?.srcIp, '192.168.10.150');
    assert.equal(s.rememberedAccount('phone-1'), 'acc-alice');
  });

  it('离线超过宽限期释放名额，但设备记忆保留（回来可自动登录）', () => {
    const s = store();
    s.login({ account: alice, srcIp: '192.168.10.101', macHash: 'phone-1', now: NOW });
    assert.equal(s.sweep(NOW + 4 * 60 * 1000).length, 0, '5 分钟内不释放');
    assert.equal(s.sweep(NOW + 6 * 60 * 1000).length, 1, '超过 5 分钟释放');
    assert.equal(s.sessions().length, 0);
    assert.equal(s.rememberedAccount('phone-1'), 'acc-alice');
  });

  it('预授权设备常驻：宽限期不会清掉它', () => {
    const s = store();
    s.seedTrusted({ macHash: 'mac-enc-1', lineId: 'line-us-1', srcIp: '192.168.10.130', now: NOW });
    assert.equal(s.sweep(NOW + 60 * 60 * 1000).length, 0, '预授权设备没有登录会话，不该被宽限期回收');
    assert.equal(s.entries()[0]?.srcIp, '192.168.10.130');
  });

  it('撤销账号会清掉它的全部会话', () => {
    const s = store();
    s.login({ account: alice, srcIp: '192.168.10.101', macHash: 'phone-1', now: NOW });
    assert.equal(s.revokeAccount('acc-alice'), 1);
    assert.equal(s.entries().length, 0);
  });

  it('会话持久化后重新加载仍生效（断电恢复）', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sess-')), 'sessions.json');
    const first = new SessionStore({ file, graceMinutes: 5 });
    first.login({ account: alice, srcIp: '192.168.10.101', macHash: 'phone-1', now: NOW });
    const second = new SessionStore({ file, graceMinutes: 5 });
    second.load(NOW + 1000);
    assert.deepEqual(
      second.entries().map((e) => e.srcIp),
      ['192.168.10.101'],
    );
  });
});
