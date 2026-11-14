import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { compileDesiredState } from '../src/compiler/compile.ts';
import { CREDENTIALS, buildFixtureState } from './fixtures.ts';

const compile = (patch: Parameters<typeof buildFixtureState>[0] = {}) =>
  compileDesiredState({
    state: buildFixtureState(patch),
    credentials: CREDENTIALS,
    controlEndpoints: ['54.199.10.8'],
    now: Date.parse('2026-11-14T02:00:00.000Z'),
  });

describe('策略编译器', () => {
  it('产出四类产物且摘要稳定', () => {
    const a = compile();
    const b = compile();
    assert.equal(a.digest, b.digest, '同一输入必须得到同一摘要');
    assert.ok(a.artifacts.singbox);
    assert.ok(a.artifacts.nftables.includes('table inet linkpilot'));
    assert.ok(a.artifacts.uci.includes('uci set'));
    assert.equal(a.artifacts.leases.length, 2, '只有已授权设备需要静态租约');
    assert.equal(a.stats.clients, 2);
    assert.equal(a.stats.pending, 1);
  });

  it('按源地址生成设备级分流，严格模式只有代理出口', () => {
    const result = compile();
    const singbox = result.artifacts.singbox as Record<string, unknown>;
    const route = singbox.route as { rules: Record<string, unknown>[]; final: string };
    const codecRules = route.rules.filter(
      (rule) => Array.isArray(rule.source_ip_cidr) && (rule.source_ip_cidr as string[]).includes('192.168.10.20/32'),
    );
    assert.ok(codecRules.length >= 2);
    // 第一条是阻断下载端口，最后一条是兜底走主线路
    const tags = codecRules.map((rule) => rule.outbound ?? rule.action);
    assert.ok(tags.includes('line:line-hk-1'));
    assert.equal(route.final, 'block');
  });

  it('大陆直连模式会插入 cn 规则集并保持默认代理', () => {
    const result = compile();
    const route = (result.artifacts.singbox as Record<string, unknown>).route as {
      rules: Record<string, unknown>[];
      rule_set: { tag: string }[];
    };
    const camRules = route.rules.filter(
      (rule) => Array.isArray(rule.source_ip_cidr) && (rule.source_ip_cidr as string[]).includes('192.168.10.21/32'),
    );
    const cnRule = camRules.find((rule) => Array.isArray(rule.rule_set));
    assert.ok(cnRule, '缺少大陆直连规则');
    assert.equal(cnRule?.outbound, 'direct');
    assert.ok(route.rule_set.some((set) => set.tag === 'geosite-cn'));
  });

  it('nftables 是默认拒绝，并把待授权设备挡在公网之外', () => {
    const nft = compile().artifacts.nftables;
    assert.match(nft, /chain forward \{[\s\S]*policy drop;/);
    assert.match(nft, /ip saddr @pending_v4 counter reject/);
    assert.match(nft, /dnat ip to 172\.19\.0\.2:53/);
    assert.match(nft, /table ip6 linkpilot6/);
    assert.match(nft, /elements = \{ 192\.168\.10\.20, 192\.168\.10\.21 \}/);
  });

  it('过期绑定不会继续放行', () => {
    const state = buildFixtureState();
    const expired = {
      ...state,
      bindings: state.bindings.map((binding) =>
        binding.id === 'bind-camera'
          ? { ...binding, validUntil: '2026-11-13T00:00:00.000Z' }
          : binding,
      ),
    };
    const result = compileDesiredState({
      state: expired,
      credentials: CREDENTIALS,
      controlEndpoints: ['54.199.10.8'],
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    assert.equal(result.stats.clients, 1);
    assert.ok(result.plan.pendingClientIps.includes('192.168.10.21'));
    assert.ok(result.warnings.some((w) => w.includes('摄像机-B')));
  });

  it('缺少凭证时拒绝生成半残配置', () => {
    const { ['cred-hk-vless']: _dropped, ...rest } = CREDENTIALS;
    assert.throws(
      () =>
        compileDesiredState({
          state: buildFixtureState(),
          credentials: rest,
          controlEndpoints: ['54.199.10.8'],
        }),
      /缺少可用凭证/,
    );
  });

  it('协议与凭证不匹配时拒绝编译', () => {
    const broken = {
      ...CREDENTIALS,
      'cred-hk-vless': { ...CREDENTIALS['cred-us-ss']! },
    };
    assert.throws(
      () => compileDesiredState({ state: buildFixtureState(), credentials: broken }),
      /协议与凭证不一致/,
    );
  });

  it('同一设备两条生效绑定视为冲突', () => {
    const state = buildFixtureState();
    const conflict = {
      ...state,
      bindings: [
        ...state.bindings,
        {
          id: 'bind-codec-dup',
          clientId: 'cl-codec',
          routeProfileId: 'profile-cn',
          validFrom: '2026-11-01T00:00:00.000Z',
          validUntil: null,
          revokedAt: null,
          version: 1,
        },
      ],
    };
    assert.throws(
      () =>
        compileDesiredState({
          state: conflict as typeof state,
          credentials: CREDENTIALS,
          controlEndpoints: ['54.199.10.8'],
        }),
      /多条同时生效的绑定/,
    );
  });

  it('没有已授权设备时仍然生成可用的隔离配置', () => {
    const state = buildFixtureState();
    const empty = {
      ...state,
      bindings: [],
      clients: state.clients.map((client) => ({ ...client, state: 'pending' as const })),
    };
    const result = compileDesiredState({
      state: empty,
      credentials: CREDENTIALS,
      controlEndpoints: ['54.199.10.8'],
    });
    assert.equal(result.stats.clients, 0);
    assert.ok(result.artifacts.nftables.includes('policy drop'));
  });
});

describe('手动锁线', () => {
  it('只影响目标设备，同组其他设备保持原线路', () => {
    const result = compileDesiredState({
      state: buildFixtureState(),
      credentials: CREDENTIALS,
      controlEndpoints: ['54.199.10.8'],
      pins: { 'cl-codec': 'line-sg-1' },
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    const codec = result.plan.clients.find((c) => c.clientId === 'cl-codec');
    const camera = result.plan.clients.find((c) => c.clientId === 'cl-camera');
    assert.equal(codec?.primary.lineId, 'line-sg-1');
    assert.equal(codec?.standby?.lineId, 'line-hk-1');
    assert.equal(camera?.primary.lineId, 'line-hk-1', '摄像机不应被连带切走');
    assert.ok(result.warnings.some((w) => w.includes('手动锁线')));
  });

  it('锁到不存在的线路时回落到默认主线路并告警', () => {
    const result = compileDesiredState({
      state: buildFixtureState(),
      credentials: CREDENTIALS,
      pins: { 'cl-codec': 'line-does-not-exist' },
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    const codec = result.plan.clients.find((c) => c.clientId === 'cl-codec');
    assert.equal(codec?.primary.lineId, 'line-hk-1');
    assert.ok(result.warnings.some((w) => w.includes('不在当前线路组内')));
  });
});
