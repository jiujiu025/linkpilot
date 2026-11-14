import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { compileDesiredState } from '../src/compiler/compile.ts';
import { validateArtifacts, hasBlockingViolation } from '../src/compiler/validate.ts';
import { CREDENTIALS, buildFixtureState } from './fixtures.ts';

const base = compileDesiredState({
  state: buildFixtureState(),
  credentials: CREDENTIALS,
  controlEndpoints: ['54.199.10.8'],
  now: Date.parse('2026-11-14T02:00:00.000Z'),
});

function revalidate(mutate: (input: Parameters<typeof validateArtifacts>[0]) => void) {
  const input = {
    plan: base.plan,
    state: buildFixtureState(),
    singbox: structuredClone(base.artifacts.singbox),
    nftables: base.artifacts.nftables,
    uci: base.artifacts.uci,
    manifest: base.artifacts.manifest,
    credentials: CREDENTIALS,
  };
  mutate(input);
  return validateArtifacts(input);
}

describe('产物不变量校验（反向用例）', () => {
  it('干净产物没有阻断级违规', () => {
    const violations = revalidate(() => {});
    assert.equal(hasBlockingViolation(violations), false);
  });

  it('route.final 被改成 direct 时拒绝', () => {
    const violations = revalidate((input) => {
      (input.singbox.route as Record<string, unknown>).final = 'direct';
    });
    assert.ok(violations.some((v) => v.code === 'ROUTE_FINAL_OPEN'));
  });

  it('缺少兜底拒绝规则时拒绝', () => {
    const violations = revalidate((input) => {
      const rules = (input.singbox.route as { rules: Record<string, unknown>[] }).rules;
      rules.pop();
    });
    assert.ok(violations.some((v) => v.code === 'NO_CATCHALL_REJECT'));
  });

  it('转发链不是默认 drop 时拒绝', () => {
    const violations = revalidate((input) => {
      input.nftables = input.nftables.replace(
        'type filter hook forward priority filter; policy drop;',
        'type filter hook forward priority filter; policy accept;',
      );
    });
    assert.ok(violations.some((v) => v.code === 'NFT_FORWARD_OPEN'));
  });

  it('DNS 劫持被删掉时拒绝', () => {
    const violations = revalidate((input) => {
      input.nftables = input.nftables.replace(/dnat ip to [\d.]+:53/, '# dnat removed');
    });
    assert.ok(violations.some((v) => v.code === 'DNS_HIJACK_MISSING'));
  });

  it('IPv6 阻断表被删掉时拒绝', () => {
    const violations = revalidate((input) => {
      input.nftables = input.nftables.replaceAll('table ip6 linkpilot6', 'table ip6 other');
    });
    assert.ok(violations.some((v) => v.code === 'IPV6_TABLE_MISSING'));
  });

  it('线路凭证写进 UCI 片段时拒绝', () => {
    const violations = revalidate((input) => {
      input.uci = `${input.uci}\n# leaked=${CREDENTIALS['cred-us-ss']?.kind === 'shadowsocks' ? CREDENTIALS['cred-us-ss'].password : ''}`;
    });
    assert.ok(violations.some((v) => v.code === 'SECRET_IN_ARTIFACT'));
  });

  it('设备缺少路由规则时拒绝', () => {
    const violations = revalidate((input) => {
      const route = input.singbox.route as { rules: Record<string, unknown>[] };
      route.rules = route.rules.filter(
        (rule) => !(Array.isArray(rule.source_ip_cidr) && (rule.source_ip_cidr as string[]).includes('192.168.10.20/32')),
      );
    });
    assert.ok(violations.some((v) => v.code === 'CLIENT_UNROUTED'));
  });

  it('没有控制通道例外时给出告警而非静默通过', () => {
    const noEndpoint = compileDesiredState({
      state: buildFixtureState(),
      credentials: CREDENTIALS,
      controlEndpoints: [],
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    assert.ok(noEndpoint.violations.some((v) => v.code === 'NO_CONTROL_ENDPOINT' && v.severity === 'warn'));
  });
});
