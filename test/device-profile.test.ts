/**
 * 硬件档位与真机应用层
 *
 * 覆盖 x86/N100 与 AX3000T 的差异点：无无线的编译分支、防火墙必须先于代理落地、
 * 失败时不得继续后续步骤（否则会出现「代理已重启但防火墙没拦」的泄露窗口）。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { compileDesiredState } from '../src/compiler/compile.ts';
import { validateArtifacts } from '../src/compiler/validate.ts';
import { createSupervisor, type Runner } from '../src/agent/supervisor.ts';
import type { HardwareProfile } from '../src/agent/hardware.ts';
import { resolveWifiEnabled } from '../src/agent/hardware.ts';
import { CREDENTIALS, buildFixtureState } from './fixtures.ts';

const X86: HardwareProfile = {
  arch: 'x64',
  platform: 'linux',
  kernel: '6.6.0',
  model: 'N100',
  cpuModel: 'Intel N100',
  cpuCores: 4,
  memoryTotalMb: 16384,
  hasWifi: false,
  nics: ['eth0', 'eth1', 'eth2', 'eth3'],
  initSystem: 'procd',
  isX86: true,
};

describe('x86/N100 档位编译', () => {
  it('无无线时不生成任何 wireless 配置', () => {
    const state = buildFixtureState();
    const result = compileDesiredState({
      state: { ...state, wifi: { ...state.wifi, enabled: false } },
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    assert.equal(result.artifacts.uci.includes('wireless.@wifi-iface'), false);
    // 只断言「没有 wifi reload 这条命令」：生成器的注释里会出现这个词，不能按包含判断
    assert.equal(/^wifi reload$/m.test(result.artifacts.uci), false);
    assert.ok(result.artifacts.uci.includes('本机无无线模块'));
    // nftables 与分流规则不受影响：有线接入同样要隔离和防泄露
    assert.match(result.artifacts.nftables, /policy drop/);
    assert.equal(result.stats.clients, 2);
  });

  it('声明无无线却仍在写 wireless 配置时被拦下', () => {
    const state = buildFixtureState();
    const withWifi = compileDesiredState({
      state,
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    const violations = validateArtifacts({
      plan: withWifi.plan,
      state: { ...state, wifi: { ...state.wifi, enabled: false } },
      singbox: withWifi.artifacts.singbox,
      nftables: withWifi.artifacts.nftables,
      uci: withWifi.artifacts.uci,
      manifest: withWifi.artifacts.manifest,
      credentials: CREDENTIALS,
    });
    assert.ok(violations.some((v) => v.code === 'WIFI_DISABLED_BUT_CONFIGURED'));
  });

  it('N100 档位按设备档案显式生成网桥与 WAN 口映射', () => {
    const state = buildFixtureState();
    const result = compileDesiredState({
      state: {
        ...state,
        wifi: { ...state.wifi, enabled: false },
        lan: { ...state.lan, lanPorts: ['lan1', 'lan2', 'lan3'], wanPort: 'wan0' },
      },
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    const uci = result.artifacts.uci;
    // x86 不自动建网桥：不生成这些行，LAN 与 DHCP 会一起失效
    assert.match(uci, /uci set network\.lan_dev\.ports='lan1 lan2 lan3'/);
    assert.match(uci, /uci set network\.lan_dev\.type='bridge'/);
    assert.match(uci, /uci set network\.wan\.device='wan0'/);
  });

  it('ARM 档位（lanPorts 为空）不生成 device 段，避免与设备树冲突', () => {
    const state = buildFixtureState();
    const result = compileDesiredState({
      state,
      credentials: CREDENTIALS,
      controlEndpoints: ['10.0.0.8'],
      now: Date.parse('2026-11-14T02:00:00.000Z'),
    });
    assert.equal(result.artifacts.uci.includes('network.lan_dev'), false);
    assert.ok(result.artifacts.uci.includes('br-lan 由设备树固化'));
  });

  it('硬件探测结果优先于云端声明', () => {
    assert.deepEqual(resolveWifiEnabled(X86, true), {
      enabled: false,
      note: '本机未检测到无线网卡，已按硬件事实关闭无线配置',
    });
    assert.deepEqual(resolveWifiEnabled({ ...X86, hasWifi: true }, true), { enabled: true, note: null });
  });
});

function makeRunner(options: { failOn?: string; missing?: string[] } = {}) {
  const calls: { file: string; args: string[]; env?: Record<string, string> }[] = [];
  const runner: Runner = async (file, args, opts) => {
    if (file === 'sh' && args[0] === '-c' && args[1]?.startsWith('command -v')) {
      const binary = (args[1] ?? '').replace('command -v ', '').trim();
      if (options.missing?.includes(binary)) throw new Error(`${binary}: not found`);
      return { stdout: `/usr/sbin/${binary}`, stderr: '' };
    }
    calls.push({ file, args, env: opts?.env });
    if (options.failOn && file === options.failOn) throw new Error('mock failure');
    return { stdout: '', stderr: '' };
  };
  return { runner, calls };
}

function writeRevision(dir: string): string {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'nftables.nft'), 'table inet linkpilot {}\n', 'utf8');
  fs.writeFileSync(path.join(dir, 'apply.uci.sh'), '#!/bin/sh\nexit 0\n', 'utf8');
  return dir;
}

describe('真机应用顺序', () => {
  it('先装防火墙，再应用 UCI，最后重启并确认代理', async () => {
    const dir = writeRevision(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sup-')));
    const { runner, calls } = makeRunner();
    const supervisor = createSupervisor({ profile: X86, runner });
    const steps = await supervisor.apply({ revision: 3, dir, wifiPsk: 'secret-psk' });

    assert.deepEqual(steps.map((s) => s.name), ['nft-apply', 'uci-apply', 'proxy-restart', 'proxy-health']);
    assert.ok(steps.every((s) => s.status === 'ok'));
    assert.equal(calls[0]?.file, 'nft');
    assert.equal(calls[1]?.file, 'sh');
    assert.equal(calls[1]?.env?.LP_WIFI_PSK, 'secret-psk', '无线口令通过环境变量注入，不写进脚本文件');
    assert.equal(calls[2]?.file, '/etc/init.d/sing-box');
    assert.deepEqual(calls[2]?.args, ['restart']);
  });

  it('防火墙加载失败就停手，不重启代理', async () => {
    const dir = writeRevision(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sup-')));
    const { runner, calls } = makeRunner({ failOn: 'nft' });
    const supervisor = createSupervisor({ profile: X86, runner });
    const steps = await supervisor.apply({ revision: 4, dir, wifiPsk: 'x' });

    assert.equal(steps[0]?.name, 'nft-apply');
    assert.equal(steps[0]?.status, 'failed');
    assert.equal(steps.some((s) => s.name === 'proxy-restart'), false);
    assert.equal(calls.some((c) => c.file === '/etc/init.d/sing-box'), false);
  });

  it('缺少 nft 时直接判失败（不能以「跳过」蒙混过关）', async () => {
    const dir = writeRevision(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sup-')));
    const { runner } = makeRunner({ missing: ['nft'] });
    const supervisor = createSupervisor({ profile: X86, runner });
    const steps = await supervisor.apply({ revision: 5, dir, wifiPsk: 'x' });
    assert.equal(steps[0]?.status, 'failed');
    assert.match(steps[0]?.detail ?? '', /无法建立 Kill Switch/);
  });

  it('缺少 uci 时判失败，不能把「没配网络」伪装成成功', async () => {
    const dir = writeRevision(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sup-')));
    const { runner, calls } = makeRunner({ missing: ['uci'] });
    const supervisor = createSupervisor({
      profile: { ...X86, initSystem: 'systemd' },
      runner,
    });
    const steps = await supervisor.apply({ revision: 6, dir, wifiPsk: 'x' });
    const uci = steps.find((s) => s.name === 'uci-apply');
    assert.equal(uci?.status, 'failed');
    // 失败即停手：不重启代理、不做健康确认，避免半套配置上线
    assert.equal(steps.some((s) => s.name === 'proxy-restart'), false);
    assert.equal(calls.some((c) => c.file === '/etc/init.d/sing-box'), false);
  });

  it('LP_ALLOW_NO_UCI=1 时允许显式跳过（仅调试用）', async () => {
    const dir = writeRevision(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sup-')));
    const { runner } = makeRunner({ missing: ['uci'] });
    const supervisor = createSupervisor({
      profile: { ...X86, initSystem: 'systemd' },
      runner,
    });
    process.env.LP_ALLOW_NO_UCI = '1';
    try {
      const steps = await supervisor.apply({ revision: 8, dir, wifiPsk: 'x' });
      assert.equal(steps.find((s) => s.name === 'uci-apply')?.status, 'skipped');
    } finally {
      delete process.env.LP_ALLOW_NO_UCI;
    }
  });

  it('dry-run 不触碰内核', async () => {
    const dir = writeRevision(fs.mkdtempSync(path.join(os.tmpdir(), 'lp-sup-')));
    const { runner, calls } = makeRunner();
    const supervisor = createSupervisor({ profile: X86, runner, dryRun: true });
    const steps = await supervisor.apply({ revision: 7, dir, wifiPsk: 'x' });
    assert.equal(steps.length, 1);
    assert.equal(steps[0]?.status, 'skipped');
    assert.equal(calls.length, 0);
  });
});
