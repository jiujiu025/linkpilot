/**
 * 真机应用层：把编译产物真正落到系统上
 *
 * 与 apply.ts 的分工：
 * - apply.ts 负责文件系统（staging、摘要、原子切换、保留版本），任何平台都能跑；
 * - 本文件负责「让内核和服务真的生效」，按硬件档位走不同后端，且每步都可单独失败。
 *
 * 顺序不可颠倒：先装 nftables（默认拒绝立刻生效），再应用 UCI，最后重启代理。
 * 反过来会出现「代理重启成功但防火墙还没拦」的窗口期，这几百毫秒就是泄露窗口。
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Step } from './apply.ts';
import type { HardwareProfile } from './hardware.ts';

const execFileAsync = promisify(execFile);

export type Runner = (
  file: string,
  args: string[],
  options?: { env?: Record<string, string>; timeoutMs?: number },
) => Promise<{ stdout: string; stderr: string }>;

export const defaultRunner: Runner = async (file, args, options = {}) => {
  const result = await execFileAsync(file, args, {
    timeout: options.timeoutMs ?? 20000,
    env: { ...process.env, ...(options.env ?? {}) },
    maxBuffer: 4 * 1024 * 1024,
  });
  return { stdout: result.stdout, stderr: result.stderr };
};

export type SupervisorOptions = {
  profile: HardwareProfile;
  runner?: Runner;
  /** 代理核心可执行名，OpenWrt 上通常是 sing-box */
  serviceName?: string;
  dryRun?: boolean;
};

export type Supervisor = {
  /** 应用一个已落盘的版本；返回逐步结果，异常不外抛 */
  apply(input: { revision: number; dir: string; wifiPsk: string }): Promise<Step[]>;
  /**
   * 只应用运行期的会话脚本（flush/add 集合）。
   * 不重启 sing-box、不重载网络——登录动作绝不能把别人的连接带断。
   */
  applySessions(scriptPath: string): Promise<{ ok: boolean; detail: string }>;
  /**
   * 加载指定的 nft 规则文件。
   * 开机时用它先把「上一次可用的防火墙」装回去，避免云端不可达时裸奔。
   */
  applyNftFile(filePath: string): Promise<{ ok: boolean; detail: string }>;
  restartProxy(): Promise<{ ok: boolean; detail: string }>;
  restartNetwork(): Promise<{ ok: boolean; detail: string }>;
  proxyRunning(): Promise<boolean>;
};

async function which(runner: Runner, binary: string): Promise<boolean> {
  try {
    await runner('sh', ['-c', `command -v ${binary}`], { timeoutMs: 4000 });
    return true;
  } catch {
    return false;
  }
}

function step(name: string, status: Step['status'], detail: string, started: number): Step {
  return { name, status, detail, durationMs: Date.now() - started };
}

export function createSupervisor(options: SupervisorOptions): Supervisor {
  const runner = options.runner ?? defaultRunner;
  const service = options.serviceName ?? 'sing-box';

  async function restartService(name: string): Promise<{ ok: boolean; detail: string }> {
    if (options.profile.initSystem === 'procd') {
      try {
        await runner('/etc/init.d/' + name, ['restart'], { timeoutMs: 20000 });
        return { ok: true, detail: `procd 重启 ${name}` };
      } catch (error) {
        return { ok: false, detail: `procd 重启 ${name} 失败: ${errText(error)}` };
      }
    }
    if (options.profile.initSystem === 'systemd') {
      try {
        await runner('systemctl', ['restart', name], { timeoutMs: 20000 });
        return { ok: true, detail: `systemd 重启 ${name}` };
      } catch (error) {
        return { ok: false, detail: `systemd 重启 ${name} 失败: ${errText(error)}` };
      }
    }
    return { ok: false, detail: '未识别 init 系统，无法重启服务' };
  }

  async function apply(input: { revision: number; dir: string; wifiPsk: string }): Promise<Step[]> {
    const steps: Step[] = [];
    if (options.dryRun) {
      steps.push(step('runtime', 'skipped', 'dry-run：不触碰内核与系统服务', Date.now()));
      return steps;
    }

    /* 1. nftables：默认拒绝先落地，再谈代理 */
    {
      const started = Date.now();
      const file = path.join(input.dir, 'nftables.nft');
      if (!fs.existsSync(file)) {
        steps.push(step('nft-apply', 'failed', `规则文件不存在: ${file}`, started));
        return steps;
      }
      if (!options.profile.platform.startsWith('linux')) {
        steps.push(step('nft-apply', 'skipped', '当前系统不是 Linux，跳过防火墙应用', started));
      } else if (!(await which(runner, 'nft'))) {
        steps.push(step('nft-apply', 'failed', '系统没有 nft 命令，无法建立 Kill Switch', started));
        return steps;
      } else {
        try {
          await runner('nft', ['-f', file], { timeoutMs: 15000 });
          steps.push(step('nft-apply', 'ok', `已加载 r${input.revision} 规则集`, started));
        } catch (error) {
          steps.push(step('nft-apply', 'failed', errText(error), started));
          return steps;
        }
      }
    }

    /* 2. UCI：网络、DHCP、无线（无无线档位不会包含 wireless） */
    {
      const started = Date.now();
      const script = path.join(input.dir, 'apply.uci.sh');
      if (!(await which(runner, 'uci'))) {
        /*
         * 没有 uci 就是没有网络配置后端：LAN/DHCP/网桥一条都不会落地。
         * 之前这里记 skipped 继续往下跑，结果是云端看到「应用成功」，客户家里
         * 网段还是旧的——设备把失败伪装成了成功。必须硬失败。
         * 仅在做非路由器角色的调试时可用 LP_ALLOW_NO_UCI=1 显式放行。
         */
        const allowed = process.env.LP_ALLOW_NO_UCI === '1';
        steps.push(
          step(
            'uci-apply',
            allowed ? 'skipped' : 'failed',
            allowed
              ? '系统没有 uci，按 LP_ALLOW_NO_UCI=1 显式跳过网络配置（调试模式，不可用于交付）'
              : '系统没有 uci，无法应用 LAN/DHCP/网桥配置，拒绝伪装成功',
            started,
          ),
        );
        if (!allowed) return steps;
      } else {
        try {
          await runner('sh', [script], {
            timeoutMs: 60000,
            env: { LP_WIFI_PSK: input.wifiPsk },
          });
          steps.push(step('uci-apply', 'ok', '网络/DHCP 配置已提交并 reload', started));
        } catch (error) {
          steps.push(step('uci-apply', 'failed', errText(error), started));
          return steps;
        }
      }
    }

    /* 3. 代理核心：配置已在前面校验过，这里只负责重启并确认活着 */
    {
      const started = Date.now();
      if (!(await which(runner, service))) {
        steps.push(
          step('proxy-restart', 'skipped', `未安装 ${service}，跳过重启（真机必须为 ok）`, started),
        );
      } else {
        const restarted = await restartService(service);
        steps.push(step('proxy-restart', restarted.ok ? 'ok' : 'failed', restarted.detail, started));
        if (!restarted.ok) return steps;
      }
    }

    /* 4. 健康确认：进程活着且能读到本次版本 */
    {
      const started = Date.now();
      const running = await isProxyRunning();
      steps.push(
        step(
          'proxy-health',
          running ? 'ok' : 'failed',
          running ? `${service} 正在运行` : `${service} 未运行`,
          started,
        ),
      );
      if (!running) return steps;
    }

    return steps;
  }

  async function isProxyRunning(): Promise<boolean> {
    if (options.dryRun) return false;
    try {
      await runner('sh', ['-c', `pidof ${service} >/dev/null 2>&1 || pgrep -x ${service} >/dev/null 2>&1`], {
        timeoutMs: 4000,
      });
      return true;
    } catch {
      return false;
    }
  }

  async function applySessions(scriptPath: string): Promise<{ ok: boolean; detail: string }> {
    if (options.dryRun) return { ok: false, detail: 'dry-run：不修改会话集合' };
    if (!options.profile.platform.startsWith('linux')) {
      return { ok: false, detail: '当前系统不是 Linux，无法应用会话集合' };
    }
    if (!(await which(runner, 'nft'))) return { ok: false, detail: '系统没有 nft 命令' };
    try {
      await runner('nft', ['-f', scriptPath], { timeoutMs: 10000 });
      return { ok: true, detail: '会话集合已更新' };
    } catch (error) {
      return { ok: false, detail: `会话集合更新失败: ${errText(error)}` };
    }
  }

  return {
    apply,
    applyNftFile: applySessions,
    applySessions,
    restartProxy: () => restartService(service),
    restartNetwork: () =>
      options.profile.initSystem === 'procd'
        ? (async () => {
            try {
              await runner('/etc/init.d/network', ['reload'], { timeoutMs: 20000 });
              return { ok: true, detail: 'network reload 完成' };
            } catch (error) {
              return { ok: false, detail: errText(error) };
            }
          })()
        : restartService('network'),
    proxyRunning: isProxyRunning,
  };
}

function errText(error: unknown): string {
  if (error && typeof error === 'object' && 'stderr' in error) {
    const stderr = String((error as { stderr: unknown }).stderr ?? '').trim();
    if (stderr) return stderr.split('\n').slice(0, 3).join(' | ');
  }
  return error instanceof Error ? error.message : String(error);
}
