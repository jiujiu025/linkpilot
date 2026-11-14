/**
 * 配置落盘与应用
 *
 * 顺序是「先校验、再原子切换、最后可回滚」，任何一步失败都保持旧版本继续工作：
 *   准备目录 → 摘要核对 → 语法/规则校验 → 原子切换 active 指针 → 保留最近三版
 *
 * 关键点：active 指针只是一个 JSON 文件，用 rename 原子替换。
 * 不用符号链接——OpenWrt 的 JFFS2/UBIFS 上符号链接语义和普通文件不同，
 * 而且出问题时排查成本高得多。
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { digestOf } from '../core/canonical.ts';
import type { CompiledArtifacts } from '../compiler/compile.ts';

const run = promisify(execFile);

export type Step = {
  name: string;
  status: 'ok' | 'failed' | 'skipped';
  detail: string;
  durationMs: number;
};

export type ActiveState = {
  revision: number;
  digest: string;
  activatedAt: string;
  previousRevision: number | null;
  status: 'active' | 'rolled_back';
};

export type ApplyOutcome = {
  status: 'succeeded' | 'failed' | 'rolled_back';
  revision: number;
  digest: string;
  steps: Step[];
  rollbackTo: number | null;
};

export type ApplyOptions = {
  root: string;
  /** dry-run 时不切换 active 指针，只做落盘与校验 */
  dryRun?: boolean;
  /** 允许注入的命令执行器，测试里可以替换 */
  runner?: (file: string, args: string[]) => Promise<{ stdout: string; stderr: string }>;
  /**
   * 切换 active 之后的真机动作（加载 nftables、提交 UCI、重启代理）。
   * 放在这里而不是调用方，是因为「运行时失败必须回滚」的语义属于应用流程本身。
   */
  postActivate?: (input: { revision: number; dir: string; artifacts: CompiledArtifacts }) => Promise<Step[]>;
};

function revisionDir(root: string, revision: number): string {
  return path.join(root, 'revisions', `r${revision}`);
}

export function readActive(root: string): ActiveState | null {
  const file = path.join(root, 'active.json');
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as ActiveState;
  } catch {
    return null;
  }
}

export function listRevisions(root: string): number[] {
  const dir = path.join(root, 'revisions');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) => /^r\d+$/.test(name))
    .map((name) => Number(name.slice(1)))
    .sort((a, b) => a - b);
}

export function readArtifacts(root: string, revision: number): CompiledArtifacts | null {
  const dir = revisionDir(root, revision);
  if (!fs.existsSync(dir)) return null;
  try {
    return {
      singbox: JSON.parse(fs.readFileSync(path.join(dir, 'singbox.json'), 'utf8')) as Record<string, unknown>,
      nftables: fs.readFileSync(path.join(dir, 'nftables.nft'), 'utf8'),
      uci: fs.readFileSync(path.join(dir, 'apply.uci.sh'), 'utf8'),
      leases: JSON.parse(fs.readFileSync(path.join(dir, 'leases.json'), 'utf8')) as CompiledArtifacts['leases'],
      manifest: JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')) as Record<string, unknown>,
    };
  } catch {
    return null;
  }
}

async function hasBinary(name: string, runner: ApplyOptions['runner']): Promise<boolean> {
  try {
    const executor = runner ?? (async (file: string, args: string[]) => run(file, args));
    await executor(process.platform === 'win32' ? 'where' : 'which', [name]);
    return true;
  } catch {
    return false;
  }
}

/**
 * 重新计算落盘产物的摘要，和 manifest 里记录的比较。
 * 防的是「传输中被截断 / 磁盘写坏 / 人类手改」，不是防伪造（伪造由签名拦）。
 */
export function verifyWrittenDigest(artifacts: CompiledArtifacts): string | null {
  const recomputed = digestOf({
    singbox: artifacts.singbox,
    nftables: artifacts.nftables,
    uci: artifacts.uci,
    leases: artifacts.leases,
  });
  const recorded = String(artifacts.manifest.digest ?? '');
  return recomputed === recorded ? null : `摘要不一致：落盘 ${recomputed.slice(0, 12)} ≠ manifest ${recorded.slice(0, 12)}`;
}

export async function applyArtifacts(
  artifacts: CompiledArtifacts,
  revision: number,
  options: ApplyOptions,
): Promise<ApplyOutcome> {
  const steps: Step[] = [];
  const executor = options.runner ?? (async (file: string, args: string[]) => run(file, args));
  const target = revisionDir(options.root, revision);
  const staging = `${target}.staging`;
  const previous = readActive(options.root);

  const step = async (
    name: string,
    fn: () => Promise<{ status: 'ok' | 'failed' | 'skipped'; detail: string }>,
  ): Promise<boolean> => {
    const started = Date.now();
    try {
      const result = await fn();
      steps.push({ name, status: result.status, detail: result.detail, durationMs: Date.now() - started });
      return result.status !== 'failed';
    } catch (error) {
      steps.push({
        name,
        status: 'failed',
        detail: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - started,
      });
      return false;
    }
  };

  /* 1. 落盘（先写 staging，再整体 rename） */
  const okPrepared = await step('prepare', async () => {
    fs.rmSync(staging, { recursive: true, force: true });
    fs.mkdirSync(staging, { recursive: true });
    fs.writeFileSync(path.join(staging, 'singbox.json'), JSON.stringify(artifacts.singbox, null, 2), 'utf8');
    fs.writeFileSync(path.join(staging, 'nftables.nft'), artifacts.nftables, 'utf8');
    fs.writeFileSync(path.join(staging, 'apply.uci.sh'), artifacts.uci, 'utf8');
    fs.writeFileSync(path.join(staging, 'leases.json'), JSON.stringify(artifacts.leases, null, 2), 'utf8');
    fs.writeFileSync(path.join(staging, 'manifest.json'), JSON.stringify(artifacts.manifest, null, 2), 'utf8');
    fs.rmSync(target, { recursive: true, force: true });
    fs.renameSync(staging, target);
    return { status: 'ok', detail: `写入 ${target}` };
  });
  if (!okPrepared) {
    return { status: 'failed', revision, digest: '', steps, rollbackTo: previous?.revision ?? null };
  }

  /* 2. 摘要核对 */
  const okDigest = await step('verify-digest', async () => {
    const written = readArtifacts(options.root, revision);
    if (!written) return { status: 'failed', detail: '产物读取失败' };
    const mismatch = verifyWrittenDigest(written);
    return mismatch ? { status: 'failed', detail: mismatch } : { status: 'ok', detail: '摘要一致' };
  });

  /* 3. 本地语法/语义校验（有对应二进制才跑，没有就明确标 skipped） */
  let okChecks = okDigest;
  if (okChecks) {
    okChecks = await step('nftables-check', async () => {
      if (!(await hasBinary('nft', options.runner))) {
        return { status: 'skipped', detail: '本机没有 nft，跳过语法校验（真机必须为 ok）' };
      }
      await executor('nft', ['-c', '-f', path.join(target, 'nftables.nft')]);
      return { status: 'ok', detail: 'nft -c 通过' };
    });
  }
  if (okChecks) {
    okChecks = await step('shell-check', async () => {
      await executor('sh', ['-n', path.join(target, 'apply.uci.sh')]);
      return { status: 'ok', detail: 'apply.uci.sh 语法通过' };
    });
  }
  if (okChecks) {
    okChecks = await step('singbox-check', async () => {
      if (!(await hasBinary('sing-box', options.runner))) {
        return { status: 'skipped', detail: '本机没有 sing-box，跳过配置校验（真机必须为 ok）' };
      }
      await executor('sing-box', ['check', '-c', path.join(target, 'singbox.json')]);
      return { status: 'ok', detail: 'sing-box check 通过' };
    });
  }

  if (!okChecks) {
    // 校验失败：删掉这次的部分产物，保持旧版本继续工作
    fs.rmSync(target, { recursive: true, force: true });
    return { status: 'failed', revision, digest: '', steps, rollbackTo: previous?.revision ?? null };
  }

  /* 4. 原子切换 */
  const okActivate = await step('activate', async () => {
    if (options.dryRun) {
      return { status: 'skipped', detail: 'dry-run：不切换 active 指针' };
    }
    const state: ActiveState = {
      revision,
      digest: String(artifacts.manifest.digest ?? ''),
      activatedAt: new Date().toISOString(),
      previousRevision: previous?.revision ?? null,
      status: 'active',
    };
    const tmp = path.join(options.root, `active.json.${Date.now()}.tmp`);
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2), 'utf8');
    fs.renameSync(tmp, path.join(options.root, 'active.json'));
    return { status: 'ok', detail: `active → r${revision}` };
  });

  /* 4.5 真机动作：任一步失败就回滚到上一版本 */
  let runtimeFailed = false;
  if (okActivate && options.postActivate) {
    try {
      const runtimeSteps = await options.postActivate({ revision, dir: target, artifacts });
      steps.push(...runtimeSteps);
      runtimeFailed = runtimeSteps.some((item) => item.status === 'failed');
    } catch (error) {
      steps.push({
        name: 'runtime',
        status: 'failed',
        detail: error instanceof Error ? error.message : String(error),
        durationMs: 0,
      });
      runtimeFailed = true;
    }
    if (runtimeFailed) {
      const back = previous?.revision ?? null;
      if (back !== null && fs.existsSync(revisionDir(options.root, back))) {
        const state: ActiveState = {
          revision: back,
          digest: String(readArtifacts(options.root, back)?.manifest.digest ?? ''),
          activatedAt: new Date().toISOString(),
          previousRevision: revision,
          status: 'rolled_back',
        };
        const tmp = path.join(options.root, `active.json.${Date.now()}.tmp`);
        fs.writeFileSync(tmp, JSON.stringify(state, null, 2), 'utf8');
        fs.renameSync(tmp, path.join(options.root, 'active.json'));
        steps.push({
          name: 'rollback',
          status: 'ok',
          detail: `运行时失败，已回退 active 指针到 r${back}`,
          durationMs: 0,
        });
      } else {
        steps.push({
          name: 'rollback',
          status: 'skipped',
          detail: '没有上一稳定版本可回退，保持默认拒绝状态（断网但不泄露）',
          durationMs: 0,
        });
      }
    }
  }

  /* 5. 保留最近三版 */
  await step('prune', async () => {
    const revisions = listRevisions(options.root);
    const keep = new Set(revisions.slice(-3));
    if (previous) keep.add(previous.revision);
    const removed = revisions.filter((r) => !keep.has(r));
    for (const r of removed) fs.rmSync(revisionDir(options.root, r), { recursive: true, force: true });
    return {
      status: 'ok',
      detail: removed.length === 0 ? '无需清理' : `清理 r${removed.join(', r')}`,
    };
  });

  return {
    status: runtimeFailed ? 'rolled_back' : okActivate ? 'succeeded' : 'failed',
    revision,
    digest: String(artifacts.manifest.digest ?? ''),
    steps,
    rollbackTo: previous?.revision ?? null,
  };
}

/** 回滚到指定版本（缺省回到 active.previousRevision） */
export async function rollbackTo(
  root: string,
  revision?: number | null,
): Promise<{ ok: boolean; revision: number | null; detail: string }> {
  const active = readActive(root);
  const target = revision ?? active?.previousRevision ?? null;
  if (target === null) return { ok: false, revision: null, detail: '没有可回滚的历史版本' };
  if (!fs.existsSync(revisionDir(root, target))) {
    return { ok: false, revision: null, detail: `版本 r${target} 的产物已不存在` };
  }
  const state: ActiveState = {
    revision: target,
    digest: String(readArtifacts(root, target)?.manifest.digest ?? ''),
    activatedAt: new Date().toISOString(),
    previousRevision: active?.revision ?? null,
    status: 'rolled_back',
  };
  const tmp = path.join(root, `active.json.${Date.now()}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), 'utf8');
  fs.renameSync(tmp, path.join(root, 'active.json'));
  return { ok: true, revision: target, detail: `已回滚到 r${target}` };
}
