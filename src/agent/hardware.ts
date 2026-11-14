/**
 * 硬件档位探测
 *
 * 目的：让同一份代码在 AX3000T（MIPS/MT7981B、有无线、procd）和 N100（x86_64、
 * 无无线、可能 systemd）上都能正确工作，而不是靠人手改配置。
 *
 * 只读取 /sys、/proc、/etc 的只读信息，不写任何设备状态。
 */
import fs from 'node:fs';
import os from 'node:os';

export type InitSystem = 'procd' | 'systemd' | 'none';

export type HardwareProfile = {
  arch: string;
  platform: string;
  kernel: string;
  model: string;
  cpuModel: string;
  cpuCores: number;
  memoryTotalMb: number;
  hasWifi: boolean;
  nics: string[];
  initSystem: InitSystem;
  /** 是否是 x86 档位（资源充裕，不需要按 256MB 内存裁剪） */
  isX86: boolean;
};

function readFirstLine(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8').trim().split('\n')[0] ?? null;
  } catch {
    return null;
  }
}

function exists(file: string): boolean {
  try {
    fs.accessSync(file);
    return true;
  } catch {
    return false;
  }
}

function listNics(): string[] {
  try {
    return fs
      .readdirSync('/sys/class/net')
      .filter((name) => name !== 'lo')
      .filter((name) => !/^(tun|tap|wg|lp-tun)/.test(name))
      .sort();
  } catch {
    // Windows/macOS 开发机：只暴露粗略信息
    const nets = os.networkInterfaces();
    return Object.keys(nets).filter((name) => name !== 'lo' && !/^(tun|tap|wg)/.test(name));
  }
}

export function detectHardware(): HardwareProfile {
  const arch = os.arch();
  const platform = os.platform();
  const nics = listNics();
  const hasWifi = nics.some((name) => exists(`/sys/class/net/${name}/wireless`));

  const model =
    readFirstLine('/sys/devices/virtual/dmi/id/product_name') ??
    readFirstLine('/sys/firmware/devicetree/base/model')?.replace(/\0/g, '') ??
    readFirstLine('/tmp/sysinfo/model') ??
    os.hostname();

  let initSystem: InitSystem = 'none';
  if (exists('/sbin/procd') || exists('/etc/init.d/sing-box')) initSystem = 'procd';
  else if (exists('/run/systemd/system')) initSystem = 'systemd';

  return {
    arch,
    platform,
    kernel: os.release(),
    model,
    cpuModel: os.cpus()[0]?.model ?? 'unknown',
    cpuCores: os.cpus().length,
    memoryTotalMb: Math.round(os.totalmem() / 1024 / 1024),
    hasWifi,
    nics,
    initSystem,
    isX86: arch === 'x64' || arch === 'ia32',
  };
}

/**
 * 用本机事实修正无线开关。
 *
 * 云端不知道这台机器有没有无线模块，如果它按「应该支持单 SSID」下发，
 * 无无线的机器会在 wifi reload 这一步失败，连带整批配置回滚。
 * 因此设备侧以硬件事实为准修正，并把修正原因写进 observed steps。
 *
 * 环境变量 LP_FORCE_WIFI=1/0 可覆盖探测结果（用于外接 USB 无线网卡的场景）。
 */
export function resolveWifiEnabled(profile: HardwareProfile, desired: boolean): { enabled: boolean; note: string | null } {
  const forced = process.env.LP_FORCE_WIFI;
  if (forced === '1' || forced === '0') {
    const enabled = forced === '1';
    return { enabled, note: `无线开关由 LP_FORCE_WIFI 强制为 ${enabled}` };
  }
  if (!profile.hasWifi && desired) {
    return { enabled: false, note: '本机未检测到无线网卡，已按硬件事实关闭无线配置' };
  }
  if (profile.hasWifi && !desired) {
    return { enabled: false, note: '检测到无线网卡，但策略要求关闭无线，保持关闭' };
  }
  return { enabled: desired, note: null };
}

export function describeHardware(profile: HardwareProfile): string {
  return `${profile.model} · ${profile.arch} · ${profile.cpuCores}C · ${profile.memoryTotalMb}MB · ${profile.initSystem}${profile.hasWifi ? ' · wifi' : ' · 无无线'}`;
}
