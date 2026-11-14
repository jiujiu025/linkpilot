/**
 * 接入会话存储（设备侧）
 *
 * 两条独立的状态：
 * 1. deviceMemory —— 「这台设备登录过谁」，按 MAC 摘要记，用来免重登。
 * 2. sessions     —— 「这个源 IP 现在走哪条线路」，数据面唯一依据。
 *
 * 只有 sessions 会进 nftables；deviceMemory 只影响登录体验。
 * 这两个分开是刻意的：IP 会因为 DHCP 变化，但设备身份不应该因此丢失。
 *
 * 宽限期（graceMinutes）只决定「名额」什么时候释放，不影响网络通断：
 * 设备离线期间会话仍然保留，回来按 MAC 自动恢复，不需要重新输密码。
 */
import fs from 'node:fs';
import path from 'node:path';
import type { SessionEntry } from '../compiler/sessions.ts';
import { assertUniqueSources } from '../compiler/sessions.ts';

export type AccessSession = {
  accountId: string;
  /** 预授权设备（无浏览器）：不参与名额计算，也不被宽限期清理 */
  pinned?: boolean;
  username: string;
  lineId: string;
  srcIp: string;
  macHash: string;
  loginAt: number;
  lastSeenAt: number;
};

export type DeviceMemory = {
  macHash: string;
  accountId: string;
  lastLoginAt: number;
};

export type SessionState = {
  sessions: AccessSession[];
  deviceMemory: DeviceMemory[];
};

export type LoginResult = {
  session: AccessSession;
  /** 因「一账号一设备 / 后登踢前登」被动下线的会话 */
  evicted: AccessSession[];
};

const MAX_MEMORY = 500;

export class SessionStore {
  private state: SessionState = { sessions: [], deviceMemory: [] };
  private loaded = false;

  private readonly options: { file: string; graceMinutes: number };

  constructor(options: { file: string; graceMinutes: number }) {
    this.options = options;
  }

  load(now = Date.now()): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = fs.readFileSync(this.options.file, 'utf8');
      const parsed = JSON.parse(raw) as Partial<SessionState>;
      this.state = {
        sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
        deviceMemory: Array.isArray(parsed.deviceMemory) ? parsed.deviceMemory : [],
      };
    } catch {
      // 文件不存在或损坏：以空状态启动。会话丢了顶多重登一次，不能因此起不来
      this.state = { sessions: [], deviceMemory: [] };
    }
    this.sweep(now);
  }

  private persist(): void {
    const dir = path.dirname(this.options.file);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = `${this.options.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), 'utf8');
    fs.renameSync(tmp, this.options.file);
  }

  /** 登录：同一账号只允许 1 台设备，后登踢前登；同一 IP 上的旧账号一并作废 */
  login(input: {
    account: { id: string; username: string; lineId: string };
    srcIp: string;
    macHash: string;
    now?: number;
  }): LoginResult {
    const now = input.now ?? Date.now();
    const evicted: AccessSession[] = [];

    // 同账号在别的设备上：踢掉旧的（按 MAC 判断，避免同一设备的 IP 漂移被误当成新设备）
    this.state.sessions = this.state.sessions.filter((session) => {
      const sameAccount = session.accountId === input.account.id;
      const otherDevice = session.macHash !== input.macHash;
      if (sameAccount && otherDevice) {
        evicted.push(session);
        return false;
      }
      // 同一源地址被别的账号占用：新登录优先，旧映射必须清掉，否则一个 IP 两条线路
      if (session.srcIp === input.srcIp) {
        if (session.accountId !== input.account.id) evicted.push(session);
        return false;
      }
      return true;
    });

    const session: AccessSession = {
      accountId: input.account.id,
      username: input.account.username,
      lineId: input.account.lineId,
      srcIp: input.srcIp,
      macHash: input.macHash,
      loginAt: now,
      lastSeenAt: now,
    };
    this.state.sessions.push(session);

    this.state.deviceMemory = this.state.deviceMemory.filter((m) => m.macHash !== input.macHash);
    this.state.deviceMemory.unshift({ macHash: input.macHash, accountId: input.account.id, lastLoginAt: now });
    this.state.deviceMemory = this.state.deviceMemory.slice(0, MAX_MEMORY);

    this.persist();
    return { session, evicted };
  }

  /**
   * 设备换了源地址（DHCP 重排、AP 重启后常见）。
   * 以 MAC 为准把会话迁到新地址，用户无感——这是「不要因为 IP 变了就逼人重登」的关键一步。
   */
  rebind(macHash: string, srcIp: string, now = Date.now()): AccessSession | null {
    const session = this.state.sessions.find((s) => s.macHash === macHash);
    if (!session) return null;
    if (session.srcIp !== srcIp) {
      const conflict = this.state.sessions.find((s) => s.srcIp === srcIp && s.macHash !== macHash);
      if (conflict) {
        this.state.sessions = this.state.sessions.filter((s) => s !== conflict);
      }
      session.srcIp = srcIp;
    }
    session.lastSeenAt = now;
    this.persist();
    return session;
  }

  touch(macHash: string, now = Date.now()): void {
    const session = this.state.sessions.find((s) => s.macHash === macHash);
    if (!session) return;
    session.lastSeenAt = now;
  }

  logoutByMac(macHash: string): boolean {
    const before = this.state.sessions.length;
    this.state.sessions = this.state.sessions.filter((s) => s.macHash !== macHash);
    if (this.state.sessions.length !== before) this.persist();
    return this.state.sessions.length !== before;
  }

  /** 撤销某个账号的全部会话（云端踢线 / 到期 / 被删除） */
  revokeAccount(accountId: string): number {
    const before = this.state.sessions.length;
    this.state.sessions = this.state.sessions.filter((s) => s.accountId !== accountId);
    const removed = before - this.state.sessions.length;
    if (removed > 0) this.persist();
    return removed;
  }

  /**
   * 预授权设备落位：按 MAC 直接绑定线路，不需要登录。
   * 编码器、NVR、打印机这类设备没有浏览器，这是它们唯一能上网的路径。
   */
  seedTrusted(input: { macHash: string; lineId: string; srcIp: string; now?: number }): AccessSession {
    const now = input.now ?? Date.now();
    const existing = this.state.sessions.find((s) => s.macHash === input.macHash);
    if (existing) {
      existing.srcIp = input.srcIp;
      existing.lineId = input.lineId;
      existing.lastSeenAt = now;
      existing.pinned = true;
      this.persist();
      return existing;
    }
    const session: AccessSession = {
      accountId: `trusted:${input.macHash.slice(0, 8)}`,
      username: '（预授权设备）',
      lineId: input.lineId,
      srcIp: input.srcIp,
      macHash: input.macHash,
      loginAt: now,
      lastSeenAt: now,
      pinned: true,
    };
    this.state.sessions.push(session);
    this.persist();
    return session;
  }

  /** 清理超过宽限期的会话：只释放名额，不清设备记忆；预授权设备永不清理 */
  sweep(now = Date.now()): AccessSession[] {
    const limit = this.options.graceMinutes * 60 * 1000;
    const removed: AccessSession[] = [];
    this.state.sessions = this.state.sessions.filter((session) => {
      if (session.pinned) return true;
      if (now - session.lastSeenAt > limit) {
        removed.push(session);
        return false;
      }
      return true;
    });
    if (removed.length > 0) this.persist();
    return removed;
  }

  sessions(): AccessSession[] {
    return [...this.state.sessions];
  }

  findByMac(macHash: string): AccessSession | null {
    return this.state.sessions.find((s) => s.macHash === macHash) ?? null;
  }

  rememberedAccount(macHash: string): string | null {
    return this.state.deviceMemory.find((m) => m.macHash === macHash)?.accountId ?? null;
  }

  /** 交给编译器渲染 nft 脚本用的最小集合 */
  entries(): SessionEntry[] {
    const entries = this.state.sessions.map((session) => ({
      srcIp: session.srcIp,
      lineId: session.lineId,
      accountId: session.accountId,
      macHash: session.macHash,
    }));
    assertUniqueSources(entries);
    return entries;
  }
}
