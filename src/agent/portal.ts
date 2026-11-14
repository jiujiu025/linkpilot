/**
 * 本地门户服务
 *
 * 门户只做三件事：认证（本地 scrypt 校验）、展示（脱敏快照）、转发写操作。
 * 它不读线路凭证、不碰代理核心、不提供任何系统管理入口。
 *
 * 会话用 HMAC 签名 Cookie，不用 JWT 库：设备侧依赖越少越好，
 * 而「签名 + 过期 + HttpOnly + SameSite」已经覆盖这个场景的需求。
 */
import crypto from 'node:crypto';
import http from 'node:http';
import { verifyPassword } from '../core/crypto.ts';
import { AppError } from '../core/errors.ts';
import { Router, serve, type Ctx } from '../control/http.ts';
import { renderPortalHtml } from './portal-ui.ts';

export type PortalAccountView = {
  username: string;
  displayName: string;
  role: 'customer' | 'device_admin';
  passwordHash: string;
  disabled: boolean;
};

export type PortalClientView = {
  id: string;
  label: string;
  ip: string;
  state: 'pending' | 'authorized' | 'revoked';
  attach: 'lan' | 'wifi';
  primaryLine: string | null;
  primaryLineId: string | null;
  standbyLine: string | null;
  profileName: string | null;
};

export type AccessOnlineView = {
  username: string;
  lineId: string;
  lineName: string | null;
  ip: string;
  since: string;
  pinned: boolean;
};

export type PortalSnapshot = {
  device: {
    id: string;
    model: string;
    health: string;
    activeRevision: number;
    digestShort: string;
    lastApply: string;
    cloudReachable: boolean;
  };
  wifi: { enabled: boolean; ssid: string; band: string };
  exit: { lineName: string | null; region: string | null };
  clients: PortalClientView[];
  profiles: { id: string; name: string }[];
  lines: { id: string; name: string; region: string }[];
  diagnostics: { name: string; detail: string; status: 'ok' | 'warn' }[];
  /** 接入模式与在线会话（会话模式下门户的管理视图） */
  access: {
    mode: 'device_binding' | 'session';
    graceMinutes: number;
    online: AccessOnlineView[];
  };
  /** 仅用于本地口令校验，绝不出现在任何响应里 */
  accounts: PortalAccountView[];
};

export type Session = { username: string; role: 'customer' | 'device_admin'; displayName: string; exp: number };

/** 接入账号登录：账号决定出口线路，与管理员登录是两套东西 */
export type AccessLoginInput = {
  username: string;
  password: string;
  srcIp: string;
  macHash: string;
};

export type AccessLoginResult = {
  ok: boolean;
  lineId: string | null;
  lineName: string | null;
};

export type AccessStateView = {
  /** 当前设备是否处于「账号接入」模式；false 时门户展示原来的管理员/客户登录 */
  enabled: boolean;
  authed: boolean;
  username: string | null;
  lineId: string | null;
  lineName: string | null;
};

export type PortalDeps = {
  deviceId: string;
  secret: string;
  getSnapshot: () => PortalSnapshot;
  /** 会话模式才注入；未注入表示当前是设备绑定模式，门户不提供接入登录 */
  accessLogin?: (input: AccessLoginInput) => Promise<AccessLoginResult>;
  accessState?: (srcIp: string) => AccessStateView;
  accessLogout?: (srcIp: string) => Promise<boolean>;
  /** 设备管理员在门户里把某个在线用户踢下线 */
  accessKick?: (input: { username: string; by: string }) => Promise<boolean>;
  authorizeDevice: (input: { username: string; clientId: string; routeProfileId: string }) => Promise<void>;
  changeWifi: (input: { username: string; psk: string }) => Promise<void>;
  pinLine: (input: { username: string; clientId: string; lineId: string }) => Promise<void>;
  logger?: (line: string) => void;
};

const COOKIE = 'lp_session';
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;

function sign(secret: string, payload: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

export function createSessionToken(secret: string, session: Omit<Session, 'exp'>, ttlMs = SESSION_TTL_MS): string {
  const payload = Buffer.from(
    JSON.stringify({ ...session, exp: Date.now() + ttlMs }),
    'utf8',
  ).toString('base64url');
  return `${payload}.${sign(secret, payload)}`;
}

export function readSessionToken(secret: string, token: string | undefined): Session | null {
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = sign(secret, payload);
  if (expected.length !== signature.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Session;
    if (!session.exp || session.exp < Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return out;
}

function publicSnapshot(snapshot: PortalSnapshot): Omit<PortalSnapshot, 'accounts'> {
  const { accounts: _accounts, ...rest } = snapshot;
  return rest;
}

/** socket 给出的可能是 ::ffff:a.b.c.d，统一成纯 IPv4，避免集合里出现两种写法 */
export function normalizeIp(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
}

export function startPortal(deps: PortalDeps, port: number, host: string): http.Server {
  const router = new Router();
  const log = deps.logger ?? ((line: string) => console.log(line));

  function currentSession(ctx: Ctx): Session {
    const token = parseCookies(String(ctx.headers.cookie ?? ''))[COOKIE];
    const session = readSessionToken(deps.secret, token);
    if (!session) throw new AppError('UNAUTHORIZED', '请先登录');
    return session;
  }

  router.get('/', () => ({ raw: renderPortalHtml(), contentType: 'text/html; charset=utf-8' }));

  router.get('/api/portal/me', (ctx) => {
    const session = currentSession(ctx);
    return { body: { ok: true, me: session } };
  });

  router.post('/api/portal/login', (ctx) => {
    const body = (ctx.json ?? {}) as { username?: string; password?: string };
    const snapshot = deps.getSnapshot();
    const account = snapshot.accounts.find((a) => a.username === body.username);
    // 账号不存在与口令错误返回同一个错误，避免枚举账号
    if (!account || account.disabled || !verifyPassword(String(body.password ?? ''), account.passwordHash)) {
      throw new AppError('UNAUTHORIZED', '账号或密码错误');
    }
    const token = createSessionToken(deps.secret, {
      username: account.username,
      role: account.role,
      displayName: account.displayName,
    });
    log(`[portal] 登录成功 ${account.username} (${account.role})`);
    return {
      body: { ok: true },
      headers: {
        'set-cookie': `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
      },
    };
  });

  router.post('/api/portal/logout', () => ({
    body: { ok: true },
    headers: { 'set-cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` },
  }));

  /* --------------------------------------------------- 接入账号（会话模式） */

  router.post('/api/portal/access-login', async (ctx) => {
    if (!deps.accessLogin) throw new AppError('CAPABILITY_UNSUPPORTED', '当前不是账号接入模式');
    const body = (ctx.json ?? {}) as { username?: string; password?: string };
    const srcIp = normalizeIp(ctx.remoteAddress);
    if (!srcIp) throw new AppError('BAD_REQUEST', '无法识别客户端地址');
    const result = await deps.accessLogin({
      username: String(body.username ?? '').trim(),
      password: String(body.password ?? ''),
      srcIp,
      // MAC 摘要由设备侧用 ARP 表反查，不接受客户端自报——自报等于谁都能冒充别人
      macHash: '',
    });
    log(`[portal] 接入登录 ${result.ok ? '成功' : '失败'} src=${srcIp} line=${result.lineId ?? '-'}`);
    return { body: result };
  });

  router.get('/api/portal/access-state', (ctx) => {
    if (!deps.accessState) {
      return { body: { enabled: false, authed: false, username: null, lineId: null, lineName: null } };
    }
    const srcIp = normalizeIp(ctx.remoteAddress);
    return { body: deps.accessState(srcIp) };
  });

  router.post('/api/portal/access-logout', async (ctx) => {
    if (!deps.accessLogout) throw new AppError('CAPABILITY_UNSUPPORTED', '当前不是账号接入模式');
    const srcIp = normalizeIp(ctx.remoteAddress);
    const ok = await deps.accessLogout(srcIp);
    return { body: { ok } };
  });

  router.get('/api/portal/state', (ctx) => {
    const session = currentSession(ctx);
    return { body: { ok: true, me: session, snapshot: publicSnapshot(deps.getSnapshot()) } };
  });

  router.post('/api/portal/device-bindings', async (ctx) => {
    const session = currentSession(ctx);
    const body = (ctx.json ?? {}) as { clientId?: string; routeProfileId?: string };
    if (!body.clientId || !body.routeProfileId) throw new AppError('BAD_REQUEST', '缺少设备或线路策略');
    await deps.authorizeDevice({
      username: session.username,
      clientId: body.clientId,
      routeProfileId: body.routeProfileId,
    });
    log(`[portal] ${session.username} 授权设备 ${body.clientId} → ${body.routeProfileId}`);
    return { body: { ok: true } };
  });

  router.post('/api/portal/line-switch', async (ctx) => {
    const session = currentSession(ctx);
    if (session.role !== 'device_admin') throw new AppError('FORBIDDEN', '只有设备管理员可以手动切线路');
    const body = (ctx.json ?? {}) as { clientId?: string; lineId?: string };
    if (!body.clientId || !body.lineId) throw new AppError('BAD_REQUEST', '缺少设备或线路');
    await deps.pinLine({ username: session.username, clientId: body.clientId, lineId: body.lineId });
    log(`[portal] ${session.username} 手动锁线 ${body.clientId} → ${body.lineId}`);
    return { body: { ok: true } };
  });

  router.post('/api/portal/access-kick', async (ctx) => {
    const session = currentSession(ctx);
    if (session.role !== 'device_admin') throw new AppError('FORBIDDEN', '只有设备管理员可以踢线');
    if (!deps.accessKick) throw new AppError('CAPABILITY_UNSUPPORTED', '当前不是账号接入模式');
    const body = (ctx.json ?? {}) as { username?: string };
    const username = String(body.username ?? '').trim();
    if (!username) throw new AppError('BAD_REQUEST', '缺少账号');
    const ok = await deps.accessKick({ username, by: session.username });
    log(`[portal] ${session.username} 踢下线 ${username} → ${ok ? '成功' : '无此会话'}`);
    return { body: { ok } };
  });

  router.post('/api/portal/wifi', async (ctx) => {
    const session = currentSession(ctx);
    if (session.role !== 'device_admin') throw new AppError('FORBIDDEN', '只有设备管理员可以修改 Wi-Fi');
    const body = (ctx.json ?? {}) as { psk?: string };
    const psk = String(body.psk ?? '');
    if (psk.length < 8 || psk.length > 63) throw new AppError('BAD_REQUEST', '口令长度需为 8~63 位');
    await deps.changeWifi({ username: session.username, psk });
    log(`[portal] ${session.username} 修改 Wi-Fi 口令（不记录内容）`);
    return { body: { ok: true } };
  });

  return serve(router, { port, host, label: 'portal' });
}
