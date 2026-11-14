/**
 * 线路可用性探测（云端侧）
 *
 * 能力边界必须说清楚，否则会误判：
 * - 这里测的是「从云端到落地节点的 TCP/TLS 握手」，能证明端口可达、证书/SNI 对得上；
 * - **不能证明凭证有效、也代表不了客户本地网络的链路质量**。
 * 真正等价于 PassWall「URL 测试」的做法，要在设备上拉起 sing-box 走一次真实请求，
 * 那是下一步；当前这一层解决的是「一百条里哪几条是死的」，先止损。
 */
import net from 'node:net';
import tls from 'node:tls';
import type { LineCredential } from '../core/schema.ts';

export type ProbeOutcome = {
  ok: boolean;
  /** tcp = 只做了三次握手；tls = 还验了证书与 SNI */
  kind: 'tcp' | 'tls';
  rttMs: number | null;
  error: string | null;
  at: string;
};

export type ProbeTarget = {
  server: string;
  port: number;
  tlsServerName: string | null;
  allowInsecure: boolean;
};

/** 从凭证里取出「要不要做 TLS 握手」以及 SNI */
export function probeTargetOf(
  credential: LineCredential | null,
  fallback: { server: string; port: number },
): ProbeTarget {
  const base: ProbeTarget = {
    server: fallback.server,
    port: fallback.port,
    tlsServerName: null,
    allowInsecure: false,
  };
  if (!credential) return base;
  switch (credential.kind) {
    case 'trojan':
      return { ...base, tlsServerName: credential.tls.serverName, allowInsecure: credential.tls.allowInsecure };
    case 'vless':
    case 'vmess':
      return credential.tls
        ? { ...base, tlsServerName: credential.tls.serverName, allowInsecure: credential.tls.allowInsecure }
        : base;
    case 'hysteria2':
      // Hysteria2 强制 TLS，握手能验出证书与 SNI 是否匹配
      return credential.tls
        ? { ...base, tlsServerName: credential.tls.serverName, allowInsecure: credential.tls.allowInsecure }
        : base;
    default:
      return base;
  }
}

function normalizeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/ENOTFOUND|EAI_AGAIN/.test(message)) return '域名解析失败';
  if (/ECONNREFUSED/.test(message)) return '端口拒绝连接';
  if (/ETIMEDOUT|timeout/i.test(message)) return '连接超时';
  if (/EHOSTUNREACH|ENETUNREACH/.test(message)) return '网络不可达';
  if (/certificate|self signed|CERT_/i.test(message)) return '证书校验失败（可标记 insecure）';
  return message.split('\n')[0] ?? '未知错误';
}

/**
 * 单条线路探测。
 *
 * 一律不抛异常：批量测 100 条时，一条挂掉不能让整批结果丢失。
 */
export function probeLine(target: ProbeTarget, timeoutMs = 4000): Promise<ProbeOutcome> {
  const at = new Date().toISOString();
  const started = Date.now();

  return new Promise<ProbeOutcome>((resolve) => {
    let settled = false;
    const done = (outcome: Omit<ProbeOutcome, 'at'>): void => {
      if (settled) return;
      settled = true;
      resolve({ ...outcome, at });
    };

    if (target.tlsServerName) {
      const socket = tls.connect({
        host: target.server,
        port: target.port,
        servername: target.tlsServerName,
        rejectUnauthorized: !target.allowInsecure,
        timeout: timeoutMs,
      });
      socket.once('secureConnect', () => {
        const rtt = Date.now() - started;
        socket.destroy();
        done({ ok: true, kind: 'tls', rttMs: rtt, error: null });
      });
      socket.once('timeout', () => {
        socket.destroy();
        done({ ok: false, kind: 'tls', rttMs: null, error: '连接超时' });
      });
      socket.once('error', (error) => {
        socket.destroy();
        done({ ok: false, kind: 'tls', rttMs: null, error: normalizeError(error) });
      });
      return;
    }

    const socket = net.connect({ host: target.server, port: target.port, timeout: timeoutMs });
    socket.once('connect', () => {
      const rtt = Date.now() - started;
      socket.destroy();
      done({ ok: true, kind: 'tcp', rttMs: rtt, error: null });
    });
    socket.once('timeout', () => {
      socket.destroy();
      done({ ok: false, kind: 'tcp', rttMs: null, error: '连接超时' });
    });
    socket.once('error', (error) => {
      socket.destroy();
      done({ ok: false, kind: 'tcp', rttMs: null, error: normalizeError(error) });
    });
  });
}

/** 并发受限的批量探测：100 条 × 4 秒超时，无节制并发会把自己的出网打满 */
export async function probeMany<T>(
  items: T[],
  worker: (item: T) => Promise<ProbeOutcome>,
  concurrency = 8,
): Promise<{ item: T; outcome: ProbeOutcome }[]> {
  const results: { item: T; outcome: ProbeOutcome }[] = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index]!;
      results[index] = { item, outcome: await worker(item) };
    }
  });
  await Promise.all(runners);
  return results;
}
