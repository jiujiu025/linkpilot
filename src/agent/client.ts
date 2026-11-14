/**
 * Agent → 云端 的签名 HTTP 客户端
 *
 * 每条请求都带 Ed25519 签名，签名覆盖方法、路径、时间戳、nonce 和请求体摘要。
 * 这样即使控制面被放在公网，抓到一个请求也无法篡改路径或重放——
 * 这是「云端不开放设备入站端口」的另一半：设备主动出站，但出站也要可验证。
 */
import http from 'node:http';
import https from 'node:https';
import { randomHex } from '../core/crypto.ts';
import { signAgentRequest } from '../core/bundle-envelope.ts';
import { AppError } from '../core/errors.ts';

export type AgentClientOptions = {
  baseUrl: string;
  deviceId: string;
  ed25519PrivateKey: string;
  timeoutMs?: number;
};

export type AgentClient = {
  /** 有 body 走 POST，无 body 走 GET；方法由调用方式决定，避免调用点写错 */
  call<T>(path: string, body?: unknown): Promise<T>;
};

export function createAgentClient(options: AgentClientOptions): AgentClient {
  const url = new URL(options.baseUrl);
  const transport = url.protocol === 'https:' ? https : http;
  const timeoutMs = options.timeoutMs ?? 8000;

  return {
    call<T>(path: string, body?: unknown): Promise<T> {
      const method: 'GET' | 'POST' = body === undefined ? 'GET' : 'POST';
      const payload = body === undefined ? '' : JSON.stringify(body);
      const timestamp = new Date().toISOString();
      const nonce = randomHex(8);
      const signature = signAgentRequest(
        method,
        path,
        timestamp,
        nonce,
        payload,
        options.ed25519PrivateKey,
      );

      const headers: Record<string, string> = {
        'content-type': 'application/json; charset=utf-8',
        'content-length': String(Buffer.byteLength(payload)),
        'x-lp-device': options.deviceId,
        'x-lp-timestamp': timestamp,
        'x-lp-nonce': nonce,
        'x-lp-signature': signature,
      };

      return new Promise<T>((resolve, reject) => {
        const req = transport.request(
          {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path,
            method,
            headers,
            timeout: timeoutMs,
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => chunks.push(chunk));
            res.on('end', () => {
              const text = Buffer.concat(chunks).toString('utf8');
              let parsed: unknown = null;
              try {
                parsed = text.length > 0 ? JSON.parse(text) : null;
              } catch {
                reject(new AppError('INTERNAL', `云端返回非 JSON 响应 (${res.statusCode})`));
                return;
              }
              if ((res.statusCode ?? 500) >= 400) {
                const detail = parsed as { error?: { code?: string; message?: string } };
                reject(
                  new AppError(
                    'INTERNAL',
                    `云端拒绝请求：${detail.error?.code ?? res.statusCode} ${detail.error?.message ?? ''}`.trim(),
                  ),
                );
                return;
              }
              resolve(parsed as T);
            });
          },
        );
        req.on('timeout', () => {
          req.destroy(new Error('请求超时'));
        });
        req.on('error', reject);
        if (payload.length > 0) req.write(payload);
        req.end();
      });
    },
  };
}

/** 无需签名的首次注册请求（此时设备还没有身份） */
export async function postEnrollment(
  baseUrl: string,
  body: unknown,
  timeoutMs = 8000,
): Promise<unknown> {
  const url = new URL(baseUrl);
  const transport = url.protocol === 'https:' ? https : http;
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: '/agent/enrollment',
        method: 'POST',
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'content-length': String(Buffer.byteLength(payload)),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            const parsed = JSON.parse(text) as { ok?: boolean; error?: { code?: string; message?: string } };
            if ((res.statusCode ?? 500) >= 400 || parsed.ok === false) {
              reject(new AppError('INTERNAL', `注册失败：${parsed.error?.code} ${parsed.error?.message ?? ''}`));
              return;
            }
            resolve(parsed);
          } catch {
            reject(new AppError('INTERNAL', '注册响应解析失败'));
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('注册请求超时')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}
