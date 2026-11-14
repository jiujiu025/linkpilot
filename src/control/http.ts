/**
 * 极简 HTTP 路由
 *
 * 刻意不引框架：控制面要和设备侧共享同一套错误模型与状态码语义，
 * 多一层框架就多一层「它到底返回了什么」的不确定性。
 */
import http from 'node:http';
import { AppError, errorBody } from '../core/errors.ts';

export type Ctx = {
  method: string;
  path: string;
  query: URLSearchParams;
  params: Record<string, string>;
  headers: http.IncomingHttpHeaders;
  /** 对端地址：门户要靠它判断「谁在登录」，因此必须由服务端取，不能信请求体 */
  remoteAddress: string;
  rawBody: string;
  json: unknown;
};

export type HandlerResult = {
  status?: number;
  body?: unknown;
  raw?: string;
  contentType?: string;
  headers?: Record<string, string>;
};

export type Handler = (ctx: Ctx) => Promise<HandlerResult | void> | HandlerResult | void;

type Route = { method: string; segments: string[]; handler: Handler };

const MAX_BODY = 2 * 1024 * 1024;

export class Router {
  private readonly routes: Route[] = [];

  add(method: string, pattern: string, handler: Handler): this {
    this.routes.push({
      method: method.toUpperCase(),
      segments: pattern.split('/').filter((s) => s.length > 0),
      handler,
    });
    return this;
  }

  get(pattern: string, handler: Handler): this {
    return this.add('GET', pattern, handler);
  }

  post(pattern: string, handler: Handler): this {
    return this.add('POST', pattern, handler);
  }

  patch(pattern: string, handler: Handler): this {
    return this.add('PATCH', pattern, handler);
  }

  match(method: string, pathname: string): { handler: Handler; params: Record<string, string> } | null {
    const parts = pathname.split('/').filter((s) => s.length > 0);
    for (const route of this.routes) {
      if (route.method !== method.toUpperCase()) continue;
      if (route.segments.length !== parts.length) continue;
      const params: Record<string, string> = {};
      let ok = true;
      for (let i = 0; i < route.segments.length; i += 1) {
        const seg = route.segments[i]!;
        const part = parts[i]!;
        if (seg.startsWith(':')) params[seg.slice(1)] = decodeURIComponent(part);
        else if (seg !== part) {
          ok = false;
          break;
        }
      }
      if (ok) return { handler: route.handler, params };
    }
    return null;
  }
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new AppError('BAD_REQUEST', '请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export type ServeOptions = {
  port: number;
  host?: string;
  label: string;
  onListen?: () => void;
};

export function serve(router: Router, options: ServeOptions): http.Server {
  const server = http.createServer((req, res) => {
    void (async () => {
      const started = Date.now();
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      const method = req.method ?? 'GET';
      let status = 500;
      try {
        const matched = router.match(method, url.pathname);
        if (!matched) {
          status = 404;
          res.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ ok: false, error: { code: 'NOT_FOUND', message: '接口不存在' } }));
          return;
        }
        const rawBody = method === 'GET' ? '' : await readBody(req);
        let json: unknown = null;
        if (rawBody.length > 0) {
          try {
            json = JSON.parse(rawBody);
          } catch {
            throw new AppError('BAD_REQUEST', '请求体不是合法 JSON');
          }
        }
        const result =
          (await matched.handler({
            method,
            path: url.pathname,
            query: url.searchParams,
            params: matched.params,
            headers: req.headers,
            remoteAddress: req.socket.remoteAddress ?? '',
            rawBody,
            json,
          })) ?? {};
        status = result.status ?? 200;
        const headers: Record<string, string> = { ...(result.headers ?? {}) };
        if (result.raw !== undefined) {
          headers['content-type'] = result.contentType ?? 'text/plain; charset=utf-8';
          res.writeHead(status, headers);
          res.end(result.raw);
          return;
        }
        headers['content-type'] = 'application/json; charset=utf-8';
        headers['cache-control'] = 'no-store';
        res.writeHead(status, headers);
        res.end(JSON.stringify(result.body ?? { ok: true }));
      } catch (error) {
        const body = errorBody(error);
        status = error instanceof AppError ? error.status : 500;
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(body));
        if (status >= 500) {
          console.error(`[${options.label}] ${method} ${url.pathname} → ${status}`, error);
        }
      } finally {
        if (status !== 404) {
          console.log(
            `[${options.label}] ${method} ${url.pathname} → ${status} ${Date.now() - started}ms`,
          );
        }
      }
    })();
  });

  server.listen(options.port, options.host ?? '127.0.0.1', () => {
    options.onListen?.();
  });
  return server;
}
