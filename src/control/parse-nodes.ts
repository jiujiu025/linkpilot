/**
 * 分享链接识别（ss:// / vmess:// / vless:// / trojan:// / hy2:// / socks5:// / http://）
 *
 * 为什么要有这一层：机场和自建服务给的都是分享链接，让人手工拆成表格不现实，
 * 一百条抄错三条就够排查一晚。这里把「粘贴一串链接」变成「结构化线路」。
 *
 * 明确不支持的要报错而不是猜：VMess 老式明文、SSR、TUIC、AnyTLS 我们内核没接，
 * 静默跳过会让运营以为导入了 100 条，实际只有 80 条可用。
 */
import type { LineCredential } from '../core/schema.ts';

export type ParsedNode = {
  index: number;
  id: string;
  name: string;
  region: string;
  server: string;
  port: number;
  credential: LineCredential;
  raw: string;
};

export type NodeError = { index: number; line: number; message: string };

export type ParseNodeOptions = {
  idPrefix?: string;
  /** 识别失败时是否把整行贴进错误里（默认贴前 40 字） */
  echoLength?: number;
};

const REGION_HINTS: { pattern: RegExp; region: string }[] = [
  { pattern: /(香港|hk|hong\s*kong)/i, region: '香港' },
  { pattern: /(台湾|tw|taiwan)/i, region: '台湾' },
  { pattern: /(日本|jp|japan|东京|大阪)/i, region: '日本' },
  { pattern: /(新加坡|sg|singapore|狮城)/i, region: '新加坡' },
  { pattern: /(美国|us|united\s*states|洛杉矶|圣何塞|西雅图|纽约|达拉斯|硅谷)/i, region: '美国' },
  { pattern: /(韩国|kr|korea|首尔)/i, region: '韩国' },
  { pattern: /(英国|uk|britain|london|伦敦)/i, region: '英国' },
  { pattern: /(德国|de|germany|法兰克福)/i, region: '德国' },
  { pattern: /(马来|my|malaysia)/i, region: '马来西亚' },
  { pattern: /(泰国|th|thailand)/i, region: '泰国' },
  { pattern: /(越南|vn|vietnam)/i, region: '越南' },
  { pattern: /(菲律宾|ph|philippines)/i, region: '菲律宾' },
  { pattern: /(印度|in|india)/i, region: '印度' },
  { pattern: /(加拿大|ca|canada)/i, region: '加拿大' },
  { pattern: /(澳大利亚|澳洲|au|australia)/i, region: '澳大利亚' },
  { pattern: /(土耳其|tr|turkey)/i, region: '土耳其' },
  { pattern: /(俄罗斯|ru|russia)/i, region: '俄罗斯' },
];

const SS_METHODS = new Set([
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
]);

function b64decode(input: string): string {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, 'base64').toString('utf8');
}

function splitFragment(raw: string): { body: string; name: string } {
  const hash = raw.indexOf('#');
  if (hash < 0) return { body: raw, name: '' };
  return { body: raw.slice(0, hash), name: decodeURIComponent(raw.slice(hash + 1)).trim() };
}

function splitHostPort(hostPart: string): { host: string; port: number } | null {
  const cleaned = hostPart.split('?')[0] ?? '';
  // IPv6: [::1]:443
  if (cleaned.startsWith('[')) {
    const end = cleaned.indexOf(']');
    if (end < 0) return null;
    const host = cleaned.slice(1, end);
    const port = Number(cleaned.slice(end + 2));
    return Number.isInteger(port) ? { host, port } : null;
  }
  const colon = cleaned.lastIndexOf(':');
  if (colon < 0) return null;
  const host = cleaned.slice(0, colon);
  const port = Number(cleaned.slice(colon + 1));
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

function query(text: string): URLSearchParams {
  const index = text.indexOf('?');
  return new URLSearchParams(index >= 0 ? text.slice(index + 1).split('#')[0] : '');
}

function truthy(value: string | null): boolean {
  return value === '1' || value === 'true';
}

function guessRegion(name: string, server: string): string {
  const target = `${name} ${server}`;
  for (const hint of REGION_HINTS) {
    if (hint.pattern.test(target)) return hint.region;
  }
  return '未标注';
}

type NodeBody = {
  name: string;
  server: string;
  port: number;
  credential: LineCredential;
};

function parseShadowsocks(raw: string): NodeBody | string {
  const { body, name } = splitFragment(raw.slice('ss://'.length));
  let userInfo = '';
  let hostPart = '';
  if (body.includes('@')) {
    const at = body.lastIndexOf('@');
    userInfo = body.slice(0, at);
    hostPart = body.slice(at + 1);
    // SIP002：userinfo 为 base64(method:password)；也兼容明文
    if (!userInfo.includes(':')) {
      try {
        userInfo = b64decode(userInfo);
      } catch {
        return 'SS 用户信息无法解析';
      }
    }
  } else {
    // 老格式：整段 base64(method:password@host:port)
    let decoded = '';
    try {
      decoded = b64decode(body);
    } catch {
      return 'SS 链接不是合法 base64';
    }
    const at = decoded.lastIndexOf('@');
    if (at < 0) return 'SS 链接缺少服务器地址';
    userInfo = decoded.slice(0, at);
    hostPart = decoded.slice(at + 1);
  }
  const target = splitHostPort(hostPart);
  if (!target) return 'SS 服务器地址或端口不合法';
  const sep = userInfo.indexOf(':');
  if (sep < 0) return 'SS 缺少加密方法或密码';
  const method = userInfo.slice(0, sep).trim();
  const password = userInfo.slice(sep + 1);
  if (!SS_METHODS.has(method)) return `不支持的 SS 加密方法：${method}`;
  if (!password) return 'SS 密码为空';
  return {
    name,
    server: target.host,
    port: target.port,
    credential: { kind: 'shadowsocks', method: method as never, password },
  };
}

function parseVmess(raw: string): NodeBody | string {
  let decoded = '';
  try {
    decoded = b64decode(raw.slice('vmess://'.length));
  } catch {
    return 'VMess 链接不是合法 base64';
  }
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return 'VMess 内容不是合法 JSON';
  }
  const server = String(json.add ?? '');
  const port = Number(json.port ?? 0);
  const uuid = String(json.id ?? '');
  if (!server || !uuid || !Number.isInteger(port) || port <= 0) return 'VMess 缺少服务器、端口或 UUID';
  const net = String(json.net ?? 'tcp');
  const tls = String(json.tls ?? '');
  const sni = String(json.sni ?? json.host ?? '').trim();
  const path = String(json.path ?? '').trim();
  const hostHeader = String(json.host ?? '').trim();
  const transport =
    net === 'ws'
      ? { type: 'ws' as const, path: path || '/', host: hostHeader || undefined }
      : net === 'grpc'
        ? { type: 'grpc' as const, serviceName: path || undefined }
        : { type: 'tcp' as const };
  return {
    name: String(json.ps ?? ''),
    server,
    port,
    credential: {
      kind: 'vmess',
      uuid,
      alterId: Number(json.aid ?? 0) || 0,
      security: 'auto',
      tls: tls === 'tls' ? { serverName: sni || server, alpn: [], allowInsecure: false } : null,
      transport,
    },
  };
}

function parseVless(raw: string): NodeBody | string {
  const { body, name } = splitFragment(raw.slice('vless://'.length));
  const at = body.indexOf('@');
  if (at < 0) return 'VLESS 缺少 UUID 或服务器';
  const uuid = body.slice(0, at).trim();
  const target = splitHostPort(body.slice(at + 1));
  if (!target) return 'VLESS 服务器地址或端口不合法';
  if (!uuid) return 'VLESS 缺少 UUID';
  const q = query(body);
  const security = (q.get('security') ?? 'none').toLowerCase();
  const sni = q.get('sni') ?? q.get('host') ?? '';
  const realityPub = q.get('pbk') ?? '';
  const tls =
    security === 'tls' || security === 'reality'
      ? {
          serverName: sni || target.host,
          alpn: [],
          allowInsecure: truthy(q.get('allowInsecure')) || truthy(q.get('insecure')),
          ...(security === 'reality' && realityPub
            ? { reality: { publicKey: realityPub, shortId: q.get('sid') ?? '' } }
            : {}),
        }
      : null;
  const type = (q.get('type') ?? 'tcp').toLowerCase();
  const transport =
    type === 'ws'
      ? { type: 'ws' as const, path: q.get('path') || '/', host: q.get('host') || undefined }
      : type === 'grpc'
        ? { type: 'grpc' as const, serviceName: q.get('serviceName') || undefined }
        : type === 'httpupgrade'
          ? { type: 'httpupgrade' as const, path: q.get('path') || '/', host: q.get('host') || undefined }
          : { type: 'tcp' as const };
  return {
    name,
    server: target.host,
    port: target.port,
    credential: {
      kind: 'vless',
      uuid,
      flow: q.get('flow') === 'xtls-rprx-vision' ? 'xtls-rprx-vision' : '',
      tls,
      transport,
    },
  };
}

function parseTrojan(raw: string): NodeBody | string {
  const { body, name } = splitFragment(raw.slice('trojan://'.length));
  const at = body.indexOf('@');
  if (at < 0) return 'Trojan 缺少密码或服务器';
  const password = decodeURIComponent(body.slice(0, at)).trim();
  const target = splitHostPort(body.slice(at + 1));
  if (!target) return 'Trojan 服务器地址或端口不合法';
  if (!password) return 'Trojan 密码为空';
  const q = query(body);
  const sni = q.get('sni') ?? q.get('peer') ?? target.host;
  const type = (q.get('type') ?? 'tcp').toLowerCase();
  const transport =
    type === 'ws'
      ? { type: 'ws' as const, path: q.get('path') || '/', host: q.get('host') || undefined }
      : type === 'grpc'
        ? { type: 'grpc' as const, serviceName: q.get('serviceName') || undefined }
        : { type: 'tcp' as const };
  return {
    name,
    server: target.host,
    port: target.port,
    credential: {
      kind: 'trojan',
      password,
      tls: {
        serverName: sni,
        alpn: [],
        allowInsecure: truthy(q.get('allowInsecure')) || truthy(q.get('insecure')),
      },
      transport,
    },
  };
}

function parseHysteria2(raw: string): NodeBody | string {
  const withoutScheme = raw.replace(/^hy2:\/\//i, '').replace(/^hysteria2:\/\//i, '');
  const { body, name } = splitFragment(withoutScheme);
  const at = body.indexOf('@');
  if (at < 0) return 'Hysteria2 缺少密码或服务器';
  const password = decodeURIComponent(body.slice(0, at)).trim();
  const target = splitHostPort(body.slice(at + 1));
  if (!target) return 'Hysteria2 服务器地址或端口不合法';
  if (!password) return 'Hysteria2 密码为空';
  const q = query(body);
  const obfs = q.get('obfs') === 'salamander' ? q.get('obfs-password') : null;
  return {
    name,
    server: target.host,
    port: target.port,
    credential: {
      kind: 'hysteria2',
      password,
      tls: {
        serverName: q.get('sni') ?? target.host,
        alpn: [],
        allowInsecure: truthy(q.get('insecure')),
      },
      obfs: obfs ? { type: 'salamander', password: obfs } : null,
    },
  };
}

function parseSocks(raw: string, scheme: string): NodeBody | string {
  // 必须按实际匹配到的前缀切片：用错长度会把用户名截掉一个字母，且极难发现
  const https = scheme.startsWith('http');
  const { body, name } = splitFragment(raw.slice(scheme.length));
  const at = body.lastIndexOf('@');
  const auth = at >= 0 ? body.slice(0, at) : '';
  const target = splitHostPort(at >= 0 ? body.slice(at + 1) : body);
  if (!target) return '代理地址或端口不合法';
  const [username, password] = auth.includes(':')
    ? [decodeURIComponent(auth.slice(0, auth.indexOf(':'))), decodeURIComponent(auth.slice(auth.indexOf(':') + 1))]
    : ['', ''];
  return {
    name,
    server: target.host,
    port: target.port,
    credential: https
      ? { kind: 'http', username: username || undefined, password: password || undefined }
      : { kind: 'socks5', username: username || undefined, password: password || undefined },
  };
}

function parseOne(raw: string): NodeBody | string {
  const line = raw.trim();
  const lower = line.toLowerCase();
  if (lower.startsWith('ss://')) return parseShadowsocks(line);
  if (lower.startsWith('vmess://')) return parseVmess(line);
  if (lower.startsWith('vless://')) return parseVless(line);
  if (lower.startsWith('trojan://')) return parseTrojan(line);
  if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) return parseHysteria2(line);
  if (lower.startsWith('socks5://')) return parseSocks(line, 'socks5://');
  if (lower.startsWith('socks://')) return parseSocks(line, 'socks://');
  if (lower.startsWith('https://')) return parseSocks(line, 'https://');
  if (lower.startsWith('http://')) return parseSocks(line, 'http://');
  if (lower.startsWith('ssr://')) return '不支持 SSR（内核未接入），请让服务方提供 SS/VLESS/Trojan';
  if (lower.startsWith('tuic://')) return '不支持 TUIC（内核未接入），可用 Hysteria2 或 VLESS 替代';
  if (lower.startsWith('hysteria://')) return '不支持 Hysteria v1，请用 hysteria2://';
  if (lower.startsWith('anytls://')) return '不支持 AnyTLS（内核未接入）';
  return '无法识别的链接格式';
}

/**
 * 解析整份清单。
 *
 * 重复节点直接跳过：同一条线路给两个账号用，本质是两个客户共用一个出口 IP，
 * 这跟「一人一 IP」冲突，宁可少导入也不要留下隐患。
 */
export function parseNodeList(text: string, options: ParseNodeOptions = {}): {
  nodes: ParsedNode[];
  errors: NodeError[];
  duplicates: NodeError[];
} {
  const nodes: ParsedNode[] = [];
  const errors: NodeError[] = [];
  const duplicates: NodeError[] = [];
  const seen = new Set<string>();
  const prefix = options.idPrefix ?? 'line';
  const echoLength = options.echoLength ?? 40;

  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  let index = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i]!.trim();
    if (raw.length === 0 || raw.startsWith('#')) continue;
    index += 1;
    const parsed = parseOne(raw);
    if (typeof parsed === 'string') {
      errors.push({ index, line: i + 1, message: `${parsed}：${raw.slice(0, echoLength)}` });
      continue;
    }
    const fingerprint = `${parsed.credential.kind}|${parsed.server}|${parsed.port}|${JSON.stringify(parsed.credential)}`;
    if (seen.has(fingerprint)) {
      duplicates.push({ index, line: i + 1, message: `与前面的节点完全相同，已跳过：${parsed.server}:${parsed.port}` });
      continue;
    }
    seen.add(fingerprint);
    const name = parsed.name || `${prefix.toUpperCase()}-${String(nodes.length + 1).padStart(3, '0')}`;
    nodes.push({
      index: nodes.length + 1,
      id: `${prefix}-${String(nodes.length + 1).padStart(3, '0')}`,
      name,
      region: guessRegion(parsed.name, parsed.server),
      server: parsed.server,
      port: parsed.port,
      credential: parsed.credential,
      raw: raw.slice(0, echoLength),
    });
  }
  return { nodes, errors, duplicates };
}

/** 账号名：jy001…jy100，位数按总数确定，保证排序稳定 */
export function accountNameFor(prefix: string, ordinal: number, total: number): string {
  const width = Math.max(3, String(total).length);
  return `${prefix}${String(ordinal).padStart(width, '0')}`;
}
