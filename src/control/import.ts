/**
 * 批量导入解析
 *
 * 为什么是 CSV 而不是 Excel 解析器：一百条线路/账号，粘贴文本是最短的路径，
 * 不需要额外依赖，也不会因为 xlsx 的合并单元格、隐藏列把数据搞错。
 *
 * 解析保持纯函数：只做「文本 → 结构化行 + 行号级错误」，不碰存储。
 * 这样 100 行里第 37 行写错了，能精确告诉你是哪一行错在哪。
 */

export type ImportRowResult = {
  line: number;
  status: 'created' | 'skipped' | 'error';
  message: string;
};

export type ParsedLineRow = {
  line: number;
  id: string;
  name: string;
  region: string;
  kind: 'shadowsocks' | 'trojan' | 'vless' | 'socks5' | 'wireguard' | 'http';
  server: string;
  port: number;
  credential: Record<string, unknown>;
};

export type ParsedAccountRow = {
  line: number;
  username: string;
  password: string;
  displayName: string;
  lineId: string;
  expiresAt: string | null;
};

const LINE_KINDS = new Set(['shadowsocks', 'trojan', 'vless', 'socks5', 'wireguard', 'http']);

/** 支持逗号或制表符；忽略空行与 # 注释；不做引号转义（线路参数里不该出现逗号） */
function splitRows(csv: string): { line: number; cells: string[] }[] {
  const out: { line: number; cells: string[] }[] = [];
  const lines = csv.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index]!.trim();
    if (raw.length === 0 || raw.startsWith('#')) continue;
    const cells = (raw.includes('\t') ? raw.split('\t') : raw.split(',')).map((cell) => cell.trim());
    out.push({ line: index + 1, cells });
  }
  return out;
}

function isHeader(cells: string[]): boolean {
  const first = (cells[0] ?? '').toLowerCase();
  return first === 'id' || first === 'username' || first === '账号' || first === '线路id';
}

/**
 * 线路表列顺序：
 * id, name, region, kind, server, port, secret, sni, wsPath
 *
 * secret 按协议解释：shadowsocks/trojan = 密码，vless = UUID，socks5 = 密码。
 * method 走默认值（shadowsocks 默认 aes-256-gcm），需要改特殊加密时用单条接口。
 */
export function parseLinesCsv(csv: string): { rows: ParsedLineRow[]; errors: ImportRowResult[] } {
  const rows: ParsedLineRow[] = [];
  const errors: ImportRowResult[] = [];
  for (const { line, cells } of splitRows(csv)) {
    if (isHeader(cells)) continue;
    const [id, name, region, kind, server, portText, secret, sni, wsPath] = cells;
    if (!id || !kind || !server) {
      errors.push({ line, status: 'error', message: '缺少必填列（id / kind / server）' });
      continue;
    }
    if (!LINE_KINDS.has(kind)) {
      errors.push({ line, status: 'error', message: `不支持的协议 ${kind}` });
      continue;
    }
    const port = Number(portText ?? '');
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push({ line, status: 'error', message: `端口不合法：${portText ?? ''}` });
      continue;
    }
    const credential = buildCredential(kind, secret ?? '', sni ?? '', wsPath ?? '');
    if ('error' in credential) {
      errors.push({ line, status: 'error', message: credential.error });
      continue;
    }
    rows.push({
      line,
      id,
      name: name || id,
      region: region || '未标注',
      kind: kind as ParsedLineRow['kind'],
      server,
      port,
      credential: credential.value,
    });
  }
  return { rows, errors };
}

function buildCredential(
  kind: string,
  secret: string,
  sni: string,
  wsPath: string,
): { value: Record<string, unknown> } | { error: string } {
  const tls = sni ? { serverName: sni, alpn: [] as string[], allowInsecure: false } : null;
  switch (kind) {
    case 'shadowsocks':
      if (!secret) return { error: 'Shadowsocks 需要密码' };
      return { value: { kind, method: 'aes-256-gcm', password: secret } };
    case 'trojan':
      if (!secret) return { error: 'Trojan 需要密码' };
      if (!tls) return { error: 'Trojan 需要 SNI（TLS 必须）' };
      return { value: { kind, password: secret, tls } };
    case 'vless':
      if (!secret) return { error: 'VLESS 需要 UUID' };
      return {
        value: {
          kind,
          uuid: secret,
          tls,
          transport: wsPath ? { type: 'ws', path: wsPath } : { type: 'tcp' },
        },
      };
    case 'socks5':
      if (!secret) return { error: 'SOCKS5 需要密码' };
      return { value: { kind, username: 'linkpilot', password: secret } };
    case 'wireguard':
      if (!secret) return { error: 'WireGuard 需要私钥' };
      return { value: { kind, privateKey: secret, localAddress: '10.0.0.2/32', peerPublicKey: '', mtu: 1420 } };
    case 'http':
      if (!secret) return { error: 'HTTP 代理需要密码' };
      return { value: { kind, username: 'linkpilot', password: secret } };
    default:
      return { error: `不支持的协议 ${kind}` };
  }
}

/** 账号表列顺序：username, password, displayName, lineId, expiresAt */
export function parseAccountsCsv(csv: string): { rows: ParsedAccountRow[]; errors: ImportRowResult[] } {
  const rows: ParsedAccountRow[] = [];
  const errors: ImportRowResult[] = [];
  const seen = new Set<string>();
  for (const { line, cells } of splitRows(csv)) {
    if (isHeader(cells)) continue;
    const [username, password, displayName, lineId, expiresAt] = cells;
    if (!username || !password || !lineId) {
      errors.push({ line, status: 'error', message: '缺少必填列（username / password / lineId）' });
      continue;
    }
    if (username.length < 3) {
      errors.push({ line, status: 'error', message: '账号至少 3 位' });
      continue;
    }
    if (password.length < 8) {
      errors.push({ line, status: 'error', message: '密码至少 8 位' });
      continue;
    }
    if (seen.has(username)) {
      errors.push({ line, status: 'error', message: `文件内账号重复：${username}` });
      continue;
    }
    seen.add(username);
    const expires = expiresAt && expiresAt.length > 0 ? normalizeDate(expiresAt) : null;
    if (expiresAt && expires === null) {
      errors.push({ line, status: 'error', message: `到期日格式无法识别：${expiresAt}` });
      continue;
    }
    rows.push({
      line,
      username,
      password,
      displayName: displayName || username,
      lineId,
      expiresAt: expires,
    });
  }
  return { rows, errors };
}

/** 接受 2026-12-31 或 2026/12/31，统一成 ISO 字符串（当天 23:59:59 到期） */
function normalizeDate(text: string): string | null {
  const normalized = text.replace(/\//g, '-');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(normalized)) return null;
  const parsed = Date.parse(`${normalized}T23:59:59.000Z`);
  if (!Number.isFinite(parsed)) return null;
  return new Date(parsed).toISOString();
}

/**
 * 一百台设备的地址池检查。
 *
 * 静默失败最难查：池子不够时表现为「一部分手机连上了但拿不到地址」，
 * 用户只会说「你们这个 Wi-Fi 有问题」。所以在导入时就把它算出来。
 */
export function poolCapacity(dhcpStart: string, dhcpEnd: string): number {
  const from = dhcpStart.split('.').map(Number);
  const to = dhcpEnd.split('.').map(Number);
  if (from.length !== 4 || to.length !== 4) return 0;
  const start = from[3] ?? 0;
  const end = to[3] ?? 0;
  return end > start ? end - start + 1 : 0;
}
