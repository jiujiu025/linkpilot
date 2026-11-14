/**
 * 门户 DNS 应答器
 *
 * 存在的唯一理由：让「连上 Wi-Fi 但没登录」的设备能自动弹登录页。
 *
 * 各家系统的连通性探测都是「解析一个固定域名 → 发 HTTP 请求 → 看返回内容」。
 * 如果 DNS 不回答，探测第一步就失败，多数系统只会显示「无法连接互联网」，
 * 不会弹登录页——用户根本不知道要去哪输账号。
 *
 * 做法：任意域名都答网关地址，HTTP 80 已被 nftables 劫持到门户，
 * 探测请求拿到 302 就会触发「需要登录」提示。这是酒店/机场网关的标准手法。
 *
 * 只答 A，AAAA 返回空：IPv6 在本产品里是全关的，答了反而会让客户端走 v6 超时。
 */
import dgram from 'node:dgram';
import net from 'node:net';

export type DnsAnswerOptions = {
  /** 所有 A 查询都解析到这个地址（通常是网关） */
  answerIp: string;
  /** 网关自身名字（如 portal.lan）返回真实解析，避免门户页面自己打不开 */
  ttlSeconds?: number;
};

const TYPE_A = 1;
const TYPE_AAAA = 28;
const CLASS_IN = 1;

function parseQuestionName(buf: Buffer, offset: number): { name: string; end: number } | null {
  const labels: string[] = [];
  let pos = offset;
  let guard = 0;
  while (pos < buf.length && guard < 128) {
    guard += 1;
    const len = buf[pos]!;
    if (len === 0) return { name: labels.join('.'), end: pos + 1 };
    if (len > 63 || pos + 1 + len > buf.length) return null;
    labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return null;
}

/**
 * 构造应答。纯函数，便于用构造出来的报文做单元测试——
 * 真机验证前只能靠这个保证「不会把报文拼坏」。
 */
export function buildDnsResponse(query: Buffer, options: DnsAnswerOptions): Buffer | null {
  if (query.length < 12) return null;
  const qdcount = query.readUInt16BE(4);
  if (qdcount !== 1) return null;

  const question = parseQuestionName(query, 12);
  if (!question) return null;
  const qtype = query.readUInt16BE(question.end);
  const qclass = query.readUInt16BE(question.end + 2);
  if (qclass !== CLASS_IN) return null;

  const questionEnd = question.end + 4;
  const questionBytes = query.subarray(12, questionEnd);

  const answerIp = net.isIPv4(options.answerIp) ? options.answerIp : null;
  const answers: Buffer[] = [];
  if (qtype === TYPE_A && answerIp) {
    const rdata = Buffer.from(answerIp.split('.').map((part) => Number(part) & 0xff));
    const record = Buffer.alloc(12 + rdata.length);
    record.writeUInt16BE(0xc00c, 0); // 指向问题里的域名
    record.writeUInt16BE(TYPE_A, 2);
    record.writeUInt16BE(CLASS_IN, 4);
    record.writeUInt32BE(options.ttlSeconds ?? 30, 6);
    record.writeUInt16BE(rdata.length, 10);
    rdata.copy(record, 12);
    answers.push(record);
  }

  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2); // 事务 ID 原样回传
  // QR=1, OPCODE 保留, RD 照抄, RA=1, RCODE=0(NOERROR)
  const rd = query.readUInt16BE(2) & 0x0100;
  header.writeUInt16BE(0x8000 | rd | 0x0080, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(0, 8);
  // 原查询若带 EDNS0，回一个空的 OPT，避免部分客户端认为响应不可用
  const arcount = query.readUInt16BE(10);
  let opt: Buffer | null = null;
  if (arcount > 0) {
    opt = Buffer.alloc(11);
    opt.writeUInt8(0, 0); // root name
    opt.writeUInt16BE(41, 1); // OPT
    opt.writeUInt16BE(1232, 3); // UDP payload size
    opt.writeUInt32BE(0, 5);
    opt.writeUInt16BE(0, 9);
  }
  header.writeUInt16BE(opt ? 1 : 0, 10);

  return Buffer.concat([header, questionBytes, ...answers, ...(opt ? [opt] : [])]);
}

export type PortalDnsHandle = {
  close: () => void;
  sockets: { udp: dgram.Socket; tcp: net.Server };
};

/**
 * 启动应答器。只监听指定地址，且**只在会话模式下启用**——
 * 设备绑定模式没有「未登录」状态，不需要它。
 */
export function startPortalDns(
  options: DnsAnswerOptions & { host: string; port?: number; logger?: (line: string) => void },
): PortalDnsHandle {
  const log = options.logger ?? (() => {});
  const port = options.port ?? 53;

  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg, rinfo) => {
    const reply = buildDnsResponse(msg, options);
    if (!reply) return;
    udp.send(reply, rinfo.port, rinfo.address, () => {});
  });
  udp.on('error', (error) => log(`[portal-dns] UDP 异常：${error.message}`));
  udp.bind(port, options.host);

  const tcp = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const length = buffer.readUInt16BE(0);
        if (buffer.length < 2 + length) return;
        const query = buffer.subarray(2, 2 + length);
        buffer = buffer.subarray(2 + length);
        const reply = buildDnsResponse(query, options);
        if (!reply) {
          socket.destroy();
          return;
        }
        const framed = Buffer.alloc(2 + reply.length);
        framed.writeUInt16BE(reply.length, 0);
        reply.copy(framed, 2);
        socket.write(framed);
      }
    });
    socket.on('error', () => socket.destroy());
  });
  tcp.on('error', (error) => log(`[portal-dns] TCP 异常：${error.message}`));
  tcp.listen(port, options.host);

  log(`[portal-dns] 已监听 ${options.host}:${port}，任意 A 记录 → ${options.answerIp}`);
  return {
    close: () => {
      udp.close();
      tcp.close();
    },
    sockets: { udp, tcp },
  };
}
