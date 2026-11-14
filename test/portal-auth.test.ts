/**
 * 接入认证的周边件：DNS 应答器、ARP/租约解析
 *
 * 这些逻辑在真机上很难复现（要真的连设备、等弹窗），
 * 所以把报文拼装和文本解析抽成纯函数，用构造数据守住。
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildDnsResponse } from '../src/agent/portal-dns.ts';
import { identityForIp, parseArpTable, parseDhcpLeases, ipForMacHash } from '../src/agent/netinfo.ts';
import { hashMacAddress } from '../src/core/crypto.ts';

const GATEWAY = '192.168.10.1';

function dnsQuery(name: string, qtype: number, withEdns = false): Buffer {
  const labels = name.split('.').map((label) => {
    const buf = Buffer.alloc(1 + label.length);
    buf.writeUInt8(label.length, 0);
    buf.write(label, 1, 'ascii');
    return buf;
  });
  const question = Buffer.concat([
    ...labels,
    Buffer.from([0]),
    Buffer.from([qtype >> 8, qtype & 0xff, 0, 1]),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(withEdns ? 1 : 0, 10);
  const opt = withEdns
    ? Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0])
    : Buffer.alloc(0);
  return Buffer.concat([header, question, opt]);
}

describe('门户 DNS 应答器', () => {
  it('任意 A 查询都答网关地址，用于触发登录弹窗', () => {
    const reply = buildDnsResponse(dnsQuery('captive.apple.com', 1), { answerIp: GATEWAY });
    assert.ok(reply);
    assert.equal(reply.readUInt16BE(0), 0x1234, '事务 ID 必须原样回传');
    assert.equal(reply.readUInt16BE(2) & 0x8000, 0x8000, 'QR 位必须为响应');
    assert.equal(reply.readUInt16BE(6), 1, '必须有一条 A 记录');
    // 答案在报文尾部：type/class/ttl/rdlength + 4 字节地址
    const tail = reply.subarray(reply.length - 4);
    assert.deepEqual([...tail], [192, 168, 10, 1]);
  });

  it('AAAA 查询返回空答案：IPv6 全关，答了只会让客户端等超时', () => {
    const reply = buildDnsResponse(dnsQuery('example.com', 28), { answerIp: GATEWAY });
    assert.ok(reply);
    assert.equal(reply.readUInt16BE(6), 0);
    assert.equal(reply.readUInt16BE(2) & 0x000f, 0, 'RCODE 应为 NOERROR');
  });

  it('带 EDNS0 的查询会回一个空 OPT，避免部分客户端判定响应不可用', () => {
    const reply = buildDnsResponse(dnsQuery('example.com', 1, true), { answerIp: GATEWAY });
    assert.ok(reply);
    assert.equal(reply.readUInt16BE(10), 1, 'ARCOUNT 应为 1');
  });

  it('畸形报文直接丢弃，不生成半个响应', () => {
    assert.equal(buildDnsResponse(Buffer.alloc(4), { answerIp: GATEWAY }), null);
    const twoQuestions = dnsQuery('a.com', 1);
    twoQuestions.writeUInt16BE(2, 4);
    assert.equal(buildDnsResponse(twoQuestions, { answerIp: GATEWAY }), null);
  });
});

describe('设备身份：ARP 与 DHCP 租约', () => {
  it('ARP 表解析会跳过无效条目', () => {
    const text = [
      'IP address       HW type     Flags       HW address            Mask     Device',
      '192.168.10.101   0x1         0x2         aa:bb:cc:dd:ee:01     *        br-lan',
      '192.168.10.102   0x1         0x0         00:00:00:00:00:00     *        br-lan',
      '',
    ].join('\n');
    assert.deepEqual(parseArpTable(text), [{ ip: '192.168.10.101', mac: 'aa:bb:cc:dd:ee:01' }]);
  });

  it('dnsmasq 租约解析：* 表示无主机名', () => {
    const text = '1750000000 aa:bb:cc:dd:ee:02 192.168.10.120 * 01:aa:bb\n';
    assert.deepEqual(parseDhcpLeases(text), [
      { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.10.120', hostname: '' },
    ]);
  });

  it('拿不到 MAC 时退化为按 IP 生成稳定标识，而不是拒绝登录', () => {
    const { macHash, mac } = identityForIp('192.168.10.150', []);
    assert.equal(mac, null);
    assert.equal(macHash, hashMacAddress('ip:192.168.10.150'));
  });

  it('预授权设备按 MAC 摘要反查当前 IP', () => {
    const leases = [{ mac: 'aa:bb:cc:dd:ee:03', ip: '192.168.10.130', hostname: 'encoder' }];
    assert.equal(ipForMacHash(hashMacAddress('aa:bb:cc:dd:ee:03'), leases), '192.168.10.130');
    assert.equal(ipForMacHash(hashMacAddress('aa:bb:cc:dd:ee:04'), leases), null);
  });
});
