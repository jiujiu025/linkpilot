/**
 * 分享链接识别
 *
 * 这一层的错误代价很高：错一条就是一条卖出去的线路出口不对。
 * 所以用例覆盖「各种协议的真实链接形态」以及「不支持的协议必须报错」。
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { accountNameFor, parseNodeList } from '../src/control/parse-nodes.ts';

const b64 = (text: string): string => Buffer.from(text, 'utf8').toString('base64');

describe('分享链接识别', () => {
  it('SS（SIP002：userinfo 为 base64）', () => {
    const link = `ss://${b64('aes-256-gcm:pass-123456')}@1.2.3.4:8388#%E7%BE%8E%E5%9B%BD-%E6%B4%9B%E6%9D%89%E7%9F%B6`;
    const { nodes, errors } = parseNodeList(link);
    assert.equal(errors.length, 0);
    assert.equal(nodes[0]?.server, '1.2.3.4');
    assert.equal(nodes[0]?.port, 8388);
    assert.equal(nodes[0]?.region, '美国');
    assert.deepEqual(nodes[0]?.credential, { kind: 'shadowsocks', method: 'aes-256-gcm', password: 'pass-123456' });
  });

  it('SS（老格式：整段 base64 带 host）', () => {
    const link = `ss://${b64('aes-128-gcm:pass-abcdef@5.6.7.8:9000')}#香港`;
    const { nodes } = parseNodeList(link);
    assert.equal(nodes[0]?.server, '5.6.7.8');
    assert.equal(nodes[0]?.region, '香港');
  });

  it('VMess（base64 JSON，含 ws + tls）', () => {
    const json = {
      v: '2',
      ps: '日本-东京-01',
      add: 'jp.example.com',
      port: '443',
      id: 'uuid-1234',
      aid: '0',
      net: 'ws',
      path: '/ray',
      host: 'jp.example.com',
      tls: 'tls',
      sni: 'jp.example.com',
    };
    const { nodes } = parseNodeList(`vmess://${b64(JSON.stringify(json))}`);
    assert.equal(nodes.length, 1);
    const credential = nodes[0]!.credential;
    assert.equal(credential.kind, 'vmess');
    assert.equal(nodes[0]?.region, '日本');
    if (credential.kind === 'vmess') {
      assert.equal(credential.uuid, 'uuid-1234');
      assert.equal(credential.transport.type, 'ws');
      assert.equal(credential.tls?.serverName, 'jp.example.com');
    }
  });

  it('VLESS（ws + tls + flow）', () => {
    const link =
      'vless://uuid-5678@sg.example.com:443?security=tls&type=ws&path=%2Fws&sni=sg.example.com&flow=xtls-rprx-vision#%E6%96%B0%E5%8A%A0%E5%9D%A1-01';
    const { nodes } = parseNodeList(link);
    const credential = nodes[0]!.credential;
    assert.equal(nodes[0]?.region, '新加坡');
    if (credential.kind === 'vless') {
      assert.equal(credential.uuid, 'uuid-5678');
      assert.equal(credential.flow, 'xtls-rprx-vision');
      assert.equal(credential.transport.path, '/ws');
      assert.equal(credential.tls?.serverName, 'sg.example.com');
    }
  });

  it('VLESS（reality）', () => {
    const link = 'vless://uuid-9@us.example.com:443?security=reality&pbk=pubkey&sid=ab12&sni=www.apple.com#美国-02';
    const credential = parseNodeList(link).nodes[0]!.credential;
    if (credential.kind === 'vless') {
      assert.equal(credential.tls?.reality?.publicKey, 'pubkey');
      assert.equal(credential.tls?.reality?.shortId, 'ab12');
    }
  });

  it('Trojan（sni + ws）', () => {
    const link = 'trojan://pass-abcdef@hk.example.com:443?sni=hk.example.com&type=ws&path=%2Ftj#香港-02';
    const credential = parseNodeList(link).nodes[0]!.credential;
    assert.equal(credential.kind, 'trojan');
    if (credential.kind === 'trojan') {
      assert.equal(credential.password, 'pass-abcdef');
      assert.equal(credential.tls.serverName, 'hk.example.com');
      assert.equal(credential.transport.type, 'ws');
    }
  });

  it('Hysteria2（含 obfs 与 insecure）', () => {
    const link = 'hy2://pass-hy2@1.1.1.1:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=obfspass#日本-03';
    const credential = parseNodeList(link).nodes[0]!.credential;
    assert.equal(credential.kind, 'hysteria2');
    if (credential.kind === 'hysteria2') {
      assert.equal(credential.tls?.allowInsecure, true);
      assert.deepEqual(credential.obfs, { type: 'salamander', password: 'obfspass' });
    }
  });

  it('SOCKS5 与 HTTP 代理', () => {
    const socks = parseNodeList('socks5://user:pw123456@9.9.9.9:1080#代理A').nodes[0]!.credential;
    assert.deepEqual(socks, { kind: 'socks5', username: 'user', password: 'pw123456' });
    const http = parseNodeList('http://user:pw123456@9.9.9.8:8080').nodes[0]!.credential;
    assert.deepEqual(http, { kind: 'http', username: 'user', password: 'pw123456' });
  });
});

describe('识别失败要说清楚原因', () => {
  it('不支持的协议直接报错，不静默跳过', () => {
    const { nodes, errors } = parseNodeList(
      ['ssr://abcdef', 'tuic://x@y:443', 'anytls://z@y:443', 'hysteria://a@b:443'].join('\n'),
    );
    assert.equal(nodes.length, 0);
    assert.equal(errors.length, 4);
    assert.ok(errors[0]!.message.includes('SSR'));
    assert.ok(errors[1]!.message.includes('TUIC'));
  });

  it('缺字段的链接报错，并带上行号与原文', () => {
    const { errors } = parseNodeList(['ss://aes-256-gcm:pass@1.2.3.4:8388#ok', 'vless://@x:443'].join('\n'));
    assert.equal(errors.length, 1);
    assert.equal(errors[0]?.line, 2);
    assert.match(errors[0]!.message, /VLESS/);
  });

  it('不支持的 SS 加密方法要拒绝', () => {
    const { errors } = parseNodeList(`ss://${b64('rc4-md5:pass1234')}@1.2.3.4:8388`);
    assert.match(errors[0]!.message, /不支持的 SS 加密方法/);
  });
});

describe('一百条的批量场景', () => {
  it('一百条互不相同的链接 → 一百条线路，账号 jy001…jy100', () => {
    const lines: string[] = [];
    for (let i = 1; i <= 100; i += 1) {
      const host = `10.0.${Math.floor(i / 250)}.${i % 250}`;
      lines.push(`ss://${b64(`aes-256-gcm:pass-${i}00000`)}@${host}:8388#%E7%BE%8E%E5%9B%BD-${i}`);
    }
    const { nodes, errors } = parseNodeList(lines.join('\n'));
    assert.equal(errors.length, 0);
    assert.equal(nodes.length, 100);
    assert.equal(nodes[99]?.id, 'line-100');
    assert.equal(accountNameFor('jy', 1, nodes.length), 'jy001');
    assert.equal(accountNameFor('jy', 100, nodes.length), 'jy100');
  });

  it('重复节点只留一条：两个账号共用一个出口 IP 是隐患', () => {
    const link = `ss://${b64('aes-256-gcm:pass-123456')}@1.2.3.4:8388#A`;
    const { nodes, duplicates } = parseNodeList([link, link].join('\n'));
    assert.equal(nodes.length, 1);
    assert.equal(duplicates.length, 1);
  });

  it('没有备注名的节点自动编号，不产生重复 id', () => {
    const { nodes } = parseNodeList(
      ['trojan://p1@a.example.com:443?sni=a.example.com', 'trojan://p2@b.example.com:443?sni=b.example.com'].join('\n'),
    );
    assert.deepEqual(
      nodes.map((n) => n.id),
      ['line-001', 'line-002'],
    );
    assert.notEqual(nodes[0]?.name, nodes[1]?.name);
  });
});
