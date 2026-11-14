/**
 * 线路测速
 *
 * 用本机临时端口做真实握手，避免「测速本身写错了」这件事只能靠真机发现。
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { after, describe, it } from 'node:test';
import { probeLine, probeMany, probeTargetOf } from '../src/control/probe.ts';

const servers: net.Server[] = [];

function listen(): Promise<number> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => socket.end());
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      servers.push(server);
      resolve(typeof address === 'object' && address ? address.port : 0);
    });
  });
}

after(() => {
  for (const server of servers) server.close();
});

describe('单条线路探测', () => {
  it('端口活着：返回握手耗时', async () => {
    const port = await listen();
    const outcome = await probeLine({ server: '127.0.0.1', port, tlsServerName: null, allowInsecure: false }, 2000);
    assert.equal(outcome.ok, true);
    assert.equal(outcome.kind, 'tcp');
    assert.ok((outcome.rttMs ?? -1) >= 0);
    assert.equal(outcome.error, null);
  });

  it('端口关闭：判失败并给出人话原因', async () => {
    const outcome = await probeLine({ server: '127.0.0.1', port: 1, tlsServerName: null, allowInsecure: false }, 1500);
    assert.equal(outcome.ok, false);
    assert.match(String(outcome.error), /拒绝连接|不可达|超时/);
  });

  it('域名不存在：不抛异常，按失败返回', async () => {
    const outcome = await probeLine(
      { server: 'no-such-host.invalid', port: 443, tlsServerName: null, allowInsecure: false },
      2000,
    );
    assert.equal(outcome.ok, false);
    assert.ok(outcome.error && outcome.error.length > 0);
  });

  it('声明了 TLS 但对面不是 TLS：握手失败而不是误判可达', async () => {
    const port = await listen();
    const outcome = await probeLine({ server: '127.0.0.1', port, tlsServerName: 'example.com', allowInsecure: false }, 2000);
    assert.equal(outcome.ok, false);
    assert.equal(outcome.kind, 'tls');
  });
});

describe('从凭证推导探测方式', () => {
  it('Trojan 一定走 TLS，用凭证里的 SNI', () => {
    const target = probeTargetOf(
      {
        kind: 'trojan',
        password: 'p',
        tls: { serverName: 'hk.example.com', alpn: [], allowInsecure: true },
        transport: { type: 'tcp' },
      },
      { server: '1.2.3.4', port: 443 },
    );
    assert.equal(target.tlsServerName, 'hk.example.com');
    assert.equal(target.allowInsecure, true);
  });

  it('没有 TLS 的 VLESS 只做 TCP 握手', () => {
    const target = probeTargetOf(
      { kind: 'vless', uuid: 'u', flow: '', tls: null, transport: { type: 'tcp' } },
      { server: '1.2.3.4', port: 80 },
    );
    assert.equal(target.tlsServerName, null);
  });

  it('SHADOWSOCKS 没有 TLS 字段，保持 TCP', () => {
    const target = probeTargetOf(
      { kind: 'shadowsocks', method: 'aes-256-gcm', password: 'p' },
      { server: '1.2.3.4', port: 8388 },
    );
    assert.equal(target.tlsServerName, null);
  });

  it('凭证缺失时不报错，退化成纯 TCP 探测', () => {
    const target = probeTargetOf(null, { server: '1.2.3.4', port: 443 });
    assert.deepEqual(target, { server: '1.2.3.4', port: 443, tlsServerName: null, allowInsecure: false });
  });
});

describe('批量探测', () => {
  it('结果顺序与输入一致，且一条失败不影响其余', async () => {
    const goodPort = await listen();
    const items = [
      { name: 'good', port: goodPort },
      { name: 'bad', port: 1 },
      { name: 'good2', port: goodPort },
    ];
    const results = await probeMany(items, (item) =>
      probeLine({ server: '127.0.0.1', port: item.port, tlsServerName: null, allowInsecure: false }, 1500), 2);
    assert.deepEqual(
      results.map((r) => r.item.name),
      ['good', 'bad', 'good2'],
    );
    assert.equal(results[0]?.outcome.ok, true);
    assert.equal(results[1]?.outcome.ok, false);
  });
});
