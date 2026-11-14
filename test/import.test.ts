/**
 * 批量导入解析
 *
 * 一百条数据里错一行，如果只是「导入失败」而不说是哪一行，运营只能一行行试。
 * 所以这里守两件事：列顺序不能错位、错误必须带行号。
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseAccountsCsv, parseLinesCsv, poolCapacity } from '../src/control/import.ts';

describe('线路 CSV', () => {
  it('跳过表头与注释，按列顺序解析', () => {
    const csv = [
      'id,name,region,kind,server,port,secret,sni,wsPath',
      '# 这是注释',
      'line-us-01,美国-洛杉矶,US,shadowsocks,1.2.3.4,8388,pass-123456,,',
      '',
      'line-hk-01,香港,HK,trojan,hk.example.com,443,pass-abcdef,hk.example.com,',
    ].join('\n');
    const { rows, errors } = parseLinesCsv(csv);
    assert.equal(errors.length, 0);
    assert.equal(rows.length, 2);
    assert.deepEqual(rows[0]?.credential, { kind: 'shadowsocks', method: 'aes-256-gcm', password: 'pass-123456' });
    assert.equal(rows[1]?.kind, 'trojan');
    assert.equal(rows[1]?.port, 443);
  });

  it('制表符分隔也认（从表格软件复制粘贴常见）', () => {
    const { rows } = parseLinesCsv('line-jp-1\t日本\tJP\tsocks5\tjp.example.com\t1080\tpass-123456\t\t');
    assert.equal(rows[0]?.id, 'line-jp-1');
    assert.equal(rows[0]?.region, 'JP');
  });

  it('错误带行号，且不因为一行坏掉就整批失败', () => {
    const csv = [
      'line-a,线路A,US,shadowsocks,1.1.1.1,8388,pass-123456,,',
      'line-b,线路B,US,不存在的协议,1.1.1.2,8388,pass-123456,,',
      'line-c,线路C,US,trojan,1.1.1.3,70000,pass-123456,sni.example.com,',
      'line-d,线路D,US,shadowsocks,1.1.1.4,8388,,,',
    ].join('\n');
    const { rows, errors } = parseLinesCsv(csv);
    assert.equal(rows.length, 1);
    assert.deepEqual(errors.map((e) => e.line), [2, 3, 4]);
    assert.match(errors[0]!.message, /不支持的协议/);
    assert.match(errors[1]!.message, /端口不合法/);
    assert.match(errors[2]!.message, /需要密码/);
  });

  it('Trojan 缺 SNI 直接拒绝：没有 TLS 的 trojan 连不上', () => {
    const { errors } = parseLinesCsv('line-x,线路X,US,trojan,t.example.com,443,pass-123456,,');
    assert.equal(errors.length, 1);
    assert.match(errors[0]!.message, /SNI/);
  });
});

describe('账号 CSV', () => {
  it('解析到期日，统一成当天 23:59:59', () => {
    const { rows, errors } = parseAccountsCsv('u001,pass-123456,客户001,line-us-01,2026/12/31');
    assert.equal(errors.length, 0);
    assert.equal(rows[0]?.expiresAt, new Date(Date.parse('2026-12-31T23:59:59.000Z')).toISOString());
  });

  it('文件内重复账号只保留第一条，并指出行号', () => {
    const csv = ['u001,pass-123456,A,line-a,', 'u001,pass-654321,B,line-b,'].join('\n');
    const { rows, errors } = parseAccountsCsv(csv);
    assert.equal(rows.length, 1);
    assert.equal(errors[0]?.line, 2);
    assert.match(errors[0]!.message, /重复/);
  });

  it('密码不足 8 位、缺线路都拒绝', () => {
    const { errors } = parseAccountsCsv(['u001,123,A,line-a,', 'u002,pass-123456,B,,', 'u3,pass-123456,C,line-a,'].join('\n'));
    assert.equal(errors.length, 3);
    assert.ok(errors.some((e) => /密码至少 8 位/.test(e.message)));
    assert.ok(errors.some((e) => /缺少必填列/.test(e.message)));
    assert.ok(errors.some((e) => /账号至少 3 位/.test(e.message)));
  });
});

describe('地址池容量', () => {
  it('一百台手机需要至少 100 个地址，默认池要留余量', () => {
    assert.equal(poolCapacity('192.168.10.50', '192.168.10.250'), 201);
    assert.equal(poolCapacity('192.168.10.100', '192.168.10.200'), 101);
    assert.equal(poolCapacity('192.168.10.200', '192.168.10.100'), 0);
  });
});
