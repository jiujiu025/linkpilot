/**
 * 控制面安全边界测试
 *
 * 这些用例覆盖的是「一旦失效就会静默泄露」的路径：
 * 重放、错投、篡改、越权、令牌复用。它们比功能测试重要得多。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createControlPlane, type ControlPlane } from '../src/control/server.ts';
import { seedDemo } from '../src/control/seed.ts';
import { generateEd25519KeyPair, generateX25519KeyPair, randomHex } from '../src/core/crypto.ts';
import { signAgentRequest, verifyBundle, verifyCommandSignature } from '../src/core/bundle-envelope.ts';
import { ConfigBundle } from '../src/core/schema.ts';

const ADMIN_TOKEN = 'test-admin-token';
let plane: ControlPlane;
let baseUrl = '';
let dataDir = '';
let token = '';
let identity: { ed25519: { publicKey: string; privateKey: string }; x25519: { publicKey: string; privateKey: string } };
let deviceId = '';

function signedHeaders(method: string, path: string, body: string, privateKey: string, id: string, nonce = randomHex(8)) {
  const timestamp = new Date().toISOString();
  return {
    'content-type': 'application/json',
    'x-lp-device': id,
    'x-lp-timestamp': timestamp,
    'x-lp-nonce': nonce,
    'x-lp-signature': signAgentRequest(method, path, timestamp, nonce, body, privateKey),
  };
}

async function agentPost<T>(pathName: string, body: unknown, privateKey = identity.ed25519.privateKey, id = deviceId): Promise<{ status: number; body: T }> {
  const payload = JSON.stringify(body);
  const res = await fetch(`${baseUrl}${pathName}`, {
    method: 'POST',
    headers: signedHeaders('POST', pathName, payload, privateKey, id),
    body: payload,
  });
  return { status: res.status, body: (await res.json()) as T };
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'linkpilot-test-'));
  plane = createControlPlane({ dataDir, port: 0, adminToken: ADMIN_TOKEN });
  // listen 是异步的：不等 listening 事件，address() 会返回 null，测试会以「fetch failed」的形式失败
  if (!plane.server.listening) {
    await new Promise<void>((resolve) => plane.server.once('listening', () => resolve()));
  }
  const address = plane.server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
  const seeded = seedDemo(plane.store, plane.keys, { deviceId: 'dev-test-001' });
  token = seeded.enrollmentToken;
  deviceId = seeded.deviceId;
  identity = { ed25519: generateEd25519KeyPair(), x25519: generateX25519KeyPair() };
});

after(() => {
  plane.server.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

describe('设备注册', () => {
  it('错误令牌被拒绝', async () => {
    const res = await fetch(`${baseUrl}/agent/enrollment`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: 'not-a-real-token',
        deviceModel: 'AX3000T',
        agentVersion: '0.1.0',
        hardwareFingerprint: 'test',
        ed25519PublicKey: identity.ed25519.publicKey,
        x25519PublicKey: identity.x25519.publicKey,
      }),
    });
    assert.equal(res.status, 401);
  });

  it('合法令牌可以激活，且令牌只能使用一次', async () => {
    const body = {
      token,
      deviceModel: 'Xiaomi AX3000T',
      agentVersion: '0.1.0',
      hardwareFingerprint: 'test-fingerprint',
      ed25519PublicKey: identity.ed25519.publicKey,
      x25519PublicKey: identity.x25519.publicKey,
    };
    const first = await fetch(`${baseUrl}/agent/enrollment`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    assert.equal(first.status, 200);
    const second = await fetch(`${baseUrl}/agent/enrollment`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    assert.equal(second.status, 409, '令牌复用必须被拒绝');
  });
});

describe('设备请求鉴权', () => {
  it('没有签名头直接拒绝', async () => {
    const res = await fetch(`${baseUrl}/agent/heartbeat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 401);
  });

  it('伪造签名的请求被拒绝', async () => {
    const attacker = generateEd25519KeyPair();
    const { status } = await agentPost('/agent/heartbeat', minimalHeartbeat(), attacker.privateKey);
    assert.equal(status, 401);
  });

  it('同一个 nonce 重放被拒绝', async () => {
    const payload = JSON.stringify(minimalHeartbeat());
    const nonce = randomHex(8);
    const headers = signedHeaders('POST', '/agent/heartbeat', payload, identity.ed25519.privateKey, deviceId, nonce);
    const first = await fetch(`${baseUrl}/agent/heartbeat`, { method: 'POST', headers, body: payload });
    assert.equal(first.status, 200);
    const second = await fetch(`${baseUrl}/agent/heartbeat`, { method: 'POST', headers, body: payload });
    assert.equal(second.status, 409);
  });

  it('篡改请求体导致签名失效', async () => {
    const payload = JSON.stringify(minimalHeartbeat());
    const headers = signedHeaders('POST', '/agent/heartbeat', payload, identity.ed25519.privateKey, deviceId);
    const tampered = JSON.stringify({ ...minimalHeartbeat(), observedRevision: 999 });
    const res = await fetch(`${baseUrl}/agent/heartbeat`, { method: 'POST', headers, body: tampered });
    assert.equal(res.status, 401);
  });
});

describe('配置包签名与版本', () => {
  it('正常配置包可以通过校验', async () => {
    const { status, body } = await agentPost<{ upToDate: boolean; bundle: unknown }>('/agent/desired-state/pull', {
      currentRevision: 0,
    });
    assert.equal(status, 200);
    const bundle = ConfigBundle.parse(body.bundle);
    const verdict = verifyBundle(bundle, {
      deviceId,
      cloudPublicKey: plane.keys.signing.publicKey,
      currentRevision: 0,
    });
    assert.deepEqual(verdict, { ok: true });
  });

  it('篡改正文内容会被摘要拦下', async () => {
    const { body } = await agentPost<{ bundle: unknown }>('/agent/desired-state/pull', { currentRevision: 0 });
    const bundle = ConfigBundle.parse(body.bundle);
    bundle.payload.clients[0]!.ipAddress = '192.168.10.99';
    const verdict = verifyBundle(bundle, {
      deviceId,
      cloudPublicKey: plane.keys.signing.publicKey,
      currentRevision: 0,
    });
    assert.equal(verdict.ok, false);
    assert.equal((verdict as { code: string }).code, 'DIGEST_MISMATCH');
  });

  it('换一张设备公钥伪造签名会被拒绝', async () => {
    const { body } = await agentPost<{ bundle: unknown }>('/agent/desired-state/pull', { currentRevision: 0 });
    const bundle = ConfigBundle.parse(body.bundle);
    const attacker = generateEd25519KeyPair();
    const verdict = verifyBundle(bundle, {
      deviceId,
      cloudPublicKey: attacker.publicKey,
      currentRevision: 0,
    });
    assert.equal(verdict.ok, false);
    assert.equal((verdict as { code: string }).code, 'SIGNATURE_INVALID');
  });

  it('过期配置包被拒绝', async () => {
    const { body } = await agentPost<{ bundle: unknown }>('/agent/desired-state/pull', { currentRevision: 0 });
    const bundle = ConfigBundle.parse(body.bundle);
    const verdict = verifyBundle(bundle, {
      deviceId,
      cloudPublicKey: plane.keys.signing.publicKey,
      currentRevision: 0,
      now: Date.parse(bundle.expiresAt) + 10 * 60 * 1000,
    });
    assert.equal(verdict.ok, false);
    assert.equal((verdict as { code: string }).code, 'EXPIRED');
  });

  it('版本不递增时按重放处理', async () => {
    const { body } = await agentPost<{ bundle: unknown }>('/agent/desired-state/pull', { currentRevision: 0 });
    const bundle = ConfigBundle.parse(body.bundle);
    const verdict = verifyBundle(bundle, {
      deviceId,
      cloudPublicKey: plane.keys.signing.publicKey,
      currentRevision: bundle.revision,
    });
    assert.equal(verdict.ok, false);
    assert.equal((verdict as { code: string }).code, 'REVISION_REJECTED');
  });

  it('配置包里不含明文凭证', async () => {
    const { body } = await agentPost<{ bundle: unknown }>('/agent/desired-state/pull', { currentRevision: 0 });
    const text = JSON.stringify(body);
    assert.equal(text.includes('Ss-US-4mN8vB2x'), false, 'SS 口令不能出现在下发的 bundle 中');
    assert.equal(text.includes('Tj-SG-7xK2pQ9m'), false, 'Trojan 口令不能出现在下发的 bundle 中');
    assert.ok(text.includes('ciphertext'), '凭证必须以密文形式随包下发');
  });
});

describe('命令与权限', () => {
  it('管理接口需要令牌', async () => {
    const res = await fetch(`${baseUrl}/api/admin/overview`);
    assert.equal(res.status, 401);
  });

  it('签发的命令带签名且设备可验证', async () => {
    const command = plane.issueCommand({
      deviceId,
      type: 'RESTART_PROXY',
      params: {},
      actor: 'test',
      reason: '单元测试',
    });
    const verdict = verifyCommandSignature(command, {
      deviceId,
      cloudPublicKey: plane.keys.signing.publicKey,
    });
    assert.deepEqual(verdict, { ok: true });

    const tampered = { ...command, type: 'ENTER_MAINTENANCE' as const, params: { enabled: true } };
    const bad = verifyCommandSignature(tampered, { deviceId, cloudPublicKey: plane.keys.signing.publicKey });
    assert.equal(bad.ok, false);
  });

  it('非白名单命令被拒绝', async () => {
    const res = await fetch(`${baseUrl}/api/admin/routers/${deviceId}/commands`, {
      method: 'POST',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'EXEC_SHELL', params: { cmd: 'id' }, reason: '越权测试' }),
    });
    assert.equal(res.status, 400);
  });

  it('高风险操作缺少原因时拒绝下发', () => {
    assert.throws(() =>
      plane.issueCommand({ deviceId, type: 'RESTART_NETWORK', params: {}, actor: 'test', reason: '   ' }),
    );
  });

  it('设备不能确认他人的命令', async () => {
    const command = plane.issueCommand({
      deviceId,
      type: 'RESTART_PROXY',
      params: {},
      actor: 'test',
      reason: '越权测试',
    });
    const other = generateEd25519KeyPair();
    const res = await agentPost(
      '/agent/commands/ack',
      { commandId: command.id, status: 'SUCCEEDED', code: 'OK', message: '', observedRevision: 0 },
      other.privateKey,
    );
    assert.equal(res.status, 401, '签名不匹配应在鉴权阶段被拒绝');
  });
});

function minimalHeartbeat() {
  return {
    agentVersion: '0.1.0',
    uptimeSeconds: 10,
    observedRevision: 0,
    health: 'healthy',
    resources: {
      cpuLoad1: 0.1,
      memoryUsedMb: 100,
      memoryTotalMb: 256,
      temperatureC: 45,
      diskFreeMb: 40,
    },
    proxyRunning: false,
    lastApplyResult: '',
  };
}
