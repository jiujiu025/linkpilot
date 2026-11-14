/**
 * 云端密钥管理（本地文件版）
 *
 * 生产环境这三样东西应该在 KMS/HSM 里：签名私钥、master key、设备公钥信任根。
 * 这里用文件实现，但接口按「密钥版本 + 轮换」设计，替换 KMS 时不需要改业务代码。
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { KeyPairB64 } from '../core/crypto.ts';
import { aesGcmDecrypt, aesGcmEncrypt, generateEd25519KeyPair } from '../core/crypto.ts';

export type CloudKeys = {
  signing: KeyPairB64;
  masterKey: Buffer;
};

export function loadCloudKeys(dataDir: string): CloudKeys {
  fs.mkdirSync(dataDir, { recursive: true });
  const signingFile = path.join(dataDir, 'cloud-signing.json');
  const masterFile = path.join(dataDir, 'master.key');

  let signing: KeyPairB64;
  if (fs.existsSync(signingFile)) {
    signing = JSON.parse(fs.readFileSync(signingFile, 'utf8')) as KeyPairB64;
  } else {
    signing = generateEd25519KeyPair();
    fs.writeFileSync(signingFile, JSON.stringify(signing, null, 2), { mode: 0o600 });
  }

  let masterKey: Buffer;
  if (fs.existsSync(masterFile)) {
    masterKey = Buffer.from(fs.readFileSync(masterFile, 'utf8').trim(), 'base64');
  } else {
    masterKey = crypto.randomBytes(32);
    fs.writeFileSync(masterFile, masterKey.toString('base64'), { mode: 0o600 });
  }

  return { signing, masterKey };
}

/** 用 master key 加密任意 JSON（线路凭证、无线口令） */
export function sealWithMaster(
  masterKey: Buffer,
  payload: unknown,
  aad: string,
): { nonce: string; ciphertext: string } {
  return aesGcmEncrypt(masterKey, JSON.stringify(payload), `linkpilot:master:${aad}`);
}

export function openWithMaster<T>(
  masterKey: Buffer,
  nonce: string,
  ciphertext: string,
  aad: string,
): T {
  const plaintext = aesGcmDecrypt(masterKey, nonce, ciphertext, `linkpilot:master:${aad}`).toString('utf8');
  return JSON.parse(plaintext) as T;
}
