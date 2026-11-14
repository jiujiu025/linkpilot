/**
 * 凭证封装：云端 → 设备
 *
 * 设计目标（docs/design/04 §5「配置安全」）：
 * - 云端不把线路明文凭证写进配置包正文，正文只有业务模型；
 * - 每条 bundle 用一次性 X25519 密钥对设备公钥做 ECDH，HKDF 派生封装密钥；
 * - AAD 绑定 deviceId + revision，防止把 A 设备的秘密挪到 B 设备或旧版本重放；
 * - 设备只有自己的私钥能解开，云端数据库泄露不等于线路凭证泄露。
 */
import { aesGcmDecrypt, aesGcmEncrypt, deriveEnvelopeKey, generateX25519KeyPair } from './crypto.ts';
import { SecretPayload, SealedSecrets, type LineCredential } from './schema.ts';
import { z } from 'zod';

export type SecretsToSeal = z.infer<typeof SecretPayload>;

function aadFor(deviceId: string, revision: number): string {
  return `linkpilot:secrets:${deviceId}:${revision}`;
}

export function sealSecrets(
  deviceX25519PublicKey: string,
  deviceId: string,
  revision: number,
  secrets: SecretsToSeal,
  keyVersion = 1,
): SealedSecrets {
  const ephemeral = generateX25519KeyPair();
  const key = deriveEnvelopeKey(ephemeral.privateKey, deviceX25519PublicKey, deviceId);
  const payload = JSON.stringify(secrets);
  const { nonce, ciphertext } = aesGcmEncrypt(key, payload, aadFor(deviceId, revision));
  return {
    keyVersion,
    ephemeralPublicKey: ephemeral.publicKey,
    nonce,
    ciphertext,
  };
}

export function openSecrets(
  deviceX25519PrivateKey: string,
  deviceId: string,
  revision: number,
  sealed: SealedSecrets,
): SecretsToSeal {
  const key = deriveEnvelopeKey(deviceX25519PrivateKey, sealed.ephemeralPublicKey, deviceId);
  const plaintext = aesGcmDecrypt(key, sealed.nonce, sealed.ciphertext, aadFor(deviceId, revision)).toString('utf8');
  return SecretPayload.parse(JSON.parse(plaintext));
}

/** 校验「线路 kind」与「凭证 kind」一致，属于能力矩阵检查的一部分 */
export function credentialMatchesLineKind(
  lineKind: LineCredential['kind'],
  credential: LineCredential,
): boolean {
  return lineKind === credential.kind;
}
