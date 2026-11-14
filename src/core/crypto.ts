/**
 * LinkPilot 密码学原语
 *
 * 只依赖 node:crypto，故意不引第三方加密库：
 * 设备侧要跑在 256MB 内存的 OpenWrt 上，依赖越少越好。
 *
 * 用到的三类密钥：
 * - Ed25519：设备身份签名、云端 bundle/命令签名、Agent 请求签名
 * - X25519：云端 → 设备的凭证封装（ECDH + HKDF + AES-256-GCM）
 * - scrypt：门户账号口令哈希（不保存明文）
 */
import crypto from 'node:crypto';

export type KeyPairB64 = { publicKey: string; privateKey: string };

const ed25519 = (): crypto.KeyPairKeyObjectResult => crypto.generateKeyPairSync('ed25519');
const x25519 = (): crypto.KeyPairKeyObjectResult => crypto.generateKeyPairSync('x25519');

function exportPublic(key: crypto.KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64');
}

function exportPrivate(key: crypto.KeyObject): string {
  return key.export({ type: 'pkcs8', format: 'der' }).toString('base64');
}

export function generateEd25519KeyPair(): KeyPairB64 {
  const { publicKey, privateKey } = ed25519();
  return { publicKey: exportPublic(publicKey), privateKey: exportPrivate(privateKey) };
}

export function generateX25519KeyPair(): KeyPairB64 {
  const { publicKey, privateKey } = x25519();
  return { publicKey: exportPublic(publicKey), privateKey: exportPrivate(privateKey) };
}

function loadPublic(b64: string): crypto.KeyObject {
  return crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), type: 'spki', format: 'der' });
}

function loadPrivate(b64: string): crypto.KeyObject {
  return crypto.createPrivateKey({ key: Buffer.from(b64, 'base64'), type: 'pkcs8', format: 'der' });
}

export function signEd25519(data: Buffer | string, privateKeyB64: string): string {
  const msg = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const sig = crypto.sign(null, msg, loadPrivate(privateKeyB64));
  return sig.toString('base64');
}

export function verifyEd25519(
  data: Buffer | string,
  signatureB64: string,
  publicKeyB64: string,
): boolean {
  try {
    const msg = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return crypto.verify(null, msg, loadPublic(publicKeyB64), Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

export function sha256Hex(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * MAC 摘要：云端与设备侧必须用同一套算法，否则「预授权设备」永远匹配不上。
 * 带上固定前缀做域分离，避免同一个哈希值被复用到别的用途上。
 */
export function hashMacAddress(mac: string): string {
  return `sha256:${crypto.createHash('sha256').update(`linkpilot:mac:v1:${mac.trim().toLowerCase()}`).digest('hex')}`;
}

function hkdf(ikm: Buffer, salt: Buffer, info: string, length = 32): Buffer {
  const out = crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), length);
  return Buffer.from(out);
}

export function aesGcmEncrypt(
  key: Buffer,
  plaintext: Buffer | string,
  aad: string,
): { nonce: string; ciphertext: string } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const body = Buffer.concat([
    cipher.update(typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    nonce: nonce.toString('base64'),
    ciphertext: Buffer.concat([body, tag]).toString('base64'),
  };
}

export function aesGcmDecrypt(
  key: Buffer,
  nonceB64: string,
  ciphertextB64: string,
  aad?: string,
): Buffer {
  const raw = Buffer.from(ciphertextB64, 'base64');
  const tag = raw.subarray(raw.length - 16);
  const body = raw.subarray(0, raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(nonceB64, 'base64'));
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/** 用一次性 X25519 密钥与设备公钥做 ECDH，导出 32 字节封装密钥 */
export function deriveEnvelopeKey(
  ephemeralPrivate: string,
  peerPublic: string,
  context: string,
): Buffer {
  const shared = crypto.diffieHellman({
    privateKey: loadPrivate(ephemeralPrivate),
    publicKey: loadPublic(peerPublic),
  });
  return hkdf(shared, Buffer.from(context, 'utf8'), 'linkpilot/secrets/v1', 32);
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function randomHex(bytes = 16): string {
  return crypto.randomBytes(bytes).toString('hex');
}

/** 口令哈希：scrypt$N$r$p$salt$hash（base64） */
export function hashPassword(password: string, cost = 16384): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, { N: cost, r: 8, p: 1 });
  return ['scrypt', cost, 8, 1, salt.toString('base64'), hash.toString('base64')].join('$');
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4] ?? '', 'base64');
  const expected = Buffer.from(parts[5] ?? '', 'base64');
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;
  let actual: Buffer;
  try {
    actual = crypto.scryptSync(password, salt, expected.length, { N, r, p });
  } catch {
    return false;
  }
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

/** 恒定时间比较字符串，避免签名/令牌比较被计时侧信道利用 */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * 重放防护：内存 Nonce 窗口。
 * 云端单实例足够；多实例时需要换成 Redis SETNX（Phase 4 事项）。
 */
export class ReplayGuard {
  private readonly seen = new Map<string, number>();
  private readonly windowMs: number;

  constructor(windowMs = 5 * 60 * 1000) {
    this.windowMs = windowMs;
  }

  /** 返回 false 表示该 nonce 在窗口内已被使用过 */
  use(key: string, now = Date.now()): boolean {
    this.gc(now);
    if (this.seen.has(key)) return false;
    this.seen.set(key, now + this.windowMs);
    return true;
  }

  private gc(now: number): void {
    for (const [key, expiry] of this.seen) {
      if (expiry <= now) this.seen.delete(key);
    }
  }
}

/** 时间窗口校验，容忍一定时钟漂移 */
export function withinSkew(isoOrMs: string | number, skewMs = 5 * 60 * 1000, now = Date.now()): boolean {
  const ts = typeof isoOrMs === 'number' ? isoOrMs : Date.parse(isoOrMs);
  if (!Number.isFinite(ts)) return false;
  return Math.abs(now - ts) <= skewMs;
}
