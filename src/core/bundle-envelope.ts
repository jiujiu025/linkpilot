/**
 * 配置包的信封、签名与校验（云端与设备侧共用同一份实现）
 *
 * 共用是刻意的：签名/校验逻辑一旦各写一份，就会出现「云端认为签了、设备认为没签」
 * 这类只在真机才暴露的问题。
 */
import { canonicalize, digestOf } from './canonical.ts';
import { sha256Hex, signEd25519, verifyEd25519 } from './crypto.ts';
import type {
  BundleSigningEnvelope,
  ConfigBundle,
  DeviceCommand,
  SealedSecrets,
} from './schema.ts';

export function computeBundleDigest(payload: unknown, secrets: SealedSecrets): string {
  return digestOf({ payload, secrets });
}

export function bundleEnvelope(bundle: Omit<ConfigBundle, 'signature'>): BundleSigningEnvelope {
  return {
    deviceId: bundle.deviceId,
    revision: bundle.revision,
    revisionId: bundle.revisionId,
    generatedAt: bundle.generatedAt,
    expiresAt: bundle.expiresAt,
    digest: bundle.digest,
  };
}

export function signaturePayload(envelope: BundleSigningEnvelope): string {
  return `linkpilot:bundle:v1\n${canonicalize(envelope)}`;
}

/** 云端签发：对信封签名，信封本身覆盖摘要，摘要覆盖正文与密文 */
export function signBundle(bundle: Omit<ConfigBundle, 'signature'>, privateKey: string): ConfigBundle {
  const payload = signaturePayload(bundleEnvelope(bundle));
  return { ...bundle, signature: signEd25519(payload, privateKey) };
}

export type BundleVerifyFailure =
  | { ok: false; code: 'SIGNATURE_INVALID'; detail: string }
  | { ok: false; code: 'DEVICE_MISMATCH'; detail: string }
  | { ok: false; code: 'EXPIRED'; detail: string }
  | { ok: false; code: 'REVISION_REJECTED'; detail: string }
  | { ok: false; code: 'DIGEST_MISMATCH'; detail: string };

export type BundleVerifyResult = { ok: true } | BundleVerifyFailure;

export type BundleVerifyOptions = {
  deviceId: string;
  cloudPublicKey: string;
  /** 已应用的最新版本；小于等于它的下发视为重放/降级 */
  currentRevision: number;
  now?: number;
  clockSkewMs?: number;
};

export function verifyBundle(bundle: ConfigBundle, options: BundleVerifyOptions): BundleVerifyResult {
  const now = options.now ?? Date.now();
  const skew = options.clockSkewMs ?? 5 * 60 * 1000;

  if (bundle.deviceId !== options.deviceId) {
    return { ok: false, code: 'DEVICE_MISMATCH', detail: '配置包不属于本设备' };
  }
  if (bundle.payload.deviceId !== bundle.deviceId) {
    return { ok: false, code: 'DEVICE_MISMATCH', detail: '正文设备标识与信封不一致' };
  }

  const expiresAt = Date.parse(bundle.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt + skew < now) {
    return { ok: false, code: 'EXPIRED', detail: '配置包已过期' };
  }

  const expectedDigest = computeBundleDigest(bundle.payload, bundle.secrets);
  if (expectedDigest !== bundle.digest) {
    return { ok: false, code: 'DIGEST_MISMATCH', detail: '摘要与内容不一致' };
  }

  const signed = verifyEd25519(
    signaturePayload(bundleEnvelope(bundle)),
    bundle.signature,
    options.cloudPublicKey,
  );
  if (!signed) {
    return { ok: false, code: 'SIGNATURE_INVALID', detail: '签名校验失败' };
  }

  // 签名通过后再判断版本关系，避免用未授权内容探测版本窗口
  if (bundle.revision <= options.currentRevision) {
    return {
      ok: false,
      code: 'REVISION_REJECTED',
      detail: `版本 ${bundle.revision} 不高于当前 ${options.currentRevision}，按重放处理`,
    };
  }

  return { ok: true };
}

/* ------------------------------------------------------------ 固定命令签名 */

export function commandSignaturePayload(
  command: Pick<DeviceCommand, 'id' | 'deviceId' | 'type' | 'params' | 'expiresAt' | 'nonce'>,
): string {
  return `linkpilot:command:v1\n${canonicalize({
    id: command.id,
    deviceId: command.deviceId,
    type: command.type,
    params: command.params,
    expiresAt: command.expiresAt,
    nonce: command.nonce,
  })}`;
}

export function signCommand(
  command: Omit<DeviceCommand, 'signature'>,
  privateKey: string,
): string {
  return signEd25519(commandSignaturePayload(command), privateKey);
}

export type CommandVerifyOptions = {
  deviceId: string;
  cloudPublicKey: string;
  now?: number;
  clockSkewMs?: number;
};

export function verifyCommandSignature(
  command: DeviceCommand,
  options: CommandVerifyOptions,
): { ok: true } | { ok: false; code: string; detail: string } {
  const now = options.now ?? Date.now();
  const skew = options.clockSkewMs ?? 60 * 1000;

  if (command.deviceId !== options.deviceId) {
    return { ok: false, code: 'DEVICE_MISMATCH', detail: '命令目标设备不匹配' };
  }
  const expiresAt = Date.parse(command.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt + skew < now) {
    return { ok: false, code: 'EXPIRED', detail: '命令已过期' };
  }
  const recomputed = commandSignaturePayload(command);
  if (!verifyEd25519(recomputed, command.signature, options.cloudPublicKey)) {
    return { ok: false, code: 'SIGNATURE_INVALID', detail: '命令签名校验失败' };
  }
  return { ok: true };
}

/* --------------------------------------------------------- Agent 请求签名 */

export function agentRequestPayload(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): string {
  return `linkpilot:agent-req:v1\n${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${sha256Hex(body)}`;
}

export function signAgentRequest(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
  privateKey: string,
): string {
  return signEd25519(agentRequestPayload(method, path, timestamp, nonce, body), privateKey);
}

export function verifyAgentRequest(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
  signature: string,
  publicKey: string,
): boolean {
  return verifyEd25519(agentRequestPayload(method, path, timestamp, nonce, body), signature, publicKey);
}
