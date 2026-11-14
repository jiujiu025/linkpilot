/**
 * 规范化 JSON 与摘要
 *
 * 签名和摘要必须建立在确定性字节序列上，否则同一份配置在不同进程里
 * 会算出不同摘要，导致「签名不通过」这种最难排查的故障。
 */
import { sha256Hex } from './crypto.ts';

export function canonicalize(value: unknown): string {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item === undefined ? null : item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
  }
  throw new Error(`canonicalize: 不支持的类型 ${typeof value}`);
}

export function digestOf(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

export function shortDigest(value: unknown, len = 12): string {
  return digestOf(value).slice(0, len);
}
