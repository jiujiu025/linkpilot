/**
 * 统一错误模型
 *
 * 对外只暴露稳定的错误码与可读信息；内部原因（哪一行签名失败、哪个字段越界）
 * 只进日志，不进响应。避免把「凭证解析失败 = 你有这条线路」这类信息泄露出去。
 */
export type ErrorCode =
  | 'BAD_REQUEST'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'RATE_LIMITED'
  | 'SIGNATURE_INVALID'
  | 'REPLAY_DETECTED'
  | 'EXPIRED'
  | 'REVISION_REJECTED'
  | 'CAPABILITY_UNSUPPORTED'
  | 'COMPILE_FAILED'
  | 'APPLY_FAILED'
  | 'INTERNAL';

const STATUS: Record<ErrorCode, number> = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  RATE_LIMITED: 429,
  SIGNATURE_INVALID: 401,
  REPLAY_DETECTED: 409,
  EXPIRED: 410,
  REVISION_REJECTED: 409,
  CAPABILITY_UNSUPPORTED: 422,
  COMPILE_FAILED: 422,
  APPLY_FAILED: 500,
  INTERNAL: 500,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = STATUS[code];
    this.details = details;
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

export function errorBody(error: unknown): { ok: false; error: { code: string; message: string } } {
  if (isAppError(error)) {
    return { ok: false, error: { code: error.code, message: error.message } };
  }
  return { ok: false, error: { code: 'INTERNAL', message: '服务内部错误' } };
}
