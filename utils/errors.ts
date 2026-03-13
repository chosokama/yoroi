// ─── Error Codes ─────────────────────────────────────────────────────────────

export const ErrorCodes = {
  UNAUTHORIZED: "UNAUTHORIZED",
  RATE_LIMITED: "RATE_LIMITED",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  INVALID_JSON: "INVALID_JSON",
  INTERNAL_ERROR: "INTERNAL_ERROR",
  NOT_FOUND: "NOT_FOUND",
  POLICY_DENIED: "POLICY_DENIED",
  TOOL_NOT_FOUND: "TOOL_NOT_FOUND",
  DB_ERROR: "DB_ERROR",
  REDIS_ERROR: "REDIS_ERROR",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

// ─── YOROI Error Class ────────────────────────────────────────────────────────

export class YoroiError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: unknown;

  constructor(
    message: string,
    code: ErrorCode,
    statusCode = 500,
    details?: unknown
  ) {
    super(message);
    this.name = "YoroiError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }

  toJSON() {
    return {
      error: this.message,
      code: this.code,
      ...(this.details !== undefined ? { details: this.details } : {}),
    };
  }
}

/** @deprecated Use YoroiError */
export const AgentWallError = YoroiError;

// ─── Factory Helpers ──────────────────────────────────────────────────────────

export const Errors = {
  unauthorized: (msg = "Unauthorized") =>
    new YoroiError(msg, ErrorCodes.UNAUTHORIZED, 401),

  notFound: (resource: string) =>
    new YoroiError(`${resource} not found`, ErrorCodes.NOT_FOUND, 404),

  validation: (msg: string, details?: unknown) =>
    new YoroiError(msg, ErrorCodes.VALIDATION_ERROR, 422, details),

  internal: (msg = "Internal server error") =>
    new YoroiError(msg, ErrorCodes.INTERNAL_ERROR, 500),

  policyDenied: (reason: string) =>
    new YoroiError(reason, ErrorCodes.POLICY_DENIED, 403),
} as const;

// ─── Type Guard ───────────────────────────────────────────────────────────────

export function isYoroiError(err: unknown): err is YoroiError {
  return err instanceof YoroiError;
}

/** @deprecated Use isYoroiError */
export const isAgentWallError = isYoroiError;
