/**
 * Input Hardening
 *
 * Enforces limits on request payloads to mitigate:
 *   - DoS via oversized JSON
 *   - Deeply nested structures (stack overflow, CPU exhaustion)
 *   - Extremely long strings (ReDoS, memory exhaustion)
 *   - Tool/action name poisoning (injection via identifiers)
 */

// ─── Limits ───────────────────────────────────────────────────────────────────

/** Max total size of args when JSON-stringified (bytes) */
export const ARGS_MAX_SIZE_BYTES = 64 * 1024; // 64 KB

/** Max depth of nested objects in args */
export const ARGS_MAX_DEPTH = 10;

/** Max length of any single string value in args */
export const ARGS_MAX_STRING_LENGTH = 16 * 1024; // 16 KB

/** Max request body size (Content-Length) before parsing */
export const REQUEST_BODY_MAX_BYTES = 128 * 1024; // 128 KB

/** Allowed characters in tool_id (alphanumeric, underscore, hyphen) */
const TOOL_ID_PATTERN = /^[a-zA-Z0-9_-]+$/;

/** Allowed characters in action (same as tool_id, plus spaces for readability) */
const ACTION_PATTERN = /^[a-zA-Z0-9_\-.\s]+$/;

// ─── Validation Helpers ────────────────────────────────────────────────────────

/**
 * Validates and optionally truncates args to enforce size/depth/string limits.
 * Returns validated args (with truncation applied) or an error.
 */
export function validateAndTruncateArgs(
  args: Record<string, unknown>
): { args: Record<string, unknown>; error?: string } {
  const argsStr = JSON.stringify(args);
  if (argsStr.length > ARGS_MAX_SIZE_BYTES) {
    return {
      args: {},
      error: `args exceeds maximum size (${ARGS_MAX_SIZE_BYTES / 1024} KB)`,
    };
  }

  const depth = getObjectDepth(args);
  if (depth > ARGS_MAX_DEPTH) {
    return {
      args: {},
      error: `args exceeds maximum nesting depth (${ARGS_MAX_DEPTH})`,
    };
  }

  const truncated = truncateLongStrings(args, ARGS_MAX_STRING_LENGTH) as Record<string, unknown>;
  return { args: truncated };
}

function getObjectDepth(obj: unknown, current = 0): number {
  if (current > ARGS_MAX_DEPTH) return current;
  if (obj === null || typeof obj !== "object") return current;
  if (Array.isArray(obj)) {
    let max = current;
    for (const item of obj) {
      max = Math.max(max, getObjectDepth(item, current + 1));
    }
    return max;
  }
  let max = current;
  for (const v of Object.values(obj as Record<string, unknown>)) {
    max = Math.max(max, getObjectDepth(v, current + 1));
  }
  return max;
}

function truncateLongStrings(obj: unknown, maxLen: number): unknown {
  if (typeof obj === "string") {
    return obj.length <= maxLen ? obj : obj.slice(0, maxLen);
  }
  if (obj === null || typeof obj !== "object") {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) =>
      typeof item === "string" && item.length > maxLen
        ? item.slice(0, maxLen)
        : truncateLongStrings(item, maxLen)
    );
  }
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    result[k] = truncateLongStrings(v, maxLen);
  }
  return result;
}

/**
 * Validates tool_id format. Rejects identifiers that could be used for
 * prompt injection (e.g. "ignore_previous_instructions" as tool name).
 */
export function validateToolId(toolId: string): { valid: boolean; error?: string } {
  if (toolId.length < 1 || toolId.length > 128) {
    return { valid: false, error: "tool_id must be 1–128 characters" };
  }
  if (!TOOL_ID_PATTERN.test(toolId)) {
    return {
      valid: false,
      error: "tool_id may only contain letters, numbers, underscores, and hyphens",
    };
  }
  const lower = toolId.toLowerCase();
  const suspicious = [
    "ignore", "override", "forget", "disregard", "system", "prompt",
    "instruction", "jailbreak", "bypass", "admin", "root", "dan",
  ];
  if (suspicious.some((s) => lower.includes(s))) {
    return {
      valid: false,
      error: "tool_id contains suspicious substring (possible injection)",
    };
  }
  return { valid: true };
}

/**
 * Validates action string format. Rejects actions that look like injection.
 */
export function validateAction(action: string): { valid: boolean; error?: string } {
  if (action.length < 1 || action.length > 256) {
    return { valid: false, error: "action must be 1–256 characters" };
  }
  if (!ACTION_PATTERN.test(action)) {
    return {
      valid: false,
      error: "action contains invalid characters",
    };
  }
  const lower = action.toLowerCase();
  const suspicious = [
    "ignore previous", "override instructions", "forget everything",
    "system prompt", "new instructions", "[system]",
  ];
  if (suspicious.some((s) => lower.includes(s))) {
    return {
      valid: false,
      error: "action contains suspicious substring (possible injection)",
    };
  }
  return { valid: true };
}

/**
 * Checks Content-Length header to reject oversized requests before parsing.
 */
export function checkRequestBodySize(request: Request): { ok: boolean; error?: string } {
  const cl = request.headers.get("content-length");
  if (!cl) return { ok: true };
  const size = parseInt(cl, 10);
  if (isNaN(size) || size < 0) return { ok: true };
  if (size > REQUEST_BODY_MAX_BYTES) {
    return {
      ok: false,
      error: `Request body exceeds maximum size (${REQUEST_BODY_MAX_BYTES / 1024} KB)`,
    };
  }
  return { ok: true };
}
