import { NextResponse } from "next/server";
import { ZodError, ZodSchema } from "zod";
import type { ApiErrorResponse } from "@/types";

// ─── Safe JSON Parse ─────────────────────────────────────────────────────────

/**
 * Safely parses a JSON string. Returns null on any parse error.
 * Prevents JSON-based injection payloads from propagating.
 */
export function safeJsonParse<T = unknown>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/**
 * Parses and validates a Next.js request body against a Zod schema.
 * Returns the parsed data or a NextResponse with validation errors.
 */
export async function parseRequestBody<T>(
  request: Request,
  schema: ZodSchema<T>
): Promise<{ data: T; error: null } | { data: null; error: NextResponse }> {
  let raw: unknown;

  try {
    raw = await request.json();
  } catch {
    return {
      data: null,
      error: NextResponse.json(
        {
          error: "Invalid JSON body",
          code: "INVALID_JSON",
        } satisfies ApiErrorResponse,
        { status: 400 }
      ),
    };
  }

  const result = schema.safeParse(raw);

  if (!result.success) {
    return {
      data: null,
      error: NextResponse.json(
        {
          error: "Request validation failed",
          code: "VALIDATION_ERROR",
          details: formatZodErrors(result.error),
        } satisfies ApiErrorResponse,
        { status: 422 }
      ),
    };
  }

  return { data: result.data, error: null };
}

/**
 * Parses URL search params against a Zod schema.
 */
export function parseQueryParams<T>(
  searchParams: URLSearchParams,
  schema: ZodSchema<T>
): { data: T; error: null } | { data: null; error: NextResponse } {
  const raw = Object.fromEntries(searchParams.entries());

  const result = schema.safeParse(raw);

  if (!result.success) {
    return {
      data: null,
      error: NextResponse.json(
        {
          error: "Query parameter validation failed",
          code: "VALIDATION_ERROR",
          details: formatZodErrors(result.error),
        } satisfies ApiErrorResponse,
        { status: 422 }
      ),
    };
  }

  return { data: result.data, error: null };
}

// ─── Zod Error Formatter ─────────────────────────────────────────────────────

function formatZodErrors(error: ZodError): Record<string, string[]> {
  const formatted: Record<string, string[]> = {};
  for (const issue of error.issues) {
    const path = issue.path.join(".") || "_root";
    if (!formatted[path]) formatted[path] = [];
    formatted[path]!.push(issue.message);
  }
  return formatted;
}

// ─── Response Helpers ─────────────────────────────────────────────────────────

export function unauthorizedResponse(reason = "Unauthorized"): NextResponse {
  return NextResponse.json(
    { error: reason, code: "UNAUTHORIZED" } satisfies ApiErrorResponse,
    { status: 401 }
  );
}

export function rateLimitResponse(resetAt: number): NextResponse {
  return NextResponse.json(
    { error: "Rate limit exceeded", code: "RATE_LIMITED" } satisfies ApiErrorResponse,
    {
      status: 429,
      headers: {
        "Retry-After": String(Math.max(0, resetAt - Math.floor(Date.now() / 1000))),
        "X-RateLimit-Reset": String(resetAt),
      },
    }
  );
}

export function internalErrorResponse(message = "Internal server error"): NextResponse {
  return NextResponse.json(
    { error: message, code: "INTERNAL_ERROR" } satisfies ApiErrorResponse,
    { status: 500 }
  );
}

export function badRequestResponse(message: string): NextResponse {
  return NextResponse.json(
    { error: message, code: "BAD_REQUEST" } satisfies ApiErrorResponse,
    { status: 400 }
  );
}
