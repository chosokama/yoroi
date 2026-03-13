/**
 * POST /api/agentwall/scan
 *
 * Standalone content scanner for tool outputs, LLM responses, and user inputs.
 * Use this to inspect content AFTER it is received from an external tool before
 * passing it back to the agent. This closes the inbound-only gap in the check
 * endpoint.
 *
 * Request:
 *   {
 *     agent_id: string
 *     content: string | object     — the content to scan
 *     content_type: "tool_output" | "llm_response" | "user_input" | "agent_args"
 *     source?: SourceType
 *   }
 *
 * Response:
 *   {
 *     safe: boolean
 *     threats: GuardrailThreat[]
 *     risk_score: number           — aggregated risk [0,1]
 *     action: "allow" | "deny" | "sanitize"
 *     sanitized_content?: string   — present when action === "sanitize"
 *   }
 */

import { NextResponse } from "next/server";
import { z } from "zod";
import { extractApiKey, validateApiKey } from "@/lib/security/api-key";
import {
  parseRequestBody,
  unauthorizedResponse,
  internalErrorResponse,
} from "@/lib/security/validation";
import { checkRateLimit } from "@/lib/redis";
import { scanContent } from "@/lib/guardrail-engine";
import { redactPII } from "@/lib/guardrail-engine/pii-scanner";
import { getSupabaseServer } from "@/lib/supabase/server";
import { v4 as uuidv4 } from "uuid";
import type { ScanResponse } from "@/lib/guardrail-engine/types";

export const runtime = "nodejs";

// ─── Request Schema ───────────────────────────────────────────────────────────

const ScanRequestSchema = z.object({
  agent_id: z.string().min(1).max(128),
  content: z.union([
    z.string().max(65536),
    z.record(z.unknown()),
  ]),
  content_type: z.enum(["tool_output", "llm_response", "user_input", "agent_args"]),
  source: z
    .enum(["system", "developer", "user", "memory", "tool", "web", "external"])
    .default("external"),
});

type ScanRequest = z.infer<typeof ScanRequestSchema>;

// ─── Route Handler ────────────────────────────────────────────────────────────

export async function POST(request: Request): Promise<NextResponse> {
  // ── 1. Authentication ──────────────────────────────────────────────────────
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) {
    return unauthorizedResponse("Valid API key required (x-api-key header).");
  }

  // ── 2. Parse & Validate ────────────────────────────────────────────────────
  const { data: body, error: parseError } = await parseRequestBody(
    request,
    ScanRequestSchema
  );
  if (parseError) return parseError;

  // ── 3. Rate Limiting ────────────────────────────────────────────────────────
  const rateLimitKey = `agentwall:ratelimit:scan:${body.agent_id}`;
  const { allowed, remaining, resetAt } = await checkRateLimit(
    rateLimitKey,
    200,
    60
  );
  if (!allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded", code: "RATE_LIMITED" },
      {
        status: 429,
        headers: {
          "Retry-After": String(Math.max(0, resetAt - Math.floor(Date.now() / 1000))),
        },
      }
    );
  }

  // ── 4. Run Guardrail Scanners ──────────────────────────────────────────────
  let guardrailResult;
  try {
    guardrailResult = scanContent(body.content);
  } catch {
    return internalErrorResponse("Scan failed due to an internal error");
  }

  const { threats, risk_boost, should_deny } = guardrailResult;

  // ── 5. Determine Action ────────────────────────────────────────────────────
  let action: ScanResponse["action"];
  let sanitizedContent: string | undefined;

  if (should_deny) {
    action = "deny";
  } else if (threats.some((t) => t.type === "pii_exposure" && t.severity !== "low")) {
    // Offer sanitized version for PII-containing content
    action = "sanitize";
    if (typeof body.content === "string") {
      sanitizedContent = redactPII(body.content);
    }
  } else if (risk_boost > 0.3) {
    // Moderate threats — let caller decide; still return allow but flag it
    action = "allow";
  } else {
    action = "allow";
  }

  // ── 6. Log Scan Result ─────────────────────────────────────────────────────
  void logScanResult(
    { ...body, source: body.source ?? "external" },
    validatedKey.orgId,
    risk_boost,
    action,
    threats.length
  );

  // ── 7. Respond ─────────────────────────────────────────────────────────────
  const response: ScanResponse = {
    safe: action === "allow",
    threats,
    risk_score: parseFloat(Math.min(1, risk_boost).toFixed(4)),
    action,
    ...(sanitizedContent !== undefined ? { sanitized_content: sanitizedContent } : {}),
  };

  return NextResponse.json(response, {
    headers: { "X-RateLimit-Remaining": String(remaining) },
  });
}

// ─── Log Helper ───────────────────────────────────────────────────────────────

async function logScanResult(
  body: ScanRequest,
  orgId: string,
  riskScore: number,
  action: string,
  threatCount: number
): Promise<void> {
  try {
    const supabase = getSupabaseServer();
    await supabase.from("scan_logs").insert({
      scan_id: uuidv4(),
      agent_id: body.agent_id,
      content_type: body.content_type,
      source: body.source,
      risk_score: riskScore,
      action,
      threat_count: threatCount,
      org_id: orgId,
      timestamp: new Date().toISOString(),
    });
  } catch {
    // Non-fatal — logging failure must not affect the response
  }
}
