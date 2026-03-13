/**
 * POST /api/agentwall/check  (legacy alias → prefer /api/yoroi/check)
 *
 * YOROI 鎧 core firewall endpoint. Evaluates every agent action through a
 * layered security pipeline before returning a decision.
 *
 * Pipeline:
 *   1. API Key Authentication       — SHA-256 hash lookup in DB
 *   2. Request Validation           — Zod schema
 *   3. Rate Limiting                — 100 req/min per agent_id (Redis)
 *   4. Policy Engine                — deterministic rules (allowlist, blocklist, spend)
 *   5. Guardrail Engine             — prompt injection, credentials, PII in args
 *   6. Risk Engine                  — weighted probabilistic scoring
 *   7. Decision Resolution          — apply policy risk thresholds
 *   8. Audit Logging                — async, fire-and-forget to Supabase
 *   9. Response
 */

import { NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import { extractApiKey, validateApiKey } from "@/lib/security/api-key";
import {
  checkRequestBodySize,
  validateAndTruncateArgs,
  validateToolId,
  validateAction,
} from "@/lib/security/input-hardening";
import {
  parseRequestBody,
  unauthorizedResponse,
  rateLimitResponse,
  internalErrorResponse,
  badRequestResponse,
} from "@/lib/security/validation";
import { checkRateLimit, CacheKeys } from "@/lib/redis";
import { loadPolicy, evaluatePolicy, getDefaultPolicy } from "@/lib/policy-engine";
import { computeRiskScore, resolveDecision } from "@/lib/risk-engine";
import { runGuardrails } from "@/lib/guardrail-engine";
import { getTool } from "@/lib/tool-registry";
import { getSupabaseServer } from "@/lib/supabase/server";
import { CheckRequestSchema } from "@/types";
import type { CheckResponse } from "@/types";
import type { GuardrailThreat } from "@/lib/guardrail-engine/types";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<NextResponse> {
  // ── 1. API Key Authentication ──────────────────────────────────────────────
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);

  if (!validatedKey) {
    return unauthorizedResponse("Valid API key required. Provide it via the x-api-key header.");
  }

  // ── 2. Input Hardening — Reject oversized requests before parsing ───────────
  const sizeCheck = checkRequestBodySize(request);
  if (!sizeCheck.ok) {
    return badRequestResponse(sizeCheck.error ?? "Request too large");
  }

  // ── 3. Parse & Validate Request Body ───────────────────────────────────────
  const { data: checkRequest, error: parseError } = await parseRequestBody(
    request,
    CheckRequestSchema
  );

  if (parseError) return parseError;

  // ── 4. Validate tool/action identifiers (anti–prompt-injection) ────────────
  const toolValidation = validateToolId(checkRequest.tool);
  if (!toolValidation.valid) {
    return badRequestResponse(toolValidation.error ?? "Invalid tool");
  }
  const actionValidation = validateAction(checkRequest.action);
  if (!actionValidation.valid) {
    return badRequestResponse(actionValidation.error ?? "Invalid action");
  }

  // ── 5. Validate & truncate args (anti-DoS, anti–ReDoS) ──────────────────────
  const argsResult = validateAndTruncateArgs(checkRequest.args ?? {});
  if (argsResult.error) {
    return badRequestResponse(argsResult.error);
  }

  // ── 6. Rate Limiting ────────────────────────────────────────────────────────
  const rateLimitKey = CacheKeys.rateLimit(checkRequest.agent_id);
  const rateLimit = await checkRateLimit(rateLimitKey, 100, 60);

  if (!rateLimit.allowed) {
    return rateLimitResponse(rateLimit.resetAt);
  }

  // ── 7. Load Policy ──────────────────────────────────────────────────────────
  const policy = (await loadPolicy(validatedKey.orgId)) ?? getDefaultPolicy();

  // Normalize optional fields; use hardened args from validation step
  const normalizedRequest = {
    ...checkRequest,
    args: argsResult.args,
    source: checkRequest.source ?? ("external" as const),
  };

  // ── 8. Policy Engine — Deterministic Evaluation ──────────────────────────────
  const policyResult = evaluatePolicy(normalizedRequest, policy);

  if (!policyResult.allowed) {
    const actionId = uuidv4();
    void logAction({
      actionId,
      request: normalizedRequest,
      decision: "deny",
      riskScore: 1.0,
      reason: policyResult.reason,
      orgId: validatedKey.orgId,
      threatCount: 0,
    });
    return NextResponse.json({
      decision: "deny",
      risk_score: 1.0,
      reason: policyResult.reason,
      action_id: actionId,
    } satisfies CheckResponse);
  }

  // ── 9. Guardrail Engine — Injection / Credential / PII Scanning ──────────────
  const guardrailResult = runGuardrails({
    args: normalizedRequest.args,
    user_intent: normalizedRequest.user_intent,
    action: normalizedRequest.action,
    tool: normalizedRequest.tool,
    source: normalizedRequest.source,
  });

  // Hard deny on any critical security violation (prompt injection, credential leak)
  if (guardrailResult.should_deny) {
    const actionId = uuidv4();
    const reason = guardrailResult.reason ?? "Critical security violation detected by guardrail engine";

    void logAction({
      actionId,
      request: normalizedRequest,
      decision: "deny",
      riskScore: 1.0,
      reason,
      orgId: validatedKey.orgId,
      threatCount: guardrailResult.threats.length,
    });

    return NextResponse.json({
      decision: "deny",
      risk_score: 1.0,
      reason,
      action_id: actionId,
    } satisfies CheckResponse);
  }

  // ── 10. Tool Registry Lookup ─────────────────────────────────────────────────
  let registeredTool = null;
  try {
    registeredTool = await getTool(checkRequest.tool);
  } catch {
    // Non-fatal — treat as unknown tool (adds risk via scoreUnknownTool)
  }

  // ── 11. Risk Engine — Weighted Scoring + Guardrail Boost ────────────────────
  const riskResult = computeRiskScore(
    normalizedRequest,
    policy,
    registeredTool,
    guardrailResult.risk_boost  // Guardrail findings directly boost the score
  );

  // ── 12. Decision Resolution ──────────────────────────────────────────────────
  const decision = resolveDecision(riskResult.risk_score, policy);

  // Build reason: prefer guardrail reason for non-allow decisions if it's more informative
  let reason: string;
  if (decision === "allow") {
    reason = policyResult.reason;
  } else if (guardrailResult.reason && guardrailResult.risk_boost > 0.1) {
    // Guardrail findings drove the decision — surface that reason
    reason = guardrailResult.reason;
  } else {
    reason = riskResult.dominant_reason;
  }

  // ── 13. Audit Log ────────────────────────────────────────────────────────────
  const actionId = uuidv4();
  void logAction({
    actionId,
    request: normalizedRequest,
    decision,
    riskScore: riskResult.risk_score,
    reason,
    orgId: validatedKey.orgId,
    threatCount: guardrailResult.threats.length,
    threats: guardrailResult.threats,
  });

  // ── 14. Respond ──────────────────────────────────────────────────────────────
  return NextResponse.json(
    {
      decision,
      risk_score: riskResult.risk_score,
      reason,
      action_id: actionId,
    } satisfies CheckResponse,
    {
      headers: {
        "X-RateLimit-Remaining": String(rateLimit.remaining),
        // Surface guardrail findings count for observability
        "X-Guardrail-Threats": String(guardrailResult.threats.length),
      },
    }
  );
}

// ─── Audit Log Helper ─────────────────────────────────────────────────────────

interface LogActionParams {
  actionId: string;
  request: {
    agent_id: string;
    tool: string;
    action: string;
    args: Record<string, unknown>;
    source: string;
  };
  decision: string;
  riskScore: number;
  reason: string;
  orgId: string;
  threatCount: number;
  threats?: GuardrailThreat[];
}

async function logAction(params: LogActionParams): Promise<void> {
  try {
    const supabase = getSupabaseServer();
    await supabase.from("actions").insert({
      action_id: params.actionId,
      agent_id: params.request.agent_id,
      tool: params.request.tool,
      action: params.request.action,
      args: params.request.args,
      risk_score: params.riskScore,
      decision: params.decision,
      reason: params.reason,
      source: params.request.source,
      org_id: params.orgId,
      timestamp: new Date().toISOString(),
      // Store threat count and top threats for dashboard queries
      threat_count: params.threatCount,
      threats: params.threats
        ? params.threats.slice(0, 10).map((t) => ({
            type: t.type,
            severity: t.severity,
            field: t.field,
            detail: t.detail,
          }))
        : [],
    });
  } catch {
    // Logging failure must never affect the main response
  }
}

// Reject non-POST methods
export async function GET(): Promise<NextResponse> {
  return internalErrorResponse("Method not allowed");
}
