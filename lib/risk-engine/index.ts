import {
  scorePaymentRisk,
  scoreUnknownTool,
  scoreUntrustedDomain,
  scoreSensitiveArgs,
  scoreIntentMismatch,
  scoreExternalSource,
  type ScorerResult,
} from "./scorers";
import { getSourceRiskDelta } from "@/lib/source-provenance";
import type { CheckRequest, Policy, Tool } from "@/types";

export interface RiskEvaluationResult {
  risk_score: number;         // Final clamped score [0, 1]
  scorer_results: ScorerResult[];
  dominant_reason: string;    // Reason from the highest-contributing scorer
}

/**
 * Computes the overall risk score for a request.
 *
 * Each scorer produces a raw score (0–1) and a weight.
 * Final score = sum(score_i * weight_i) + guardrail_boost, clamped to [0, 1].
 *
 * @param guardrailBoost  Additional risk from the guardrail engine (0–1).
 *                        This is added directly to the weighted-scorer sum.
 */
export function computeRiskScore(
  request: CheckRequest,
  policy: Policy,
  registeredTool: Tool | null,
  guardrailBoost = 0
): RiskEvaluationResult {
  const sourceDelta = getSourceRiskDelta(request.source);

  const scorerResults: ScorerResult[] = [
    scorePaymentRisk(request),
    scoreUnknownTool(request, registeredTool),
    scoreUntrustedDomain(request, policy),
    scoreSensitiveArgs(request),
    scoreIntentMismatch(request),
    scoreExternalSource(sourceDelta),
  ];

  // Weighted sum from probabilistic scorers
  const weightedSum = scorerResults.reduce(
    (sum, s) => sum + s.score * s.weight,
    0
  );

  // Add guardrail boost (from prompt injection / credential / PII findings)
  const rawScore = weightedSum + guardrailBoost;
  const risk_score = Math.min(1, Math.max(0, rawScore));

  // Find the scorer contributing the most risk (excluding guardrail boost)
  const dominant = scorerResults.reduce((max, s) =>
    s.score * s.weight > max.score * max.weight ? s : max
  );

  return {
    risk_score: parseFloat(risk_score.toFixed(4)),
    scorer_results: scorerResults,
    dominant_reason: dominant.reason,
  };
}

// ─── Decision Resolver ───────────────────────────────────────────────────────

import type { DecisionType } from "@/types";

/**
 * Maps a risk score to a decision using policy-defined thresholds.
 */
export function resolveDecision(
  risk_score: number,
  policy: Policy
): DecisionType {
  if (risk_score < policy.risk_threshold_allow) return "allow";
  if (risk_score < policy.risk_threshold_sandbox) return "require_confirmation";
  if (risk_score < policy.risk_threshold_deny) return "sandbox";
  return "deny";
}
