/**
 * Guardrail Engine — Orchestrator
 *
 * Runs all security scanners against a check request or scan payload and
 * produces a consolidated GuardrailResult:
 *
 *   1. Prompt Injection Scanner  — instruction override, jailbreak, data extraction
 *   2. Credential Scanner        — secrets/keys in arg values
 *   3. PII Scanner               — personal data in arg values
 *
 * The result includes:
 *   - threats[]         — all findings with severity and field paths
 *   - should_deny       — true if any CRITICAL threat is found
 *   - risk_boost        — additional score to add to the risk engine output
 *   - passed            — true if no high/critical threats found
 *   - reason            — human-readable summary for the check response
 *
 * Integration point: call runGuardrails() after the policy engine and before
 * the risk engine in the check route pipeline.
 */

import { scanForPromptInjection } from "./prompt-injection";
import { scanForCredentials } from "./credential-scanner";
import { scanForPII } from "./pii-scanner";
import {
  DENY_SEVERITIES,
  SEVERITY_WEIGHTS,
  type GuardrailResult,
  type GuardrailThreat,
  type ScannerResult,
  type ThreatSeverity,
} from "./types";

// ─── Guardrail Config ────────────────────────────────────────────────────────

/**
 * Per-scanner configuration: which scanners run and on which content.
 */
interface GuardrailConfig {
  /** Scan args for prompt injection (default: true) */
  scanPromptInjection: boolean;
  /** Scan user_intent for injection patterns (default: true) */
  scanUserIntent: boolean;
  /** Scan args values for credentials (default: true) */
  scanCredentials: boolean;
  /** Scan args values for PII (default: true) */
  scanPII: boolean;
  /**
   * When true (e.g. source is tool/web), also deny on HIGH severity.
   * Mitigates indirect prompt attacks from untrusted external content.
   */
  strictDenyForIndirectSource: boolean;
}

const DEFAULT_CONFIG: GuardrailConfig = {
  scanPromptInjection: true,
  scanUserIntent: true,
  scanCredentials: true,
  scanPII: true,
  strictDenyForIndirectSource: false,
};

// ─── Threat Aggregation ───────────────────────────────────────────────────────

/**
 * Computes the total risk boost from all threats.
 * Critical threats contribute the most; multiple low-severity findings add up.
 * Result is clamped to [0, 1].
 */
function computeRiskBoost(threats: GuardrailThreat[]): number {
  if (threats.length === 0) return 0;

  // Use the single highest-severity threat as the base
  const severityOrder: Record<ThreatSeverity, number> = {
    critical: 3,
    high: 2,
    medium: 1,
    low: 0,
  };

  const sorted = [...threats].sort(
    (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
  );

  const topThreat = sorted[0]!;
  const baseBoost = SEVERITY_WEIGHTS[topThreat.severity];

  // Additional threats add diminishing marginal risk (max +0.2 extra)
  const additionalBoost = Math.min(
    0.2,
    sorted.slice(1).reduce((sum, t) => sum + SEVERITY_WEIGHTS[t.severity] * 0.3, 0)
  );

  return Math.min(1.0, baseBoost + additionalBoost);
}

/**
 * Builds a human-readable reason string from the most severe threats.
 */
function buildReason(threats: GuardrailThreat[]): string {
  if (threats.length === 0) return "All guardrail checks passed";

  const critical = threats.filter((t) => t.severity === "critical");
  const high = threats.filter((t) => t.severity === "high");

  if (critical.length > 0) {
    const top = critical.slice(0, 2).map((t) => t.detail).join("; ");
    return `Critical security violation: ${top}`;
  }

  if (high.length > 0) {
    const top = high.slice(0, 2).map((t) => t.detail).join("; ");
    return `High-risk content detected: ${top}`;
  }

  const top = threats[0]!;
  return `Security warning: ${top.detail}`;
}

// ─── Public Interface ─────────────────────────────────────────────────────────

export interface GuardrailInput {
  /** Tool-call arguments to scan */
  args: Record<string, unknown>;
  /** User intent string (may contain injected instructions) */
  user_intent?: string;
  /** Action string (used as context for intent mismatch detection) */
  action?: string;
  /** Tool name (used as context) */
  tool?: string;
  /**
   * Request source. When "tool" or "web", applies stricter denial (high severity → deny)
   * to mitigate indirect prompt attacks from untrusted content.
   */
  source?: string;
}

/**
 * Runs all guardrail scanners against the provided input.
 * This is the main entry point called from the check route.
 */
export function runGuardrails(
  input: GuardrailInput,
  config: Partial<GuardrailConfig> = {}
): GuardrailResult {
  const isIndirectSource = input.source === "tool" || input.source === "web";
  const cfg: GuardrailConfig = {
    ...DEFAULT_CONFIG,
    ...config,
    strictDenyForIndirectSource:
      config.strictDenyForIndirectSource ?? isIndirectSource,
  };
  const scannerResults: ScannerResult[] = [];

  // Build extra fields for injection scanner (action, tool, user_intent)
  const extraStrings: Array<{ path: string; value: string }> = [];
  if (input.action) extraStrings.push({ path: "action", value: input.action });
  if (input.tool) extraStrings.push({ path: "tool", value: input.tool });

  // ── 1. Prompt Injection Scan ────────────────────────────────────────────
  if (cfg.scanPromptInjection || cfg.scanUserIntent) {
    // Scan args deeply
    const argsContent = cfg.scanPromptInjection ? input.args : {};
    // Conditionally include user_intent in the extra strings
    if (cfg.scanUserIntent && input.user_intent) {
      extraStrings.push({ path: "user_intent", value: input.user_intent });
    }
    const injectionResult = scanForPromptInjection(argsContent, extraStrings);
    scannerResults.push(injectionResult);
  }

  // ── 2. Credential Scan ──────────────────────────────────────────────────
  if (cfg.scanCredentials) {
    const credResult = scanForCredentials(input.args);
    scannerResults.push(credResult);
  }

  // ── 3. PII Scan ─────────────────────────────────────────────────────────
  if (cfg.scanPII) {
    const piiResult = scanForPII(input.args);
    scannerResults.push(piiResult);
  }

  // ── Aggregate Results ───────────────────────────────────────────────────
  const allThreats = scannerResults.flatMap((r) => r.threats);

  const denySeverities = cfg.strictDenyForIndirectSource
    ? [...DENY_SEVERITIES, "high"]
    : DENY_SEVERITIES;
  const shouldDeny = allThreats.some((t) => denySeverities.includes(t.severity));

  const passed = allThreats.every(
    (t) => t.severity === "low" || t.severity === "medium"
  );

  const riskBoost = computeRiskBoost(allThreats);
  const reason = buildReason(allThreats);

  return {
    passed,
    threats: allThreats,
    risk_boost: parseFloat(riskBoost.toFixed(4)),
    should_deny: shouldDeny,
    reason: allThreats.length > 0 ? reason : null,
    scanner_results: scannerResults,
  };
}

/**
 * Scans raw string or object content — used by the /api/yoroi/scan endpoint
 * to inspect tool outputs and LLM responses.
 */
export function scanContent(
  content: string | Record<string, unknown>,
  config: Partial<GuardrailConfig> = {}
): GuardrailResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const scannerResults: ScannerResult[] = [];

  const normalizedArgs: Record<string, unknown> =
    typeof content === "string" ? { _content: content } : content;

  if (cfg.scanPromptInjection) {
    scannerResults.push(scanForPromptInjection(normalizedArgs));
  }

  if (cfg.scanCredentials) {
    scannerResults.push(scanForCredentials(normalizedArgs));
  }

  if (cfg.scanPII) {
    scannerResults.push(scanForPII(normalizedArgs));
  }

  const allThreats = scannerResults.flatMap((r) => r.threats);
  const shouldDeny = allThreats.some((t) => DENY_SEVERITIES.includes(t.severity));
  const passed = allThreats.every((t) => t.severity === "low" || t.severity === "medium");
  const riskBoost = computeRiskBoost(allThreats);
  const reason = buildReason(allThreats);

  return {
    passed,
    threats: allThreats,
    risk_boost: parseFloat(riskBoost.toFixed(4)),
    should_deny: shouldDeny,
    reason: allThreats.length > 0 ? reason : null,
    scanner_results: scannerResults,
  };
}

// Re-export types for external use
export type { GuardrailResult, GuardrailThreat, ScannerResult } from "./types";
