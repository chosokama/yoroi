// ─── Threat Classification ────────────────────────────────────────────────────

export type ThreatSeverity = "low" | "medium" | "high" | "critical";

export type ThreatType =
  | "prompt_injection"       // Attempt to override agent instructions
  | "jailbreak"              // Attempt to bypass safety constraints
  | "instruction_override"   // "ignore previous instructions" patterns
  | "data_extraction"        // Attempt to exfiltrate system prompt / context
  | "credential_leak"        // Secret/API key/token in args or content
  | "pii_exposure"           // Personal data (SSN, CC, email, phone) in args
  | "content_policy"         // Violates content safety rules
  | "schema_mismatch"        // Tool call doesn't match registered schema
  | "indirect_injection";    // Injected payload embedded in external content

// ─── Individual Threat ────────────────────────────────────────────────────────

export interface GuardrailThreat {
  /** Category of threat */
  type: ThreatType;
  /** How severe this finding is */
  severity: ThreatSeverity;
  /** Dot-path to the field that triggered this finding (e.g. "args.body") */
  field: string;
  /** Human-readable description of the finding */
  detail: string;
  /** Snippet of the triggering content (truncated, never more than 100 chars) */
  snippet?: string;
}

// ─── Scanner Result ───────────────────────────────────────────────────────────

export interface ScannerResult {
  /** Name of the scanner that produced these findings */
  scanner: string;
  /** Threats found by this scanner */
  threats: GuardrailThreat[];
}

// ─── Guardrail Evaluation Result ─────────────────────────────────────────────

export interface GuardrailResult {
  /** True if no critical/high threats were found */
  passed: boolean;
  /** All threats found across all scanners */
  threats: GuardrailThreat[];
  /** Additional risk score boost to add (0–1) */
  risk_boost: number;
  /** True if the guardrail mandates immediate denial regardless of risk score */
  should_deny: boolean;
  /** Summary reason for display in the check response */
  reason: string | null;
  /** Per-scanner breakdown */
  scanner_results: ScannerResult[];
}

// ─── Scan Request (for /api/yoroi/scan) ───────────────────────────────────────

export type ScanContentType =
  | "tool_output"    // Output from an external tool
  | "llm_response"   // Response from an LLM completion
  | "user_input"     // Raw user message
  | "agent_args";    // Tool-call arguments (same as check args)

export interface ScanRequest {
  agent_id: string;
  /** The content to scan — string or structured object */
  content: string | Record<string, unknown>;
  content_type: ScanContentType;
  source?: string;
}

export interface ScanResponse {
  safe: boolean;
  threats: GuardrailThreat[];
  risk_score: number;
  action: "allow" | "deny" | "sanitize";
  sanitized_content?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Severities that mandate immediate denial */
export const DENY_SEVERITIES: ThreatSeverity[] = ["critical"];

/** Severity weights for risk_boost calculation */
export const SEVERITY_WEIGHTS: Record<ThreatSeverity, number> = {
  low: 0.05,
  medium: 0.15,
  high: 0.35,
  critical: 0.60,
};

/** Redacts a string for safe inclusion in logs */
export function redactSnippet(raw: string, maxLen = 100): string {
  const trimmed = raw.slice(0, maxLen);
  return trimmed.length < raw.length ? `${trimmed}…` : trimmed;
}
