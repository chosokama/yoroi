import type { CheckRequest, Policy, Tool } from "@/types";

export interface ScorerResult {
  scorer: string;
  score: number;    // Contribution to total risk (0–1)
  weight: number;   // Relative weight of this scorer
  reason: string;
}

// ─── Payment / Transfer Risk ─────────────────────────────────────────────────

const PAYMENT_KEYWORDS = [
  "payment", "transfer", "withdraw", "deposit", "send", "pay",
  "transaction", "wallet", "crypto", "solana", "ethereum", "bitcoin",
  "stripe", "charge", "debit", "credit",
];

export function scorePaymentRisk(request: CheckRequest): ScorerResult {
  const text = `${request.action} ${request.tool} ${JSON.stringify(request.args)}`.toLowerCase();
  const hasPaymentKeyword = PAYMENT_KEYWORDS.some((kw) => text.includes(kw));

  return {
    scorer: "payment_risk",
    score: hasPaymentKeyword ? 1.0 : 0.0,
    weight: 0.25,
    reason: hasPaymentKeyword
      ? "Action involves payment/financial operation"
      : "No payment keywords detected",
  };
}

// ─── Unknown Tool Risk ───────────────────────────────────────────────────────

export function scoreUnknownTool(
  request: CheckRequest,
  registeredTool: Tool | null
): ScorerResult {
  if (!registeredTool) {
    return {
      scorer: "unknown_tool",
      score: 1.0,
      weight: 0.2,
      reason: `Tool "${request.tool}" is not registered in the tool registry`,
    };
  }

  const riskMap: Record<string, number> = {
    low: 0.1,
    medium: 0.4,
    high: 0.7,
    critical: 1.0,
  };

  const score = riskMap[registeredTool.risk_level] ?? 0.5;

  return {
    scorer: "unknown_tool",
    score,
    weight: 0.2,
    reason: `Tool "${request.tool}" has risk level: ${registeredTool.risk_level}`,
  };
}

// ─── Untrusted Domain Risk ───────────────────────────────────────────────────

export function scoreUntrustedDomain(
  request: CheckRequest,
  policy: Policy
): ScorerResult {
  const { trusted_domains } = policy;
  const urlKeys = ["url", "domain", "href", "endpoint", "target", "destination"];

  for (const key of urlKeys) {
    const val = request.args[key];
    if (typeof val !== "string" || !val) continue;

    try {
      const url = new URL(val.startsWith("http") ? val : `https://${val}`);
      const domain = url.hostname.replace(/^www\./, "");

      if (trusted_domains.length > 0) {
        const isTrusted = trusted_domains.some(
          (d) => domain === d || domain.endsWith(`.${d}`)
        );
        if (!isTrusted) {
          return {
            scorer: "untrusted_domain",
            score: 0.7,
            weight: 0.15,
            reason: `Domain "${domain}" is not in the trusted list`,
          };
        }
      }
    } catch {
      // Malformed URL — treat as risky
      return {
        scorer: "untrusted_domain",
        score: 0.8,
        weight: 0.15,
        reason: "Malformed or unresolvable URL detected in args",
      };
    }
  }

  return {
    scorer: "untrusted_domain",
    score: 0.0,
    weight: 0.15,
    reason: "No untrusted domains detected",
  };
}

// ─── Sensitive Args Risk ─────────────────────────────────────────────────────

const SENSITIVE_ARG_PATTERNS = [
  /password/i, /secret/i, /token/i, /api_?key/i, /private_?key/i,
  /credential/i, /auth/i, /bearer/i, /seed/i, /mnemonic/i,
  /ssn/i, /social_?security/i, /credit_?card/i, /cvv/i,
];

export function scoreSensitiveArgs(request: CheckRequest): ScorerResult {
  const argsStr = JSON.stringify(request.args);
  const matchedPatterns: string[] = [];

  for (const pattern of SENSITIVE_ARG_PATTERNS) {
    if (pattern.test(argsStr)) {
      matchedPatterns.push(pattern.source);
    }
  }

  const score = Math.min(1.0, matchedPatterns.length * 0.3);

  return {
    scorer: "sensitive_args",
    score,
    weight: 0.2,
    reason: matchedPatterns.length > 0
      ? `Sensitive data patterns detected in args: ${matchedPatterns.slice(0, 3).join(", ")}`
      : "No sensitive data patterns detected",
  };
}

// ─── Intent Mismatch Risk ────────────────────────────────────────────────────

/**
 * Checks for obvious mismatches between user intent and requested action.
 * Uses simple keyword heuristics — not LLM-based.
 */
export function scoreIntentMismatch(request: CheckRequest): ScorerResult {
  const { user_intent, action, tool } = request;

  if (!user_intent || user_intent.trim().length === 0) {
    return {
      scorer: "intent_mismatch",
      score: 0.1,
      weight: 0.1,
      reason: "No user intent provided — slight risk increase",
    };
  }

  const intentLower = user_intent.toLowerCase();
  const actionLower = action.toLowerCase();
  const toolLower = tool.toLowerCase();

  // High-risk actions not mentioned in intent
  const dangerousKeywords = ["delete", "transfer", "payment", "withdraw", "drop", "wipe"];
  for (const kw of dangerousKeywords) {
    if ((actionLower.includes(kw) || toolLower.includes(kw)) && !intentLower.includes(kw)) {
      return {
        scorer: "intent_mismatch",
        score: 0.8,
        weight: 0.1,
        reason: `Action "${action}" involves "${kw}" but user intent does not mention it — possible prompt injection`,
      };
    }
  }

  return {
    scorer: "intent_mismatch",
    score: 0.0,
    weight: 0.1,
    reason: "Action appears consistent with stated user intent",
  };
}

// ─── External Source Risk ────────────────────────────────────────────────────

export function scoreExternalSource(sourceDelta: number): ScorerResult {
  return {
    scorer: "external_source",
    score: sourceDelta,
    weight: 0.1,
    reason: `Source provenance contributes ${(sourceDelta * 100).toFixed(0)}% risk`,
  };
}
