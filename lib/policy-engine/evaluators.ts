import type { Policy, PolicyResult } from "@/types";

// ─── Tool Access Evaluator ───────────────────────────────────────────────────

/**
 * Checks whether the requested tool is in the policy's allowed list.
 * If allowed_tools is empty, all tools are permitted (open policy).
 */
export function evaluateToolAccess(
  tool: string,
  policy: Policy
): PolicyResult {
  const { allowed_tools } = policy;

  // Empty allowed list means no tool restrictions
  if (allowed_tools.length === 0) {
    return { allowed: true, reason: "No tool restrictions defined", evaluator: "tool_access" };
  }

  const normalizedTool = tool.toLowerCase().trim();
  const isAllowed = allowed_tools.some(
    (t) => t.toLowerCase().trim() === normalizedTool
  );

  return {
    allowed: isAllowed,
    reason: isAllowed
      ? `Tool "${tool}" is in the allowed list`
      : `Tool "${tool}" is not in the allowed tools list: [${allowed_tools.join(", ")}]`,
    evaluator: "tool_access",
  };
}

// ─── Spend Limit Evaluator ───────────────────────────────────────────────────

/**
 * Checks whether an action's spend amount would exceed the policy limit.
 * Looks for `amount`, `value`, `cost`, or `spend` keys in args.
 */
export function evaluateSpendLimit(
  args: Record<string, unknown>,
  policy: Policy
): PolicyResult {
  const { max_spend_usd } = policy;

  if (max_spend_usd === null || max_spend_usd === undefined) {
    return { allowed: true, reason: "No spend limit configured", evaluator: "spend_limit" };
  }

  const amountKeys = ["amount", "value", "cost", "spend", "price", "usd"];
  let requestedAmount: number | null = null;

  for (const key of amountKeys) {
    const val = args[key];
    if (typeof val === "number" && isFinite(val)) {
      requestedAmount = val;
      break;
    }
    if (typeof val === "string") {
      const parsed = parseFloat(val);
      if (isFinite(parsed)) {
        requestedAmount = parsed;
        break;
      }
    }
  }

  if (requestedAmount === null) {
    return { allowed: true, reason: "No spend amount detected in args", evaluator: "spend_limit" };
  }

  const withinLimit = requestedAmount <= max_spend_usd;

  return {
    allowed: withinLimit,
    reason: withinLimit
      ? `Spend amount $${requestedAmount} is within limit of $${max_spend_usd}`
      : `Spend amount $${requestedAmount} exceeds policy limit of $${max_spend_usd}`,
    evaluator: "spend_limit",
  };
}

// ─── Domain Trust Evaluator ───────────────────────────────────────────────────

/**
 * Checks whether any URL/domain in the args belongs to a trusted domain.
 * Only rejects if a URL is present AND its domain is not trusted.
 */
export function evaluateDomainTrust(
  args: Record<string, unknown>,
  policy: Policy
): PolicyResult {
  const { trusted_domains } = policy;

  if (trusted_domains.length === 0) {
    return { allowed: true, reason: "No domain restrictions configured", evaluator: "domain_trust" };
  }

  const urlKeys = ["url", "domain", "href", "endpoint", "target", "destination"];
  const foundUrls: string[] = [];

  for (const key of urlKeys) {
    const val = args[key];
    if (typeof val === "string" && val.length > 0) {
      foundUrls.push(val);
    }
  }

  if (foundUrls.length === 0) {
    return { allowed: true, reason: "No URLs detected in args", evaluator: "domain_trust" };
  }

  for (const rawUrl of foundUrls) {
    const domain = extractDomain(rawUrl);
    if (!domain) continue;

    const isTrusted = trusted_domains.some((trusted) =>
      domain === trusted || domain.endsWith(`.${trusted}`)
    );

    if (!isTrusted) {
      return {
        allowed: false,
        reason: `Domain "${domain}" is not in the trusted domains list: [${trusted_domains.join(", ")}]`,
        evaluator: "domain_trust",
      };
    }
  }

  return { allowed: true, reason: "All detected domains are trusted", evaluator: "domain_trust" };
}

// ─── Action Permission Evaluator ─────────────────────────────────────────────

/**
 * Checks whether the action is explicitly blocked by policy.
 * Also flags if action is in sensitive_actions (adds context, not a block).
 */
export function evaluateActionPermission(
  action: string,
  policy: Policy
): PolicyResult {
  const { blocked_actions } = policy;
  const normalizedAction = action.toLowerCase().trim();

  const isBlocked = blocked_actions.some(
    (a) => a.toLowerCase().trim() === normalizedAction
  );

  if (isBlocked) {
    return {
      allowed: false,
      reason: `Action "${action}" is explicitly blocked by policy`,
      evaluator: "action_permission",
    };
  }

  const isSensitive = policy.sensitive_actions.some(
    (a) => a.toLowerCase().trim() === normalizedAction
  );

  return {
    allowed: true,
    reason: isSensitive
      ? `Action "${action}" is sensitive — elevated scrutiny applied`
      : `Action "${action}" is permitted`,
    evaluator: "action_permission",
  };
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function extractDomain(rawUrl: string): string | null {
  try {
    const url = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}
