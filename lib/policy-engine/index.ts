import {
  evaluateToolAccess,
  evaluateSpendLimit,
  evaluateDomainTrust,
  evaluateActionPermission,
} from "./evaluators";
import {
  getCachedEnvelope,
  setCachedEnvelope,
  invalidate,
  CacheKeys,
} from "@/lib/redis";
import { getSupabaseServer } from "@/lib/supabase/server";
import { logger } from "@/utils/logger";
import type { Policy, PolicyResult, CheckRequest } from "@/types";

// ─── TTL Constants ────────────────────────────────────────────────────────────

/**
 * How long (ms) before a cached policy is considered stale.
 * A stale entry is still served immediately, but a background refresh is triggered.
 */
const POLICY_SOFT_TTL_MS = 60_000; // 60 seconds

/**
 * How long (seconds) the Redis key lives before it expires completely.
 * Provides a safety net if the background refresh never fires (e.g. edge crash).
 */
const POLICY_HARD_TTL_S = 300; // 5 minutes

/**
 * How long (seconds) to cache a negative result (org has no policy configured).
 * Shorter than HARD_TTL so a newly-created policy is picked up quickly.
 */
const POLICY_NEGATIVE_TTL_S = 30; // 30 seconds

// ─── Database Fetch ───────────────────────────────────────────────────────────

/**
 * Fetches the most recent policy for an org directly from Supabase.
 * Returns null if no policy exists.
 */
async function fetchPolicyFromDB(orgId: string): Promise<Policy | null> {
  const supabase = getSupabaseServer();
  const { data, error } = await supabase
    .from("policies")
    .select("*")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false })
    .limit(1)
    .single();

  if (error || !data) return null;
  return data as Policy;
}

// ─── Cache Write ──────────────────────────────────────────────────────────────

/**
 * Writes a policy (or null sentinel) into the Redis cache.
 * Uses the envelope format so stale-while-revalidate metadata is co-located.
 */
async function writePolicyToCache(
  orgId: string,
  policy: Policy | null
): Promise<void> {
  const ttl = policy === null ? POLICY_NEGATIVE_TTL_S : POLICY_HARD_TTL_S;
  await setCachedEnvelope(CacheKeys.policy(orgId), policy, ttl);
}

// ─── Background Refresh ───────────────────────────────────────────────────────

/**
 * Fire-and-forget background refresh of a stale cache entry.
 * Any error is isolated — a failed refresh never affects an in-flight request.
 */
async function refreshPolicyCacheInBackground(orgId: string): Promise<void> {
  try {
    const fresh = await fetchPolicyFromDB(orgId);
    await writePolicyToCache(orgId, fresh);
    logger.debug("Policy cache refreshed in background", { orgId });
  } catch (err) {
    logger.warn("Background policy cache refresh failed", {
      orgId,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

// ─── Policy Loading — Stale-While-Revalidate ──────────────────────────────────

/**
 * Loads a policy for an org with a stale-while-revalidate caching strategy:
 *
 *   FRESH HIT    (age < SOFT_TTL)  → return cached policy immediately
 *   STALE HIT    (age ≥ SOFT_TTL)  → return stale policy + refresh in background
 *   NEGATIVE HIT (policy is null)  → return null (no DB hit for NEGATIVE_TTL)
 *   CACHE MISS                     → fetch from DB synchronously, populate cache
 *
 * This means most requests pay zero DB latency. The stale window is at most
 * SOFT_TTL_MS (60 s) on the critical path, and HARD_TTL_S (5 min) maximum
 * for background-refreshed entries.
 */
export async function loadPolicy(orgId: string): Promise<Policy | null> {
  const cacheKey = CacheKeys.policy(orgId);

  // ── 1. Cache Lookup ────────────────────────────────────────────────────────
  const envelope = await getCachedEnvelope<Policy>(cacheKey);

  if (envelope !== null) {
    const ageMs = Date.now() - envelope.cachedAt;
    const isStale = ageMs >= POLICY_SOFT_TTL_MS;

    if (isStale) {
      // Serve stale data immediately; refresh asynchronously
      logger.debug("Serving stale policy cache, refreshing in background", {
        orgId,
        ageMs,
      });
      void refreshPolicyCacheInBackground(orgId);
    } else {
      logger.debug("Policy cache hit (fresh)", { orgId, ageMs });
    }

    // Negative cache hit: org has no policy configured
    if (envelope.isNull) return null;
    return envelope.data;
  }

  // ── 2. Cache Miss — Synchronous DB Fetch ──────────────────────────────────
  logger.debug("Policy cache miss, fetching from DB", { orgId });

  const policy = await fetchPolicyFromDB(orgId);
  void writePolicyToCache(orgId, policy); // Write asynchronously — don't block response

  return policy;
}

// ─── Cache Invalidation ───────────────────────────────────────────────────────

/**
 * Invalidates the Redis cache for an org's policy.
 * Call this from the policy API route after any write (POST, DELETE).
 */
export async function invalidatePolicyCache(orgId: string): Promise<void> {
  await invalidate(CacheKeys.policy(orgId));
  logger.debug("Policy cache invalidated", { orgId });
}

/**
 * Immediately writes a known-good policy into the cache.
 * Call this after a successful DB write to avoid the next request incurring
 * a cache-miss round trip.
 *
 * @param orgId   The organization's ID
 * @param policy  The policy that was just written to DB (pass null on DELETE)
 */
export async function warmPolicyCache(
  orgId: string,
  policy: Policy | null
): Promise<void> {
  await writePolicyToCache(orgId, policy);
  logger.debug("Policy cache warmed", { orgId, isNull: policy === null });
}

// ─── Policy Evaluation ────────────────────────────────────────────────────────

export interface PolicyEvaluationResult {
  /** Overall allowed/denied decision from policy */
  allowed: boolean;
  /** All evaluator results for transparency */
  results: PolicyResult[];
  /** The first blocking reason, or an aggregated summary */
  reason: string;
}

/**
 * Runs all deterministic policy evaluators against a request.
 * Short-circuits on the first denial.
 */
export function evaluatePolicy(
  request: CheckRequest,
  policy: Policy
): PolicyEvaluationResult {
  const results: PolicyResult[] = [];

  const evaluators: PolicyResult[] = [
    evaluateToolAccess(request.tool, policy),
    evaluateSpendLimit(request.args, policy),
    evaluateDomainTrust(request.args, policy),
    evaluateActionPermission(request.action, policy),
  ];

  for (const result of evaluators) {
    results.push(result);
    if (!result.allowed) {
      return {
        allowed: false,
        results,
        reason: result.reason,
      };
    }
  }

  const sensitiveNote = results.find(
    (r) => r.evaluator === "action_permission" && r.reason.includes("sensitive")
  );

  return {
    allowed: true,
    results,
    reason: sensitiveNote?.reason ?? "All policy checks passed",
  };
}

/**
 * Returns a default permissive policy when no policy is configured.
 * This allows all tools and actions but still runs the risk engine.
 */
export function getDefaultPolicy(): Policy {
  const now = new Date().toISOString();
  return {
    id: "00000000-0000-0000-0000-000000000000",
    org_id: "00000000-0000-0000-0000-000000000000",
    allowed_tools: [],
    blocked_actions: [],
    trusted_domains: [],
    max_spend_usd: null,
    sensitive_actions: ["payment", "transfer", "delete", "withdraw", "send"],
    risk_threshold_allow: 0.3,
    risk_threshold_sandbox: 0.6,
    risk_threshold_deny: 0.8,
    created_at: now,
    updated_at: now,
  };
}
