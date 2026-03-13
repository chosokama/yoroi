import { Redis } from "@upstash/redis";

let _redis: Redis | null = null;

function getRedis(): Redis {
  if (_redis) return _redis;

  const url = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;

  if (!url || !token) {
    throw new Error(
      "Missing Redis environment variables: UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN are required."
    );
  }

  _redis = new Redis({ url, token });
  return _redis;
}

// ─── Cache Helpers ───────────────────────────────────────────────────────────

/**
 * Retrieves a cached value. Returns null on miss or error.
 */
export async function getCached<T>(key: string): Promise<T | null> {
  try {
    const value = await getRedis().get<T>(key);
    return value ?? null;
  } catch {
    return null;
  }
}

/**
 * Stores a value with an optional TTL in seconds (default: 60s).
 */
export async function setCached<T>(
  key: string,
  value: T,
  ttlSeconds = 60
): Promise<void> {
  try {
    await getRedis().set(key, value, { ex: ttlSeconds });
  } catch {
    // Cache writes are best-effort; log silently
  }
}

/**
 * Deletes a cached key.
 */
export async function invalidate(key: string): Promise<void> {
  try {
    await getRedis().del(key);
  } catch {
    // Best-effort
  }
}

// ─── Rate Limiting ───────────────────────────────────────────────────────────

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number; // Unix timestamp (seconds)
}

/**
 * Sliding-window rate limiter using Redis.
 * @param key     Unique key (e.g. `ratelimit:agent:${agent_id}`)
 * @param limit   Maximum requests allowed in the window
 * @param windowSeconds  Window duration in seconds
 */
export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  const redis = getRedis();
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const windowStart = now - windowMs;

  try {
    const pipeline = redis.pipeline();
    // Remove entries outside the window
    pipeline.zremrangebyscore(key, 0, windowStart);
    // Add current request
    pipeline.zadd(key, { score: now, member: `${now}-${Math.random()}` });
    // Count requests in window
    pipeline.zcard(key);
    // Set TTL so the key auto-expires
    pipeline.expire(key, windowSeconds * 2);

    const results = await pipeline.exec();
    const count = (results[2] as number) ?? 0;
    const allowed = count <= limit;
    const remaining = Math.max(0, limit - count);
    const resetAt = Math.ceil((now + windowMs) / 1000);

    return { allowed, remaining, resetAt };
  } catch {
    // On Redis failure, allow the request (fail open) to avoid blocking
    return { allowed: true, remaining: limit, resetAt: 0 };
  }
}

// ─── Envelope Cache (stores metadata alongside value) ─────────────────────────

/**
 * Cache envelope that wraps any stored value with metadata.
 * Storing `cachedAt` inside the value avoids a separate Redis TTL command
 * and enables stale-while-revalidate without extra round trips.
 */
export interface CacheEnvelope<T> {
  /** Schema version — allows cache entries to be invalidated on shape changes */
  v: 1;
  /** Unix timestamp (ms) when this entry was written */
  cachedAt: number;
  /** True when this is a negative-cache entry (value was null/not found) */
  isNull: boolean;
  /** The cached value, or null for negative-cache entries */
  data: T | null;
}

/**
 * Writes a value as a cache envelope with full metadata.
 * @param softTtlMs  When `Date.now() - cachedAt > softTtlMs`, callers should
 *                   treat the entry as stale and trigger a background refresh.
 *                   The Redis key itself lives for `hardTtlSeconds`.
 */
export async function setCachedEnvelope<T>(
  key: string,
  data: T | null,
  hardTtlSeconds: number
): Promise<void> {
  const envelope: CacheEnvelope<T> = {
    v: 1,
    cachedAt: Date.now(),
    isNull: data === null,
    data,
  };
  await setCached(key, envelope, hardTtlSeconds);
}

/**
 * Retrieves a cache envelope. Returns null on miss, parse error, or version mismatch.
 */
export async function getCachedEnvelope<T>(
  key: string
): Promise<CacheEnvelope<T> | null> {
  const raw = await getCached<CacheEnvelope<T>>(key);
  if (!raw || raw.v !== 1) return null;
  return raw;
}

// ─── Cache Key Builders ──────────────────────────────────────────────────────

export const CacheKeys = {
  policy: (orgId: string) => `yoroi:policy:v1:${orgId}`,
  tool: (toolId: string) => `yoroi:tool:${toolId}`,
  toolList: () => `yoroi:tools:all`,
  rateLimit: (agentId: string) => `yoroi:ratelimit:${agentId}`,
} as const;
