import { createHash } from "crypto";
import { getSupabaseServer } from "@/lib/supabase/server";

/**
 * Hashes an API key using SHA-256.
 * Raw keys are never stored in the database.
 */
export function hashApiKey(rawKey: string): string {
  return createHash("sha256").update(rawKey).digest("hex");
}

export interface ValidatedKey {
  orgId: string;
  keyId: string;
  label: string;
}

/**
 * Validates an API key from the request header against the database.
 * Returns the org context on success, or null on failure.
 */
export async function validateApiKey(
  rawKey: string | null | undefined
): Promise<ValidatedKey | null> {
  if (!rawKey || typeof rawKey !== "string" || rawKey.trim().length === 0) {
    return null;
  }

  const keyHash = hashApiKey(rawKey.trim());

  const supabase = getSupabaseServer();
  const { data, error } = await supabase
    .from("api_keys")
    .select("id, org_id, label")
    .eq("key_hash", keyHash)
    .single();

  if (error || !data) return null;

  // Supabase client typing for this repo is intentionally lightweight (no generated DB types).
  // Cast the row into the shape we query.
  const row = data as unknown as { org_id: string; id: string; label: string };

  return {
    orgId: row.org_id,
    keyId: row.id,
    label: row.label,
  };
}

/**
 * Extracts the API key from an incoming Next.js request.
 * Checks the `x-api-key` header.
 */
export function extractApiKey(request: Request): string | null {
  return request.headers.get("x-api-key");
}

/**
 * Generates a new random API key (raw, for one-time display to the user).
 * Format: `aw_` prefix + 40 random hex chars.
 */
export function generateApiKey(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `aw_${hex}`;
}
