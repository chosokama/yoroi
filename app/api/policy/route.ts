import { NextResponse } from "next/server";
import { extractApiKey, validateApiKey } from "@/lib/security/api-key";
import {
  parseRequestBody,
  unauthorizedResponse,
  internalErrorResponse,
} from "@/lib/security/validation";
import {
  loadPolicy,
  invalidatePolicyCache,
  warmPolicyCache,
} from "@/lib/policy-engine";
import { getSupabaseServer } from "@/lib/supabase/server";
import { CreatePolicySchema } from "@/types";
import type { Policy } from "@/types";

export const runtime = "nodejs";

// ─── GET /api/policy ─────────────────────────────────────────────────────────

export async function GET(request: Request): Promise<NextResponse> {
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) return unauthorizedResponse();

  // Read through the policy cache (Redis → Supabase fallback)
  // This avoids a direct DB hit on every dashboard page load.
  const policy = await loadPolicy(validatedKey.orgId);
  return NextResponse.json({ policy });
}

// ─── POST /api/policy ────────────────────────────────────────────────────────

export async function POST(request: Request): Promise<NextResponse> {
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) return unauthorizedResponse();

  const { data: body, error: parseError } = await parseRequestBody(
    request,
    CreatePolicySchema
  );
  if (parseError) return parseError;

  const supabase = getSupabaseServer();

  // Upsert: one policy per org (replace existing)
  const { data: existing } = await supabase
    .from("policies")
    .select("id")
    .eq("org_id", validatedKey.orgId)
    .order("created_at", { ascending: false })
    .limit(1)
    .single();

  let result;
  if (existing) {
    result = await supabase
      .from("policies")
      .update({ ...body, updated_at: new Date().toISOString() })
      .eq("id", existing.id)
      .select()
      .single();
  } else {
    result = await supabase
      .from("policies")
      .insert({ ...body, org_id: validatedKey.orgId })
      .select()
      .single();
  }

  if (result.error || !result.data) {
    return internalErrorResponse("Failed to save policy");
  }

  const savedPolicy = result.data as Policy;

  // Warm the cache with the new policy immediately so the next check request
  // gets a fresh cache hit instead of a miss.
  await invalidatePolicyCache(validatedKey.orgId);
  void warmPolicyCache(validatedKey.orgId, savedPolicy);

  return NextResponse.json(
    { policy: savedPolicy },
    { status: existing ? 200 : 201 }
  );
}

// ─── DELETE /api/policy ───────────────────────────────────────────────────────

export async function DELETE(request: Request): Promise<NextResponse> {
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) return unauthorizedResponse();

  const supabase = getSupabaseServer();
  const { error } = await supabase
    .from("policies")
    .delete()
    .eq("org_id", validatedKey.orgId);

  if (error) return internalErrorResponse("Failed to delete policy");

  // Invalidate cache and write a null sentinel so the next request doesn't hit DB
  await invalidatePolicyCache(validatedKey.orgId);
  void warmPolicyCache(validatedKey.orgId, null);

  return NextResponse.json({ success: true });
}
