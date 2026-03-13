import { NextResponse } from "next/server";
import { extractApiKey, validateApiKey } from "@/lib/security/api-key";
import {
  parseQueryParams,
  unauthorizedResponse,
  internalErrorResponse,
} from "@/lib/security/validation";
import { getSupabaseServer } from "@/lib/supabase/server";
import { LogFiltersSchema } from "@/types";
import type { ActionLog } from "@/types";

export const runtime = "nodejs";

// ─── GET /api/logs ────────────────────────────────────────────────────────────

export async function GET(request: Request): Promise<NextResponse> {
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) return unauthorizedResponse();

  const url = new URL(request.url);
  const { data: filters, error: parseError } = parseQueryParams(
    url.searchParams,
    LogFiltersSchema
  );
  if (parseError) return parseError;

  const supabase = getSupabaseServer();

  const limit = filters.limit ?? 50;
  const offset = filters.offset ?? 0;

  let query = supabase
    .from("actions")
    .select("*", { count: "exact" })
    .eq("org_id", validatedKey.orgId)
    .order("timestamp", { ascending: false })
    .range(offset, offset + limit - 1);

  if (filters.agent_id) {
    query = query.eq("agent_id", filters.agent_id);
  }

  if (filters.decision) {
    query = query.eq("decision", filters.decision);
  }

  if (filters.from) {
    query = query.gte("timestamp", filters.from);
  }

  if (filters.to) {
    query = query.lte("timestamp", filters.to);
  }

  const { data, error, count } = await query;

  if (error) {
    return internalErrorResponse("Failed to fetch logs");
  }

  return NextResponse.json({
    logs: (data ?? []) as ActionLog[],
    total: count ?? 0,
    limit,
    offset,
  });
}
