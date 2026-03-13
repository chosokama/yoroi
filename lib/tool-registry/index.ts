import { getCached, setCached, invalidate, CacheKeys } from "@/lib/redis";
import { getSupabaseServer } from "@/lib/supabase/server";
import type { Tool, RegisterTool } from "@/types";

const TOOL_CACHE_TTL = 300; // 5 minutes

// ─── Get Tool ─────────────────────────────────────────────────────────────────

/**
 * Fetches a single tool by ID.
 * Checks Redis cache first, falls back to Supabase.
 */
export async function getTool(toolId: string): Promise<Tool | null> {
  const cacheKey = CacheKeys.tool(toolId);

  const cached = await getCached<Tool>(cacheKey);
  if (cached) return cached;

  const supabase = getSupabaseServer();
  const { data, error } = await supabase
    .from("tools")
    .select("*")
    .eq("tool_id", toolId)
    .single();

  if (error || !data) return null;

  const tool = data as Tool;
  await setCached(cacheKey, tool, TOOL_CACHE_TTL);

  return tool;
}

// ─── List Tools ───────────────────────────────────────────────────────────────

/**
 * Lists all registered tools.
 * Results are cached for 5 minutes.
 */
export async function listTools(): Promise<Tool[]> {
  const cacheKey = CacheKeys.toolList();

  const cached = await getCached<Tool[]>(cacheKey);
  if (cached) return cached;

  const supabase = getSupabaseServer();
  const { data, error } = await supabase
    .from("tools")
    .select("*")
    .order("created_at", { ascending: false });

  if (error || !data) return [];

  const tools = data as Tool[];
  await setCached(cacheKey, tools, TOOL_CACHE_TTL);

  return tools;
}

// ─── Register Tool ────────────────────────────────────────────────────────────

/**
 * Registers a new tool or updates an existing one (upsert by tool_id).
 * Invalidates all relevant caches.
 */
export async function registerTool(
  tool: RegisterTool
): Promise<{ tool: Tool; isNew: boolean }> {
  const supabase = getSupabaseServer();

  // Check if tool exists
  const { data: existing } = await supabase
    .from("tools")
    .select("tool_id")
    .eq("tool_id", tool.tool_id)
    .single();

  const isNew = !existing;

  const { data, error } = await supabase
    .from("tools")
    .upsert(
      { ...tool, created_at: isNew ? new Date().toISOString() : undefined },
      { onConflict: "tool_id" }
    )
    .select()
    .single();

  if (error || !data) {
    throw new Error(`Failed to register tool: ${error?.message ?? "Unknown error"}`);
  }

  const registered = data as Tool;

  // Invalidate caches
  await Promise.all([
    invalidate(CacheKeys.tool(tool.tool_id)),
    invalidate(CacheKeys.toolList()),
  ]);

  return { tool: registered, isNew };
}
