import { NextResponse } from "next/server";
import { extractApiKey, validateApiKey } from "@/lib/security/api-key";
import { unauthorizedResponse, internalErrorResponse } from "@/lib/security/validation";
import { listTools } from "@/lib/tool-registry";

export const runtime = "nodejs";

// ─── GET /api/tools ───────────────────────────────────────────────────────────

export async function GET(request: Request): Promise<NextResponse> {
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) return unauthorizedResponse();

  try {
    const tools = await listTools();
    return NextResponse.json({ tools, total: tools.length });
  } catch {
    return internalErrorResponse("Failed to fetch tools");
  }
}
