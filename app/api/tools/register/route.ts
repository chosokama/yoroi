import { NextResponse } from "next/server";
import { extractApiKey, validateApiKey } from "@/lib/security/api-key";
import {
  parseRequestBody,
  unauthorizedResponse,
  internalErrorResponse,
  badRequestResponse,
} from "@/lib/security/validation";
import { validateToolRegistration } from "@/lib/security/tool-validation";
import { registerTool } from "@/lib/tool-registry";
import { RegisterToolSchema } from "@/types";

export const runtime = "nodejs";

// ─── POST /api/tools/register ─────────────────────────────────────────────────

export async function POST(request: Request): Promise<NextResponse> {
  const rawKey = extractApiKey(request);
  const validatedKey = await validateApiKey(rawKey);
  if (!validatedKey) return unauthorizedResponse();

  const { data: body, error: parseError } = await parseRequestBody(
    request,
    RegisterToolSchema
  );
  if (parseError) return parseError;

  const toolValidation = validateToolRegistration(body);
  if (!toolValidation.valid) {
    return badRequestResponse(toolValidation.error ?? "Invalid tool registration");
  }

  try {
    const { tool, isNew } = await registerTool({
      tool_id: body.tool_id,
      publisher: body.publisher,
      permissions: body.permissions ?? [],
      risk_level: body.risk_level ?? "medium",
      schema_hash: body.schema_hash ?? null,
      description: body.description ?? null,
    });
    return NextResponse.json({ tool, created: isNew }, { status: isNew ? 201 : 200 });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to register tool";
    return internalErrorResponse(message);
  }
}
