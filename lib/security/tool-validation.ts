/**
 * Tool Registration Validation
 *
 * Scans tool metadata (description, permissions, publisher) for prompt injection
 * and tool-poisoning payloads before persisting to the registry.
 */

import { validateToolId } from "@/lib/security/input-hardening";
import { scanForPromptInjection } from "@/lib/guardrail-engine/prompt-injection";

export interface ToolValidationResult {
  valid: boolean;
  error?: string;
  threats?: Array<{ type: string; detail: string }>;
}

/** Input shape for tool registration validation */
interface ToolRegistrationInput {
  tool_id: string;
  publisher?: string;
  permissions?: string[];
  description?: string | null;
}

/**
 * Validates a tool registration payload for injection/poisoning.
 * Rejects if tool_id, description, permissions, or publisher contain malicious patterns.
 */
export function validateToolRegistration(tool: ToolRegistrationInput): ToolValidationResult {
  const idCheck = validateToolId(tool.tool_id);
  if (!idCheck.valid) {
    return { valid: false, error: idCheck.error };
  }
  const fieldsToScan: Array<{ path: string; value: string }> = [];

  if (tool.description && tool.description.trim().length > 0) {
    fieldsToScan.push({ path: "description", value: tool.description });
  }
  if (tool.publisher && tool.publisher.trim().length > 0) {
    fieldsToScan.push({ path: "publisher", value: tool.publisher });
  }
  for (let i = 0; i < (tool.permissions ?? []).length; i++) {
    const p = tool.permissions![i];
    if (typeof p === "string" && p.trim().length > 0) {
      fieldsToScan.push({ path: `permissions[${i}]`, value: p });
    }
  }

  if (fieldsToScan.length === 0) {
    return { valid: true };
  }

  const result = scanForPromptInjection({}, fieldsToScan);

  if (result.threats.length > 0) {
    const critical = result.threats.filter((t) => t.severity === "critical");
    const high = result.threats.filter((t) => t.severity === "high");

    if (critical.length > 0) {
      return {
        valid: false,
        error: `Tool registration contains prohibited content: ${critical[0]!.detail}`,
        threats: result.threats.map((t) => ({ type: t.type, detail: t.detail })),
      };
    }
    if (high.length > 0) {
      return {
        valid: false,
        error: `Tool registration contains suspicious content: ${high[0]!.detail}`,
        threats: result.threats.map((t) => ({ type: t.type, detail: t.detail })),
      };
    }
  }

  return { valid: true };
}
