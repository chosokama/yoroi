/**
 * Prompt Injection Detector
 *
 * Detects attempts to override agent instructions, hijack agent identity,
 * perform data extraction attacks, or embed indirect injection payloads
 * inside tool arguments or user intent strings.
 *
 * Uses a layered pattern library:
 *   1. Instruction Override  — "ignore previous instructions", "forget everything"
 *   2. Jailbreak             — DAN, unrestricted mode, persona hijacking
 *   3. Data Extraction       — "reveal your system prompt", "print your instructions"
 *   4. Indirect Injection    — Base64-decoded content, XML/HTML comment tricks
 *   5. Intent Contradiction  — action/tool contains dangerous keyword absent from intent
 */

import { normalizeContent } from "./deep-inspector";
import type { GuardrailThreat, ScannerResult, ThreatType, ThreatSeverity } from "./types";
import { redactSnippet } from "./types";

// ─── Pattern Libraries ────────────────────────────────────────────────────────

interface InjectionPattern {
  pattern: RegExp;
  type: ThreatType;
  severity: ThreatSeverity;
  label: string;
}

/**
 * Instruction override patterns — direct commands to ignore/replace instructions.
 * Severity is CRITICAL: these are the clearest signal of a prompt injection attack.
 */
const INSTRUCTION_OVERRIDE_PATTERNS: InjectionPattern[] = [
  {
    pattern: /ignore\s+(all\s+)?previous\s+(instructions?|prompts?|rules?|context)/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: ignore previous instructions",
  },
  {
    pattern: /disregard\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|prompts?|rules?|guidelines?)/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: disregard instructions",
  },
  {
    pattern: /forget\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|context|rules?|training)/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: forget instructions",
  },
  {
    pattern: /override\s+(your\s+)?(previous\s+)?(instructions?|rules?|directives?|guidelines?)/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: override instructions",
  },
  {
    pattern: /new\s+(system\s+)?instructions?\s*:/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: new instructions block",
  },
  {
    pattern: /\[system\s*prompt\]/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: system prompt injection marker",
  },
  {
    pattern: /\[new\s+instructions?\]/i,
    type: "instruction_override", severity: "critical",
    label: "Instruction override: new instructions marker",
  },
  {
    pattern: /your\s+(real|true|actual|hidden)\s+(task|instructions?|purpose|goal|objective)/i,
    type: "instruction_override", severity: "high",
    label: "Instruction override: 'your real task' framing",
  },
  {
    pattern: /from\s+now\s+on\s*(,\s*)?(you|act|behave|respond|ignore)/i,
    type: "instruction_override", severity: "high",
    label: "Instruction override: 'from now on' directive",
  },
  {
    pattern: /stop\s+(being|acting\s+as|following)\s+(an?\s+)?(AI|assistant|agent|model|bot)/i,
    type: "instruction_override", severity: "high",
    label: "Instruction override: stop being AI directive",
  },
];

/**
 * Jailbreak patterns — attempts to bypass safety constraints.
 * Severity is HIGH: ambiguous framing, could be legitimate in some contexts.
 */
const JAILBREAK_PATTERNS: InjectionPattern[] = [
  {
    pattern: /\bDAN\b.*?(mode|prompt|jailbreak)/i,
    type: "jailbreak", severity: "critical",
    label: "Jailbreak: DAN (Do Anything Now) mode",
  },
  {
    pattern: /jailbreak\s*(mode|prompt|this|yourself)?/i,
    type: "jailbreak", severity: "critical",
    label: "Jailbreak: explicit jailbreak request",
  },
  {
    pattern: /no\s+(safety|ethical|moral|content|restrictions?)\s*(filter|constraint|limitation|guardrail)/i,
    type: "jailbreak", severity: "high",
    label: "Jailbreak: request to disable safety filters",
  },
  {
    pattern: /act\s+as\s+(an?\s+)?(AI|model|assistant|bot|agent)\s+(without|with\s+no)\s+(restrictions?|constraints?|limitations?|rules?|ethics?)/i,
    type: "jailbreak", severity: "critical",
    label: "Jailbreak: act as unrestricted AI",
  },
  {
    pattern: /pretend\s+(you\s+)?(are|have\s+no)\s+(restrictions?|constraints?|ethics?|morals?|guidelines?)/i,
    type: "jailbreak", severity: "high",
    label: "Jailbreak: pretend no restrictions",
  },
  {
    pattern: /developer\s+mode\s*(enabled|on|activated|unlocked)/i,
    type: "jailbreak", severity: "high",
    label: "Jailbreak: developer mode activation",
  },
  {
    pattern: /\[JAILBREAK\]|\[BYPASS\]|\[OVERRIDE\]|\[ADMIN\]|\[ROOT\]/i,
    type: "jailbreak", severity: "critical",
    label: "Jailbreak: injection marker tag",
  },
  {
    pattern: /you\s+are\s+now\s+(a|an)\s+/i,
    type: "jailbreak", severity: "high",
    label: "Jailbreak: persona hijack via 'you are now a'",
  },
  {
    pattern: /simulate\s+(a\s+)?(scenario|mode|AI|model|system)\s+(where|in\s+which|that)\s+(you\s+)?(can|have\s+no|ignore)/i,
    type: "jailbreak", severity: "high",
    label: "Jailbreak: simulate unrestricted scenario",
  },
  {
    pattern: /hypothetically\s*(,\s*if\s+you\s+(could|had\s+no|were\s+not)|speaking)/i,
    type: "jailbreak", severity: "medium",
    label: "Jailbreak: hypothetical framing to bypass constraints",
  },
  {
    pattern: /in\s+this\s+(fictional|hypothetical|imaginary|fantasy|roleplay)\s+(scenario|world|context|setting)\s*,?\s*(you|the\s+AI|the\s+assistant)\s+(can|must|will|should|has\s+to)/i,
    type: "jailbreak", severity: "medium",
    label: "Jailbreak: fictional framing to elicit harmful output",
  },
  {
    pattern: /bypass\s+(your\s+)?(safety|security|ethical|moral|content|guardrail)/i,
    type: "jailbreak", severity: "critical",
    label: "Jailbreak: explicit bypass request",
  },
];

/**
 * Data extraction / prompt exfiltration patterns.
 * Attackers embed these in tool content to steal system prompts.
 */
const DATA_EXTRACTION_PATTERNS: InjectionPattern[] = [
  {
    pattern: /reveal\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|context|training|rules?)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: reveal system prompt",
  },
  {
    pattern: /print\s+(out\s+)?(your\s+)?(system\s+prompt|instructions?|context|initial\s+prompt)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: print system prompt",
  },
  {
    pattern: /show\s+(me\s+)?(your\s+)?(system\s+prompt|full\s+prompt|complete\s+instructions?|initial\s+context)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: show system prompt",
  },
  {
    pattern: /output\s+(your\s+)?(complete\s+)?(system\s+prompt|full\s+context|all\s+instructions?|initialization)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: output full context",
  },
  {
    pattern: /repeat\s+(back\s+)?(your\s+)?(exact\s+)?(system\s+prompt|instructions?|prompt|training\s+data)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: repeat system prompt",
  },
  {
    pattern: /what\s+(are|is)\s+your\s+(exact\s+)?(system\s+prompt|instructions?|rules?|guidelines?|programming)/i,
    type: "data_extraction", severity: "high",
    label: "Data extraction: query system prompt",
  },
  {
    pattern: /leak\s+(your\s+)?(system\s+prompt|context|instructions?|training)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: explicit leak request",
  },
  {
    pattern: /exfiltrate\s+(the\s+)?(context|data|content|memory|prompt|credentials?)/i,
    type: "data_extraction", severity: "critical",
    label: "Data extraction: exfiltrate request",
  },
];

/**
 * Indirect injection patterns — content that looks like injected directives
 * embedded within web pages, documents, or tool outputs.
 */
const INDIRECT_INJECTION_PATTERNS: InjectionPattern[] = [
  // HTML/XML injection of instructions
  {
    pattern: /<\s*instructions?\s*>[\s\S]*?<\/\s*instructions?\s*>/i,
    type: "indirect_injection", severity: "high",
    label: "Indirect injection: HTML <instructions> tag",
  },
  {
    pattern: /<\s*system\s*>[\s\S]*?<\/\s*system\s*>/i,
    type: "indirect_injection", severity: "high",
    label: "Indirect injection: HTML <system> tag",
  },
  {
    pattern: /<!--\s*(instructions?|system|prompt|override|ignore|forget|act\s+as)/i,
    type: "indirect_injection", severity: "high",
    label: "Indirect injection: HTML comment instruction",
  },
  // Markdown-style hidden instructions
  {
    pattern: /```\s*system[\s\S]*?```/i,
    type: "indirect_injection", severity: "high",
    label: "Indirect injection: system block in markdown",
  },
  // Note: Base64 is handled by detectBase64Injection — only flags when decoded content contains injection
  // JSON injection inside string values
  {
    pattern: /"\s*:\s*"[^"]*\\n[^"]*ignore\s+previous/i,
    type: "indirect_injection", severity: "critical",
    label: "Indirect injection: JSON-embedded instruction override",
  },
  // Tool-poisoning: instructions embedded in tool-like content (e.g. description, args)
  {
    pattern: /when\s+(this\s+)?(tool\s+)?(is\s+)?(called|invoked|executed)\s*,?\s*(ignore|override|forget|disregard)/i,
    type: "indirect_injection", severity: "critical",
    label: "Tool poisoning: conditional instruction override on tool invocation",
  },
  {
    pattern: /upon\s+(tool\s+)?(invocation|execution|call)\s*,?\s*(ignore|override|forget|execute)/i,
    type: "indirect_injection", severity: "critical",
    label: "Tool poisoning: instruction on tool invocation",
  },
  {
    pattern: /execute\s+(the\s+)?(following|below)\s+(instructions?|commands?|prompt)/i,
    type: "indirect_injection", severity: "high",
    label: "Indirect injection: execute following instructions",
  },
  // Markdown code block with system/instruction content
  {
    pattern: /```\s*(?:system|instructions?|prompt|override)[\s\S]*?```/i,
    type: "indirect_injection", severity: "high",
    label: "Indirect injection: markdown code block with instruction content",
  },
  // Unicode/homoglyph obfuscation markers
  {
    pattern: /[\u200B-\u200F\u202A-\u202E\uFEFF]/,
    type: "indirect_injection", severity: "medium",
    label: "Indirect injection: zero-width / control character detected",
  },
];

// ─── Base64 Deep Check ───────────────────────────────────────────────────────

/**
 * Checks if a base64 string decodes to content containing injection patterns.
 * Only triggers for strings long enough to be meaningful.
 */
function detectBase64Injection(value: string, path: string): GuardrailThreat[] {
  const threats: GuardrailThreat[] = [];
  const b64Regex = /\b([A-Za-z0-9+/]{40,}={0,2})\b/g;
  let match: RegExpExecArray | null;

  while ((match = b64Regex.exec(value)) !== null) {
    try {
      const decoded = Buffer.from(match[1]!, "base64").toString("utf-8");
      // Check if the decoded content looks like text (not binary)
      if (/^[\x20-\x7E\n\r\t]{10,}$/.test(decoded)) {
        const injectionScan = scanStringForInjection(decoded, `${path}[base64_decoded]`);
        threats.push(...injectionScan);
      }
    } catch {
      // Not valid base64 — ignore
    }
  }

  return threats;
}

// ─── Unicode Normalization (anti-homoglyph) ────────────────────────────────────

/**
 * Normalizes string for scanning to reduce homoglyph/obfuscation bypasses.
 * - NFKC normalization collapses lookalike Unicode to canonical form
 * - Strips zero-width and bidirectional override characters
 */
function normalizeForScan(value: string): string {
  const nfkc = value.normalize("NFKC");
  return nfkc.replace(/[\u200B-\u200F\u202A-\u202E\uFEFF]/g, "");
}

// ─── Core Scanner ─────────────────────────────────────────────────────────────

/**
 * Scans a single string for all injection pattern categories.
 */
function scanStringForInjection(value: string, path: string): GuardrailThreat[] {
  const threats: GuardrailThreat[] = [];
  const allPatterns = [
    ...INSTRUCTION_OVERRIDE_PATTERNS,
    ...JAILBREAK_PATTERNS,
    ...DATA_EXTRACTION_PATTERNS,
    ...INDIRECT_INJECTION_PATTERNS,
  ];

  // Normalize to catch homoglyph/Unicode obfuscation
  const toScan = normalizeForScan(value);

  for (const { pattern, type, severity, label } of allPatterns) {
    const match = pattern.exec(toScan);
    if (match) {
      threats.push({
        type,
        severity,
        field: path,
        detail: label,
        snippet: redactSnippet(match[0]),
      });
    }
  }

  return threats;
}

// ─── Public Interface ─────────────────────────────────────────────────────────

/**
 * Scans all string fields in the provided content for prompt injection.
 * Also recursively checks base64-encoded values.
 */
export function scanForPromptInjection(
  content: string | Record<string, unknown>,
  extraStrings?: Array<{ path: string; value: string }>
): ScannerResult {
  const threats: GuardrailThreat[] = [];
  const fields = normalizeContent(
    typeof content === "string" ? content : content
  );

  const allFields = [...fields, ...(extraStrings ?? [])];

  for (const { path, value } of allFields) {
    threats.push(...scanStringForInjection(value, path));
    // Check if value contains base64 that decodes to injection
    threats.push(...detectBase64Injection(value, path));
  }

  // Deduplicate by (field + detail)
  const seen = new Set<string>();
  const deduped = threats.filter((t) => {
    const key = `${t.field}::${t.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { scanner: "prompt_injection", threats: deduped };
}

/**
 * Quick check: does a single string contain any injection pattern?
 * Useful for fast pre-checks on user_intent.
 */
export function containsInjectionPattern(text: string): boolean {
  const allPatterns = [
    ...INSTRUCTION_OVERRIDE_PATTERNS,
    ...JAILBREAK_PATTERNS,
    ...DATA_EXTRACTION_PATTERNS,
  ];
  return allPatterns.some((p) => p.pattern.test(text));
}
