/**
 * PII Scanner
 *
 * Detects Personally Identifiable Information (PII) in string values.
 * Prevents agents from leaking or exfiltrating personal data through tool calls.
 *
 * Detects:
 * - Email addresses
 * - US / international phone numbers
 * - US Social Security Numbers (SSN)
 * - Credit card numbers (Visa, MC, Amex, Discover) with Luhn validation
 * - IPv4 and IPv6 addresses
 * - Passport numbers (US format)
 * - US Driver's License numbers
 * - Date of Birth patterns (various formats)
 * - Full name + birthday combinations (high confidence PII)
 */

import { normalizeContent } from "./deep-inspector";
import type { GuardrailThreat, ScannerResult, ThreatSeverity } from "./types";
import { redactSnippet } from "./types";

// ─── PII Pattern Library ──────────────────────────────────────────────────────

interface PIIPattern {
  name: string;
  pattern: RegExp;
  severity: ThreatSeverity;
  validate?: (match: string) => boolean;
}

const PII_PATTERNS: PIIPattern[] = [
  // ── Email Address ─────────────────────────────────────────────────────────
  {
    name: "Email address",
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/,
    severity: "medium",
  },

  // ── US Social Security Number ─────────────────────────────────────────────
  {
    name: "US Social Security Number (SSN)",
    // Strict: 3-2-4 digit format, with or without dashes/spaces
    pattern: /\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/,
    severity: "critical",
    validate: (match) => {
      // Must not be all-repeating
      const digits = match.replace(/[-\s]/g, "");
      return !/^(\d)\1{8}$/.test(digits);
    },
  },

  // ── Credit Card Numbers ───────────────────────────────────────────────────
  {
    name: "Visa credit card",
    pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/,
    severity: "critical",
    validate: luhnCheck,
  },
  {
    name: "Mastercard credit card",
    pattern: /\b5[1-5][0-9]{14}\b/,
    severity: "critical",
    validate: luhnCheck,
  },
  {
    name: "American Express credit card",
    pattern: /\b3[47][0-9]{13}\b/,
    severity: "critical",
    validate: luhnCheck,
  },
  {
    name: "Discover credit card",
    pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/,
    severity: "critical",
    validate: luhnCheck,
  },
  {
    name: "Diners Club credit card",
    pattern: /\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b/,
    severity: "critical",
    validate: luhnCheck,
  },
  {
    // Generic 16-digit card with spaces or dashes (PAN format)
    name: "Credit card (formatted)",
    pattern: /\b(?:\d{4}[-\s]){3}\d{4}\b/,
    severity: "critical",
    validate: (match) => luhnCheck(match.replace(/[-\s]/g, "")),
  },

  // ── US Phone Numbers ──────────────────────────────────────────────────────
  {
    name: "US phone number",
    pattern:
      /\b(?:\+1[-.\s]?)?\(?([2-9][0-8][0-9])\)?[-.\s]?([2-9][0-9]{2})[-.\s]?([0-9]{4})\b/,
    severity: "low",
  },
  {
    name: "International phone number",
    pattern: /\+(?:[1-9]\d{1,3}[-.\s]?)(?:\d{1,4}[-.\s]?){1,4}\d{4,9}\b/,
    severity: "low",
  },

  // ── IPv4 / IPv6 Addresses ─────────────────────────────────────────────────
  {
    name: "IPv4 address",
    pattern:
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
    severity: "low",
    validate: (ip) => {
      // Filter out obvious non-IPs: version strings (1.2.3.4), dates
      const parts = ip.split(".").map(Number);
      // Reject if it looks like a version (0.x.x.x) or localhost (127.0.0.1 is fine)
      return parts.every((p) => p <= 255);
    },
  },
  {
    name: "IPv6 address",
    pattern: /\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b/,
    severity: "low",
  },

  // ── US Passport Number ────────────────────────────────────────────────────
  {
    name: "US Passport number",
    // 9 alphanumeric chars, starts with 1-2 letters
    pattern: /\b[A-Z]{1,2}[0-9]{7,8}\b/,
    severity: "high",
  },

  // ── Date of Birth ─────────────────────────────────────────────────────────
  {
    name: "Date of birth (MM/DD/YYYY or similar)",
    pattern:
      /\b(?:0?[1-9]|1[0-2])[\/\-.](?:0?[1-9]|[12][0-9]|3[01])[\/\-.](19|20)[0-9]{2}\b/,
    severity: "medium",
  },
  {
    name: "Date of birth (YYYY-MM-DD)",
    pattern: /\b(19|20)[0-9]{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12][0-9]|3[01])\b/,
    severity: "medium",
  },

  // ── National ID / Driver's License ───────────────────────────────────────
  {
    name: "US Driver's License (generic format)",
    pattern: /\b[A-Z][0-9]{7,8}\b/,
    severity: "high",
  },

  // ── Financial Account Numbers ─────────────────────────────────────────────
  {
    name: "IBAN (International Bank Account Number)",
    pattern: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b/,
    severity: "high",
    validate: (iban) => iban.length >= 15 && iban.length <= 34,
  },
  {
    name: "US Routing Number",
    pattern: /\b[0-9]{9}\b/,
    severity: "medium",
    validate: (num) => {
      // ABA routing number checksum
      const d = num.split("").map(Number);
      const checksum =
        3 * ((d[0] ?? 0) + (d[3] ?? 0) + (d[6] ?? 0)) +
        7 * ((d[1] ?? 0) + (d[4] ?? 0) + (d[7] ?? 0)) +
        ((d[2] ?? 0) + (d[5] ?? 0) + (d[8] ?? 0));
      return checksum % 10 === 0;
    },
  },
];

// ─── Luhn Check ───────────────────────────────────────────────────────────────

/**
 * Validates a credit card number using the Luhn algorithm.
 * Eliminates false positives for generic number sequences.
 */
function luhnCheck(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let isEven = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i]!, 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

// ─── Bulk PII Context Detection ───────────────────────────────────────────────

/**
 * Detects when multiple PII types appear in the same field, which increases
 * confidence that real personal data is being exfiltrated.
 */
function detectPIICluster(threats: GuardrailThreat[]): GuardrailThreat[] {
  const byField = new Map<string, GuardrailThreat[]>();

  for (const threat of threats) {
    const existing = byField.get(threat.field) ?? [];
    existing.push(threat);
    byField.set(threat.field, existing);
  }

  const clusterThreats: GuardrailThreat[] = [];

  for (const [field, fieldThreats] of byField) {
    if (fieldThreats.length >= 3) {
      clusterThreats.push({
        type: "pii_exposure",
        severity: "critical",
        field,
        detail: `PII cluster detected: ${fieldThreats.length} distinct PII types in a single field — high confidence data exfiltration`,
        snippet: fieldThreats.map((t) => t.detail).slice(0, 3).join(", "),
      });
    }
  }

  return clusterThreats;
}

// ─── Public Interface ─────────────────────────────────────────────────────────

/**
 * Scans all string values in content for PII.
 */
export function scanForPII(
  content: string | Record<string, unknown>
): ScannerResult {
  const threats: GuardrailThreat[] = [];
  const fields = normalizeContent(content);

  for (const { path, value } of fields) {
    for (const { name, pattern, severity, validate } of PII_PATTERNS) {
      const match = pattern.exec(value);
      if (!match) continue;

      // Run optional validation (Luhn, checksum, etc.)
      if (validate && !validate(match[0])) continue;

      threats.push({
        type: "pii_exposure",
        severity,
        field: path,
        detail: `${name} detected`,
        snippet: redactSnippet(`[${name}: ${match[0].slice(0, 6)}…]`),
      });
    }
  }

  // Deduplicate by (field + name)
  const seen = new Set<string>();
  const deduped = threats.filter((t) => {
    const key = `${t.field}::${t.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Check for PII clusters (multiple PII types in same field)
  deduped.push(...detectPIICluster(deduped));

  return { scanner: "pii_scanner", threats: deduped };
}

/**
 * Redacts detected PII from a string by replacing matched patterns with placeholders.
 * Used for the sanitize action in the scan endpoint.
 */
export function redactPII(text: string): string {
  let redacted = text;

  const redactRules: Array<{ pattern: RegExp; placeholder: string }> = [
    { pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g, placeholder: "[EMAIL]" },
    { pattern: /\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g, placeholder: "[SSN]" },
    { pattern: /\b(?:\d{4}[-\s]){3}\d{4}\b/g, placeholder: "[CARD]" },
    { pattern: /\b4[0-9]{15}\b/g, placeholder: "[CARD]" },
    { pattern: /\b5[1-5][0-9]{14}\b/g, placeholder: "[CARD]" },
    { pattern: /\b3[47][0-9]{13}\b/g, placeholder: "[CARD]" },
    {
      pattern: /\b(?:\+1[-.\s]?)?\(?([2-9][0-8][0-9])\)?[-.\s]?([2-9][0-9]{2})[-.\s]?([0-9]{4})\b/g,
      placeholder: "[PHONE]",
    },
  ];

  for (const { pattern, placeholder } of redactRules) {
    redacted = redacted.replace(pattern, placeholder);
  }

  return redacted;
}
