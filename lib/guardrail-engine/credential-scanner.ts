/**
 * Credential Scanner
 *
 * Scans string VALUES (not just key names) for real secret/credential patterns.
 * The existing risk-engine/scorers.ts only checks arg KEY names like "password",
 * "api_key", etc. This scanner looks at the actual content for known formats:
 *
 * - AWS Access/Secret keys
 * - OpenAI API keys
 * - GitHub Personal Access Tokens / App tokens
 * - JWT tokens
 * - SSH / PGP / RSA private keys
 * - Stripe live keys
 * - Google API keys
 * - Slack tokens
 * - Twilio auth tokens
 * - Generic high-entropy strings (likely secrets)
 * - Hex-encoded 256-bit+ secrets
 */

import { normalizeContent } from "./deep-inspector";
import type { GuardrailThreat, ScannerResult, ThreatSeverity } from "./types";
import { redactSnippet } from "./types";

// ─── Credential Pattern Library ───────────────────────────────────────────────

interface CredentialPattern {
  name: string;
  pattern: RegExp;
  severity: ThreatSeverity;
  /** If true, run Luhn or entropy check to reduce false positives */
  requiresValidation?: boolean;
}

const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    name: "AWS Access Key ID",
    pattern: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/,
    severity: "critical",
  },
  {
    // AWS Secret Access Keys are 40 chars, base64-like — require context
    name: "AWS Secret Access Key",
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/,
    severity: "high",
    requiresValidation: true, // Too generic without context; flag as high not critical
  },

  // ── OpenAI ────────────────────────────────────────────────────────────────
  {
    name: "OpenAI API Key (legacy sk-)",
    pattern: /\bsk-[a-zA-Z0-9]{48}\b/,
    severity: "critical",
  },
  {
    name: "OpenAI API Key (project key)",
    pattern: /\bsk-proj-[a-zA-Z0-9_-]{80,120}\b/,
    severity: "critical",
  },

  // ── Anthropic ─────────────────────────────────────────────────────────────
  {
    name: "Anthropic API Key",
    pattern: /\bsk-ant-[a-zA-Z0-9_-]{80,120}\b/,
    severity: "critical",
  },

  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    name: "GitHub Personal Access Token (classic)",
    pattern: /\bghp_[a-zA-Z0-9]{36,255}\b/,
    severity: "critical",
  },
  {
    name: "GitHub OAuth Token",
    pattern: /\bgho_[a-zA-Z0-9]{36,255}\b/,
    severity: "critical",
  },
  {
    name: "GitHub App Installation Token",
    pattern: /\bghs_[a-zA-Z0-9]{36,255}\b/,
    severity: "critical",
  },
  {
    name: "GitHub Refresh Token",
    pattern: /\bghr_[a-zA-Z0-9]{36,255}\b/,
    severity: "critical",
  },
  {
    name: "GitHub Fine-Grained PAT",
    pattern: /\bgithub_pat_[a-zA-Z0-9_]{82,255}\b/,
    severity: "critical",
  },

  // ── JWT ───────────────────────────────────────────────────────────────────
  {
    name: "JWT Token",
    pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/,
    severity: "high",
  },

  // ── SSH / PGP / TLS Private Keys ─────────────────────────────────────────
  {
    name: "RSA Private Key",
    pattern: /-----BEGIN RSA PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "EC Private Key",
    pattern: /-----BEGIN EC PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "OpenSSH Private Key",
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "DSA Private Key",
    pattern: /-----BEGIN DSA PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "PGP Private Key",
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: "critical",
  },
  {
    name: "Generic Private Key",
    pattern: /-----BEGIN PRIVATE KEY-----/,
    severity: "critical",
  },

  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    name: "Stripe Live Secret Key",
    pattern: /\bsk_live_[0-9a-zA-Z]{24,99}\b/,
    severity: "critical",
  },
  {
    name: "Stripe Restricted Key",
    pattern: /\brk_live_[0-9a-zA-Z]{24,99}\b/,
    severity: "critical",
  },
  {
    name: "Stripe Test Secret Key",
    pattern: /\bsk_test_[0-9a-zA-Z]{24,99}\b/,
    severity: "medium",
  },

  // ── Google ────────────────────────────────────────────────────────────────
  {
    name: "Google API Key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: "critical",
  },
  {
    name: "Google OAuth Client Secret",
    pattern: /\bGOCSPS[0-9A-Za-z_-]{20,}\b/,
    severity: "critical",
  },

  // ── Slack ─────────────────────────────────────────────────────────────────
  {
    name: "Slack Bot Token",
    pattern: /\bxoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}\b/,
    severity: "critical",
  },
  {
    name: "Slack User Token",
    pattern: /\bxoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{32}\b/,
    severity: "critical",
  },
  {
    name: "Slack App-Level Token",
    pattern: /\bxapp-[0-9]-[a-zA-Z0-9]{10,}\b/,
    severity: "critical",
  },
  {
    name: "Slack Webhook",
    pattern: /hooks\.slack\.com\/services\/T[a-zA-Z0-9]+\/B[a-zA-Z0-9]+\/[a-zA-Z0-9]+/,
    severity: "critical",
  },

  // ── Twilio ────────────────────────────────────────────────────────────────
  {
    name: "Twilio Account SID",
    pattern: /\bAC[a-f0-9]{32}\b/,
    severity: "high",
  },
  {
    name: "Twilio Auth Token",
    pattern: /\b[a-f0-9]{32}\b/,
    severity: "medium",
    requiresValidation: true,
  },

  // ── SendGrid ──────────────────────────────────────────────────────────────
  {
    name: "SendGrid API Key",
    pattern: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/,
    severity: "critical",
  },

  // ── Solana ────────────────────────────────────────────────────────────────
  {
    name: "Solana Private Key (base58)",
    // Solana private keys are 64-byte, typically 87-88 chars in base58
    pattern: /\b[1-9A-HJ-NP-Za-km-z]{87,88}\b/,
    severity: "critical",
    requiresValidation: true,
  },

  // ── Ethereum ──────────────────────────────────────────────────────────────
  {
    name: "Ethereum Private Key",
    pattern: /\b0x[a-fA-F0-9]{64}\b/,
    severity: "critical",
  },
  {
    name: "Ethereum Mnemonic Phrase",
    pattern:
      /\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address)\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\b/i,
    severity: "critical",
  },

  // ── Generic High-Entropy / Hex Secrets ───────────────────────────────────
  {
    // 32-byte hex = 64 chars — common for tokens/secrets
    name: "32-byte hex secret",
    pattern: /\b[a-f0-9]{64}\b/i,
    severity: "high",
    requiresValidation: true,
  },
  {
    // Longer hex strings
    name: "64-byte hex secret",
    pattern: /\b[a-f0-9]{128}\b/i,
    severity: "high",
  },

  // ── Database Connection Strings ───────────────────────────────────────────
  {
    name: "PostgreSQL connection string",
    pattern: /postgresql?:\/\/[^:]+:[^@]+@[^/]+\/\S+/i,
    severity: "critical",
  },
  {
    name: "MySQL connection string",
    pattern: /mysql:\/\/[^:]+:[^@]+@[^/]+\/\S+/i,
    severity: "critical",
  },
  {
    name: "MongoDB connection string",
    pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@\S+/i,
    severity: "critical",
  },
  {
    name: "Redis URL with password",
    pattern: /redis:\/\/:[^@]+@\S+/i,
    severity: "high",
  },
];

// ─── Entropy Check ────────────────────────────────────────────────────────────

/**
 * Computes the Shannon entropy of a string.
 * High-entropy strings (>4.5 bits/char) are likely secrets or encoded data.
 */
function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const c of str) {
    freq[c] = (freq[c] ?? 0) + 1;
  }
  return Object.values(freq).reduce((entropy, count) => {
    const p = count / str.length;
    return entropy - p * Math.log2(p);
  }, 0);
}

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_ENTROPY_STRING_LENGTH = 20;

/**
 * Detects standalone high-entropy strings that are likely secrets.
 * These don't match any specific pattern but are suspicious by entropy alone.
 */
function detectHighEntropyStrings(value: string, path: string): GuardrailThreat[] {
  const threats: GuardrailThreat[] = [];
  // Split on whitespace to inspect individual tokens
  const tokens = value.split(/\s+/);

  for (const token of tokens) {
    // Only check tokens of suspicious length (likely secret vs. natural language)
    if (token.length >= MIN_ENTROPY_STRING_LENGTH && token.length <= 256) {
      // Skip URLs and other common non-secret patterns
      if (/^https?:\/\//.test(token)) continue;
      if (/^\d+$/.test(token)) continue; // Pure numbers

      const entropy = shannonEntropy(token);
      if (entropy >= HIGH_ENTROPY_THRESHOLD) {
        threats.push({
          type: "credential_leak",
          severity: "medium",
          field: path,
          detail: `High-entropy string detected (entropy: ${entropy.toFixed(2)}) — possible secret token`,
          snippet: redactSnippet(token.slice(0, 12) + "…"),
        });
        break; // One warning per field is enough
      }
    }
  }

  return threats;
}

// ─── Public Interface ─────────────────────────────────────────────────────────

/**
 * Scans all string values in the provided content for credential/secret patterns.
 */
export function scanForCredentials(
  content: string | Record<string, unknown>
): ScannerResult {
  const threats: GuardrailThreat[] = [];
  const fields = normalizeContent(content);

  for (const { path, value } of fields) {
    // Run all credential patterns
    for (const { name, pattern, severity, requiresValidation } of CREDENTIAL_PATTERNS) {
      const match = pattern.exec(value);
      if (!match) continue;

      // For patterns that require additional validation, check entropy
      if (requiresValidation) {
        const entropy = shannonEntropy(match[0]);
        if (entropy < HIGH_ENTROPY_THRESHOLD) continue;
      }

      threats.push({
        type: "credential_leak",
        severity,
        field: path,
        detail: `${name} detected in field value`,
        snippet: redactSnippet(match[0].slice(0, 8) + "…[redacted]"),
      });
    }

    // Run entropy check on longer strings
    if (value.length >= MIN_ENTROPY_STRING_LENGTH) {
      threats.push(...detectHighEntropyStrings(value, path));
    }
  }

  // Deduplicate (same field + same credential name)
  const seen = new Set<string>();
  const deduped = threats.filter((t) => {
    const key = `${t.field}::${t.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity: critical first
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  deduped.sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3));

  return { scanner: "credential_scanner", threats: deduped };
}

/**
 * Quick check: does a string appear to contain any credential?
 */
export function containsCredential(text: string): boolean {
  return CREDENTIAL_PATTERNS.some((p) => p.pattern.test(text));
}
