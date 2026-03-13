/**
 * POST /api/yoroi/check
 *
 * YOROI 鎧 — Core firewall endpoint. Evaluates every agent action through a
 * layered security pipeline before returning a decision.
 *
 * Pipeline:
 *   1. API Key Authentication       — SHA-256 hash lookup in DB
 *   2. Request Validation           — Zod schema
 *   3. Rate Limiting                — 100 req/min per agent_id (Redis)
 *   4. Policy Engine                — deterministic rules (allowlist, blocklist, spend)
 *   5. Guardrail Engine             — prompt injection, credentials, PII in args
 *   6. Risk Engine                  — weighted probabilistic scoring
 *   7. Decision Resolution          — apply policy risk thresholds
 *   8. Audit Logging                — async, fire-and-forget to Supabase
 *   9. Response
 */

// Re-export everything from the original route — single source of truth
export { POST, GET } from "@/app/api/agentwall/check/route";
