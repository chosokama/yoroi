import { z } from "zod";

// ─── Decision Types ─────────────────────────────────────────────────────────

export const DecisionTypeSchema = z.enum([
  "allow",
  "deny",
  "require_confirmation",
  "sandbox",
]);
export type DecisionType = z.infer<typeof DecisionTypeSchema>;

// ─── Source Provenance ───────────────────────────────────────────────────────

export const SourceTypeSchema = z.enum([
  "system",
  "developer",
  "user",
  "memory",
  "tool",
  "web",
  "external",
]);
export type SourceType = z.infer<typeof SourceTypeSchema>;

// ─── Check Request / Response ────────────────────────────────────────────────

export const CheckRequestSchema = z.object({
  agent_id: z.string().min(1).max(128),
  action: z.string().min(1).max(256),
  tool: z.string().min(1).max(128),
  args: z.record(z.unknown()).default({}),
  source: SourceTypeSchema.default("external"),
  user_intent: z.string().max(1024).optional(),
});
export type CheckRequest = z.infer<typeof CheckRequestSchema>;

export const CheckResponseSchema = z.object({
  decision: DecisionTypeSchema,
  risk_score: z.number().min(0).max(1),
  reason: z.string(),
  action_id: z.string().optional(),
});
export type CheckResponse = z.infer<typeof CheckResponseSchema>;

// ─── Policy ──────────────────────────────────────────────────────────────────

export const PolicySchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  allowed_tools: z.array(z.string()).default([]),
  blocked_actions: z.array(z.string()).default([]),
  trusted_domains: z.array(z.string()).default([]),
  max_spend_usd: z.number().min(0).nullable().default(null),
  sensitive_actions: z.array(z.string()).default([]),
  risk_threshold_allow: z.number().min(0).max(1).default(0.3),
  risk_threshold_sandbox: z.number().min(0).max(1).default(0.6),
  risk_threshold_deny: z.number().min(0).max(1).default(0.8),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
});
export type Policy = z.infer<typeof PolicySchema>;

export const CreatePolicySchema = PolicySchema.omit({
  id: true,
  org_id: true,
  created_at: true,
  updated_at: true,
});
export type CreatePolicy = z.infer<typeof CreatePolicySchema>;

// ─── Tool ────────────────────────────────────────────────────────────────────

export const RiskLevelSchema = z.enum(["low", "medium", "high", "critical"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const ToolSchema = z.object({
  tool_id: z.string().min(1).max(128),
  publisher: z.string().min(1).max(256),
  permissions: z.array(z.string()).default([]),
  risk_level: RiskLevelSchema.default("medium"),
  schema_hash: z.string().nullable().default(null),
  description: z.string().max(1024).nullable().default(null),
  created_at: z.string().datetime(),
});
export type Tool = z.infer<typeof ToolSchema>;

export const RegisterToolSchema = ToolSchema.omit({
  created_at: true,
});
export type RegisterTool = z.infer<typeof RegisterToolSchema>;

// ─── Action Log ──────────────────────────────────────────────────────────────

export const ActionLogSchema = z.object({
  action_id: z.string().uuid(),
  agent_id: z.string(),
  tool: z.string(),
  action: z.string(),
  args: z.record(z.unknown()),
  risk_score: z.number().min(0).max(1),
  decision: DecisionTypeSchema,
  reason: z.string(),
  source: SourceTypeSchema,
  org_id: z.string().uuid().nullable(),
  timestamp: z.string().datetime(),
});
export type ActionLog = z.infer<typeof ActionLogSchema>;

// ─── Organization ────────────────────────────────────────────────────────────

export const OrganizationSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(256),
  created_at: z.string().datetime(),
});
export type Organization = z.infer<typeof OrganizationSchema>;

// ─── API Key ─────────────────────────────────────────────────────────────────

export const ApiKeySchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  key_hash: z.string(),
  label: z.string().max(128),
  created_at: z.string().datetime(),
});
export type ApiKey = z.infer<typeof ApiKeySchema>;

// ─── Policy Evaluation Result ────────────────────────────────────────────────

export const PolicyResultSchema = z.object({
  allowed: z.boolean(),
  reason: z.string(),
  evaluator: z.string(),
});
export type PolicyResult = z.infer<typeof PolicyResultSchema>;

// ─── Log Query Filters ───────────────────────────────────────────────────────

export const LogFiltersSchema = z.object({
  agent_id: z.string().optional(),
  decision: DecisionTypeSchema.optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(100).default(50),
  offset: z.coerce.number().min(0).default(0),
});
export type LogFilters = z.infer<typeof LogFiltersSchema>;

// ─── Dashboard Stats ─────────────────────────────────────────────────────────

export interface DashboardStats {
  total_checks: number;
  allow_count: number;
  deny_count: number;
  require_confirmation_count: number;
  sandbox_count: number;
  avg_risk_score: number;
  high_risk_alerts: number;
}

// ─── Guardrail Engine Types ───────────────────────────────────────────────────

export const ThreatSeveritySchema = z.enum(["low", "medium", "high", "critical"]);
export type ThreatSeverity = z.infer<typeof ThreatSeveritySchema>;

export const ThreatTypeSchema = z.enum([
  "prompt_injection",
  "jailbreak",
  "instruction_override",
  "data_extraction",
  "credential_leak",
  "pii_exposure",
  "content_policy",
  "schema_mismatch",
  "indirect_injection",
]);
export type ThreatType = z.infer<typeof ThreatTypeSchema>;

export const GuardrailThreatSchema = z.object({
  type: ThreatTypeSchema,
  severity: ThreatSeveritySchema,
  field: z.string(),
  detail: z.string(),
  snippet: z.string().optional(),
});
export type GuardrailThreat = z.infer<typeof GuardrailThreatSchema>;

export const ScanContentTypeSchema = z.enum([
  "tool_output",
  "llm_response",
  "user_input",
  "agent_args",
]);
export type ScanContentType = z.infer<typeof ScanContentTypeSchema>;

export const ScanRequestSchema = z.object({
  agent_id: z.string().min(1).max(128),
  content: z.union([z.string().max(65536), z.record(z.unknown())]),
  content_type: ScanContentTypeSchema,
  source: SourceTypeSchema.default("external"),
});
export type ScanRequest = z.infer<typeof ScanRequestSchema>;

export const ScanResponseSchema = z.object({
  safe: z.boolean(),
  threats: z.array(GuardrailThreatSchema),
  risk_score: z.number().min(0).max(1),
  action: z.enum(["allow", "deny", "sanitize"]),
  sanitized_content: z.string().optional(),
});
export type ScanResponse = z.infer<typeof ScanResponseSchema>;

// ─── Enhanced Action Log (with guardrail fields) ──────────────────────────────

export const ActionLogWithGuardrailSchema = ActionLogSchema.extend({
  threat_count: z.number().default(0),
  threats: z.array(GuardrailThreatSchema).default([]),
});
export type ActionLogWithGuardrail = z.infer<typeof ActionLogWithGuardrailSchema>;

// ─── API Error ───────────────────────────────────────────────────────────────

export interface ApiErrorResponse {
  error: string;
  code: string;
  details?: unknown;
}
