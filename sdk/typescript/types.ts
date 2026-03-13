// YOROI TypeScript SDK — Public Type Definitions

export type DecisionType = "allow" | "deny" | "require_confirmation" | "sandbox";

export type SourceType =
  | "system"
  | "developer"
  | "user"
  | "memory"
  | "tool"
  | "web"
  | "external";

export type RiskLevel = "low" | "medium" | "high" | "critical";

// ─── SDK Request Types ────────────────────────────────────────────────────────

export interface SDKCheckRequest {
  /** Unique identifier for the agent making the request */
  agent_id: string;
  /** The action the agent wants to perform */
  action: string;
  /** The tool the agent wants to use */
  tool: string;
  /** Arguments for the action */
  args?: Record<string, unknown>;
  /** Origin of the request (defaults to "external") */
  source?: SourceType;
  /** High-level user intent (used for intent mismatch detection) */
  user_intent?: string;
}

export interface SDKCheckResponse {
  /** The firewall decision */
  decision: DecisionType;
  /** Risk score between 0 (safe) and 1 (dangerous) */
  risk_score: number;
  /** Human-readable reason for the decision */
  reason: string;
  /** Unique ID of the logged action */
  action_id?: string;
}

export interface SDKRegisterToolRequest {
  tool_id: string;
  publisher: string;
  permissions?: string[];
  risk_level?: RiskLevel;
  description?: string;
  schema_hash?: string;
}

export interface SDKLogFilters {
  agent_id?: string;
  decision?: DecisionType;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export interface SDKActionLog {
  action_id: string;
  agent_id: string;
  tool: string;
  action: string;
  args: Record<string, unknown>;
  risk_score: number;
  decision: DecisionType;
  reason: string;
  source: SourceType;
  timestamp: string;
}

export interface YoroiConfig {
  /** Your YOROI API key */
  apiKey: string;
  /** Base URL of your YOROI deployment (default: http://localhost:3000) */
  baseUrl?: string;
  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;
}

/** @deprecated Use YoroiConfig */
export type AgentWallConfig = YoroiConfig;

// ─── SDK Error ────────────────────────────────────────────────────────────────

export class YoroiSDKError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(message: string, statusCode: number, code: string) {
    super(message);
    this.name = "YoroiSDKError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

/** @deprecated Use YoroiSDKError */
export const AgentWallSDKError = YoroiSDKError;
