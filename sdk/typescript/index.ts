/**
 * YOROI 鎧 TypeScript SDK
 * Agent Security Firewall — full-stack protection for your AI agents.
 *
 * Usage:
 *   import { Yoroi } from "./sdk/typescript"
 *
 *   const wall = new Yoroi({ apiKey: process.env.YOROI_API_KEY })
 *   const result = await wall.check({ agent_id: "agent-1", action: "transfer", tool: "wallet", args: { amount: 100 } })
 *   if (result.decision !== "allow") throw new Error(`Blocked: ${result.reason}`)
 */

import {
  YoroiConfig,
  YoroiSDKError,
  SDKCheckRequest,
  SDKCheckResponse,
  SDKRegisterToolRequest,
  SDKLogFilters,
  SDKActionLog,
} from "./types";

export { YoroiSDKError, AgentWallSDKError } from "./types";
export type {
  YoroiConfig,
  SDKCheckRequest,
  SDKCheckResponse,
  SDKRegisterToolRequest,
  SDKLogFilters,
  SDKActionLog,
  DecisionType,
  SourceType,
  RiskLevel,
} from "./types";

const DEFAULT_BASE_URL = "http://localhost:3000";
const DEFAULT_TIMEOUT = 10_000;

export class Yoroi {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: YoroiConfig) {
    if (!config.apiKey || config.apiKey.trim().length === 0) {
      throw new YoroiSDKError(
        "YOROI requires an apiKey. Get one from your YOROI dashboard.",
        0,
        "MISSING_API_KEY"
      );
    }

    this.apiKey = config.apiKey.trim();
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
  }

  // ─── check() ─────────────────────────────────────────────────────────────────

  /**
   * Evaluates an agent action against your security policy and risk engine.
   *
   * @param request - The action to evaluate
   * @returns A decision with risk score and reason
   * @throws YoroiSDKError on API errors
   *
   * @example
   * const result = await wall.check({
   *   agent_id: "agent-001",
   *   action: "transfer",
   *   tool: "solana_wallet",
   *   args: { amount: 100, to: "0xabc..." },
   *   source: "user",
   *   user_intent: "Send 100 SOL to Alice",
   * })
   *
   * if (result.decision === "deny") {
   *   throw new Error(`Action denied: ${result.reason}`)
   * }
   */
  async check(request: SDKCheckRequest): Promise<SDKCheckResponse> {
    const body = {
      agent_id: request.agent_id,
      action: request.action,
      tool: request.tool,
      args: request.args ?? {},
      source: request.source ?? "external",
      user_intent: request.user_intent,
    };

    return this.post<SDKCheckResponse>("/api/yoroi/check", body);
  }

  // ─── registerTool() ──────────────────────────────────────────────────────────

  /**
   * Registers a tool in the YOROI tool registry.
   * Registered tools receive their configured risk level instead of "unknown tool" penalty.
   *
   * @example
   * await wall.registerTool({
   *   tool_id: "solana_wallet",
   *   publisher: "my-company",
   *   risk_level: "high",
   *   permissions: ["sign_transaction", "transfer"],
   * })
   */
  async registerTool(tool: SDKRegisterToolRequest): Promise<void> {
    await this.post("/api/tools/register", {
      tool_id: tool.tool_id,
      publisher: tool.publisher,
      permissions: tool.permissions ?? [],
      risk_level: tool.risk_level ?? "medium",
      description: tool.description ?? null,
      schema_hash: tool.schema_hash ?? null,
    });
  }

  // ─── getLogs() ───────────────────────────────────────────────────────────────

  /**
   * Fetches paginated action logs from your YOROI deployment.
   *
   * @example
   * const logs = await wall.getLogs({ decision: "deny", limit: 20 })
   */
  async getLogs(filters?: SDKLogFilters): Promise<SDKActionLog[]> {
    const params = new URLSearchParams();
    if (filters?.agent_id) params.set("agent_id", filters.agent_id);
    if (filters?.decision) params.set("decision", filters.decision);
    if (filters?.from) params.set("from", filters.from);
    if (filters?.to) params.set("to", filters.to);
    if (filters?.limit) params.set("limit", String(filters.limit));
    if (filters?.offset) params.set("offset", String(filters.offset));

    const qs = params.toString();
    const path = `/api/logs${qs ? `?${qs}` : ""}`;

    const result = await this.get<{ logs: SDKActionLog[] }>(path);
    return result.logs;
  }

  // ─── Internal HTTP Helpers ───────────────────────────────────────────────────

  private async post<T>(path: string, body: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.apiKey,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      return this.handleResponse<T>(response);
    } catch (err) {
      if (err instanceof YoroiSDKError) throw err;
      const message = err instanceof Error ? err.message : "Network error";
      throw new YoroiSDKError(
        `YOROI request failed: ${message}`,
        0,
        "NETWORK_ERROR"
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async get<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "GET",
        headers: {
          "x-api-key": this.apiKey,
        },
        signal: controller.signal,
      });

      return this.handleResponse<T>(response);
    } catch (err) {
      if (err instanceof YoroiSDKError) throw err;
      const message = err instanceof Error ? err.message : "Network error";
      throw new YoroiSDKError(
        `YOROI request failed: ${message}`,
        0,
        "NETWORK_ERROR"
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    if (response.ok) {
      return response.json() as Promise<T>;
    }

    let errorBody: { error?: string; code?: string } = {};
    try {
      errorBody = (await response.json()) as typeof errorBody;
    } catch {
      // Non-JSON error body
    }

    throw new YoroiSDKError(
      errorBody.error ?? `HTTP ${response.status}`,
      response.status,
      errorBody.code ?? "HTTP_ERROR"
    );
  }
}

/** @deprecated Use Yoroi */
export const AgentWall = Yoroi;
