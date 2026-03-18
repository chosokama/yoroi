import { createClient } from "@supabase/supabase-js";
import type { SupabaseClient } from "@supabase/supabase-js";
import type {
  DecisionType,
  GuardrailThreat,
  RiskLevel,
  SourceType,
} from "@/types";

type ApiKeyRow = {
  id: string;
  org_id: string;
  key_hash: string;
  label: string;
  created_at: string;
};

type PolicyRow = {
  id: string;
  org_id: string;
  allowed_tools: string[];
  blocked_actions: string[];
  trusted_domains: string[];
  max_spend_usd: number | null;
  sensitive_actions: string[];
  risk_threshold_allow: number;
  risk_threshold_sandbox: number;
  risk_threshold_deny: number;
  created_at: string;
  updated_at: string;
};

type ToolRow = {
  tool_id: string;
  publisher: string;
  permissions: string[];
  risk_level: RiskLevel;
  schema_hash: string | null;
  description: string | null;
  created_at: string;
};

type ActionRow = {
  action_id: string;
  agent_id: string;
  tool: string;
  action: string;
  args: Record<string, unknown>;
  risk_score: number;
  decision: DecisionType;
  reason: string;
  source: SourceType;
  org_id: string | null;
  timestamp: string;
  threat_count: number;
  threats: GuardrailThreat[];
};

type Database = {
  public: {
    Tables: {
      api_keys: {
        Row: ApiKeyRow;
        Insert: ApiKeyRow;
        Update: Partial<ApiKeyRow>;
      };
      policies: {
        Row: PolicyRow;
        Insert: PolicyRow;
        Update: Partial<PolicyRow>;
      };
      tools: {
        Row: ToolRow;
        Insert: ToolRow;
        Update: Partial<ToolRow>;
      };
      actions: {
        Row: ActionRow;
        Insert: ActionRow;
        Update: Partial<ActionRow>;
      };
    };
  };
};

let cached: SupabaseClient<Database> | null = null;

function getEnv(key: string): string {
  // Keep this as a helper so module import never crashes builds.
  const v = process.env[key];
  if (!v || typeof v !== "string") {
    throw new Error(
      `Missing environment variable: ${key}. Set it for the server runtime (not client).`,
    );
  }
  return v;
}

export function getSupabaseServer() {
  if (cached) return cached;

  const url = getEnv("SUPABASE_URL");
  const serviceKey = getEnv("SUPABASE_SERVICE_KEY");

  cached = createClient<Database>(url, serviceKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  return cached;
}

