-- AgentWall Initial Database Migration
-- Run this in Supabase SQL editor or via migration tool

-- ─── Extensions ─────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Organizations ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name        TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── API Keys ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key_hash    TEXT NOT NULL UNIQUE,   -- SHA-256 hash of the raw key; raw key never stored
  label       TEXT NOT NULL DEFAULT 'default',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org_id   ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash  ON api_keys(key_hash);

-- ─── Policies ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policies (
  id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  allowed_tools           TEXT[]   NOT NULL DEFAULT '{}',
  blocked_actions         TEXT[]   NOT NULL DEFAULT '{}',
  trusted_domains         TEXT[]   NOT NULL DEFAULT '{}',
  max_spend_usd           NUMERIC(18,2),
  sensitive_actions       TEXT[]   NOT NULL DEFAULT '{}',
  risk_threshold_allow    NUMERIC(4,3) NOT NULL DEFAULT 0.3,
  risk_threshold_sandbox  NUMERIC(4,3) NOT NULL DEFAULT 0.6,
  risk_threshold_deny     NUMERIC(4,3) NOT NULL DEFAULT 0.8,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_threshold_order
    CHECK (risk_threshold_allow <= risk_threshold_sandbox
       AND risk_threshold_sandbox <= risk_threshold_deny)
);

CREATE INDEX IF NOT EXISTS idx_policies_org_id ON policies(org_id);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_policies_updated_at
  BEFORE UPDATE ON policies
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ─── Tool Registry ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tools (
  tool_id      TEXT PRIMARY KEY,
  publisher    TEXT NOT NULL,
  permissions  TEXT[]   NOT NULL DEFAULT '{}',
  risk_level   TEXT     NOT NULL DEFAULT 'medium'
                 CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  schema_hash  TEXT,
  description  TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tools_risk_level ON tools(risk_level);

-- ─── Action Logs ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS actions (
  action_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id    TEXT         NOT NULL,
  tool        TEXT         NOT NULL,
  action      TEXT         NOT NULL,
  args        JSONB        NOT NULL DEFAULT '{}',
  risk_score  NUMERIC(5,4) NOT NULL,
  decision    TEXT         NOT NULL
                CHECK (decision IN ('allow', 'deny', 'require_confirmation', 'sandbox')),
  reason      TEXT         NOT NULL,
  source      TEXT         NOT NULL
                CHECK (source IN ('system','developer','user','memory','tool','web','external')),
  org_id      UUID REFERENCES organizations(id) ON DELETE SET NULL,
  timestamp   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_actions_agent_id  ON actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_actions_decision  ON actions(decision);
CREATE INDEX IF NOT EXISTS idx_actions_org_id    ON actions(org_id);
CREATE INDEX IF NOT EXISTS idx_actions_risk_score ON actions(risk_score DESC);

-- ─── Row Level Security (Supabase) ──────────────────────────────────────────
-- Service role bypasses RLS; enable for user-facing access if needed

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys      ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies      ENABLE ROW LEVEL SECURITY;
ALTER TABLE tools         ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions       ENABLE ROW LEVEL SECURITY;

-- Default: service role only (no anon/user policies defined here)
-- Add user-facing policies as needed when Supabase Auth is wired up
