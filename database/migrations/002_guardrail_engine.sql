-- AgentWall — Guardrail Engine Migration
-- Adds guardrail-related columns to the actions table and creates scan_logs.
-- Run after 001_initial.sql

-- ─── Add Guardrail Columns to Actions ────────────────────────────────────────

ALTER TABLE actions
  ADD COLUMN IF NOT EXISTS threat_count   INTEGER     NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS threats        JSONB       NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_actions_threat_count
  ON actions(threat_count DESC)
  WHERE threat_count > 0;

-- ─── Scan Logs (Tool Output / LLM Response Scanning) ─────────────────────────

CREATE TABLE IF NOT EXISTS scan_logs (
  scan_id       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id      TEXT         NOT NULL,
  content_type  TEXT         NOT NULL
                  CHECK (content_type IN ('tool_output', 'llm_response', 'user_input', 'agent_args')),
  source        TEXT         NOT NULL DEFAULT 'external',
  risk_score    NUMERIC(5,4) NOT NULL,
  action        TEXT         NOT NULL
                  CHECK (action IN ('allow', 'deny', 'sanitize')),
  threat_count  INTEGER      NOT NULL DEFAULT 0,
  org_id        UUID REFERENCES organizations(id) ON DELETE SET NULL,
  timestamp     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_agent_id  ON scan_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_scan_logs_timestamp ON scan_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scan_logs_action    ON scan_logs(action);
CREATE INDEX IF NOT EXISTS idx_scan_logs_org_id    ON scan_logs(org_id);

ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

-- ─── Guardrail Stats View ─────────────────────────────────────────────────────
-- Pre-built view for the dashboard overview page

CREATE OR REPLACE VIEW guardrail_stats AS
SELECT
  org_id,
  COUNT(*)                          AS total_checks,
  SUM(threat_count)                 AS total_threats,
  SUM(CASE WHEN threat_count > 0 THEN 1 ELSE 0 END) AS checks_with_threats,
  AVG(risk_score)                   AS avg_risk_score,
  SUM(CASE WHEN decision = 'deny' AND threat_count > 0 THEN 1 ELSE 0 END) AS guardrail_denials
FROM actions
GROUP BY org_id;
