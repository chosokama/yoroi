import { DocsSidebar } from "@/components/docs/DocsSidebar";

// ─── Reusable doc components ────────────────────────────────────────────────

function Section({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <section id={id} data-section className="scroll-mt-16 py-12 border-b border-[#1a1a1a] last:border-0">
      {children}
    </section>
  );
}

function H2({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="font-display font-black text-white text-2xl uppercase tracking-wide mb-1">{children}</h2>
  );
}

function H3({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="font-bold text-white text-base mt-8 mb-3">{children}</h3>
  );
}

function Lead({ children }: { children: React.ReactNode }) {
  return <p className="text-[#777] text-sm leading-relaxed mt-3 mb-5 max-w-2xl">{children}</p>;
}

function Code({ children, lang = "typescript" }: { children: string; lang?: string }) {
  return (
    <div className="my-4 rounded-xl overflow-hidden border border-[#1e1e1e] bg-[#0a0a0a]">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#1a1a1a]">
        <span className="size-2.5 rounded-full bg-[#ef4444]/50" />
        <span className="size-2.5 rounded-full bg-[#FFC400]/50" />
        <span className="size-2.5 rounded-full bg-[#22c55e]/50" />
        <span className="ml-2 text-[11px] text-[#444] font-mono">{lang}</span>
      </div>
      <pre className="p-5 text-sm text-[#FFC400] font-mono leading-relaxed overflow-x-auto whitespace-pre">{children}</pre>
    </div>
  );
}

function InlineCode({ children }: { children: React.ReactNode }) {
  return <code className="text-[#FFC400] bg-[#FFC400]/10 px-1.5 py-0.5 rounded text-[13px] font-mono">{children}</code>;
}

function Table({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="my-4 rounded-xl overflow-hidden border border-[#1e1e1e] overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="border-b border-[#1e1e1e] bg-[#0a0a0a]">
          <tr>
            {headers.map((h) => (
              <th key={h} className="text-left px-4 py-2.5 text-[11px] font-bold uppercase tracking-wider text-[#555]">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-[#1a1a1a]">
          {rows.map((row, i) => (
            <tr key={i} className="hover:bg-[#0a0a0a]/60 transition-colors">
              {row.map((cell, j) => (
                <td key={j} className={`px-4 py-3 text-sm ${j === 0 ? "font-mono text-[#FFC400] text-[13px]" : "text-[#888]"}`}
                  dangerouslySetInnerHTML={{ __html: cell }} />
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Badge({ color, children }: { color: "gold" | "green" | "red" | "gray"; children: React.ReactNode }) {
  const styles = {
    gold:  "bg-[#FFC400]/15 text-[#FFC400] border-[#FFC400]/30",
    green: "bg-[#22c55e]/15 text-[#22c55e] border-[#22c55e]/30",
    red:   "bg-[#ef4444]/15 text-[#ef4444] border-[#ef4444]/30",
    gray:  "bg-[#888]/15 text-[#888] border-[#888]/30",
  };
  return (
    <span className={`inline-block text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border font-display ${styles[color]}`}>
      {children}
    </span>
  );
}

function Callout({ type = "info", children }: { type?: "info" | "warn" | "danger"; children: React.ReactNode }) {
  const styles = {
    info:   { bg: "bg-[#FFC400]/6 border-[#FFC400]/25", icon: "⚡", text: "text-[#FFC400]" },
    warn:   { bg: "bg-[#f97316]/6 border-[#f97316]/25", icon: "⚠", text: "text-[#f97316]" },
    danger: { bg: "bg-[#ef4444]/6 border-[#ef4444]/25", icon: "✕", text: "text-[#ef4444]" },
  };
  const s = styles[type];
  return (
    <div className={`my-4 border rounded-xl p-4 flex gap-3 ${s.bg}`}>
      <span className={`shrink-0 text-sm font-bold ${s.text}`}>{s.icon}</span>
      <div className="text-sm text-[#999] leading-relaxed">{children}</div>
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function DocsPage() {
  return (
    <div className="flex pt-12 max-w-7xl mx-auto min-h-screen">
      <DocsSidebar />

      <main className="flex-1 px-10 py-8 max-w-3xl">

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="introduction">
          <div className="flex items-start gap-4 mb-4">
            <span className="text-5xl font-black text-[#FFC400] leading-none font-display">壁</span>
            <div>
              <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-display mb-1">YOROI 鎧 Docs v0.1</p>
              <H2>Introduction</H2>
            </div>
          </div>
          <Lead>
            YOROI 鎧 is a production-grade security firewall middleware for AI agents. It sits between your agent and its tools, evaluating every action before execution against configurable policies, risk thresholds, and threat detection guardrails.
          </Lead>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-6">
            {([
              { val: "<10ms", label: "Latency" },
              { val: "8+", label: "Threats" },
              { val: "4", label: "Decisions" },
              { val: "100%", label: "Audit" },
            ] as const).map((s) => (
              <div key={s.label} className="bg-[#0a0a0a] border border-[#1e1e1e] rounded-xl px-4 py-3 text-center">
                <p className="font-display font-black text-lg text-[#FFC400]">{s.val}</p>
                <p className="text-[11px] text-[#555] uppercase tracking-wider mt-0.5 font-sans">{s.label}</p>
              </div>
            ))}
          </div>
          <H3>What it does</H3>
          <ul className="space-y-2 text-sm text-[#888] list-none">
            {[
              "Evaluates every agent tool call against a policy (allowlist, blocklist, spend limits)",
              "Computes a 0–1 risk score across 8 weighted factors per request",
              "Scans arguments recursively for prompt injection, credential leaks, and PII",
              "Returns a decision: allow / deny / sandbox / require_confirmation",
              "Persists every decision to Supabase for full audit trail",
              "Caches policies in Upstash Redis with stale-while-revalidate for <1ms enforcement",
            ].map((item) => (
              <li key={item} className="flex gap-2.5">
                <span className="text-[#FFC400] shrink-0 mt-0.5">→</span>
                {item}
              </li>
            ))}
          </ul>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="architecture">
          <H2>Architecture</H2>
          <Lead>
            YOROI is a stateless Next.js API layer backed by Supabase (Postgres) and Upstash Redis. The request path is fully deterministic — the policy engine and risk engine have no model calls.
          </Lead>
          <Code lang="text">{`
  Agent / SDK
      │
      ▼
  POST /api/yoroi/check
      │
      ├── 1. Auth (SHA-256 API key lookup)
      ├── 2. Rate Limit (Redis sliding window, per agent_id)
      ├── 3. Input Hardening (size, depth, identifier validation)
      ├── 4. Policy Engine  ◀── Redis SWR cache ◀── Supabase
      │       ├── evaluateToolAccess()
      │       ├── evaluateActionPermission()
      │       ├── evaluateDomainTrust()
      │       └── evaluateSpendLimit()
      ├── 5. Risk Engine
      │       └── 8-factor weighted score (0–1)
      ├── 6. Guardrail Engine
      │       ├── Prompt Injection Scanner
      │       ├── Credential Scanner
      │       └── PII Scanner
      └── 7. Decision + Audit Log → Supabase
`.trim()}</Code>
          <H3>Decision Flow</H3>
          <Table
            headers={["Decision", "Trigger", "Action"]}
            rows={[
              ["allow", "Risk < threshold_allow, no policy violation", "Return allow, execute tool"],
              ["require_confirmation", "Risk in [allow, sandbox)", "Return decision, await human confirm"],
              ["sandbox", "Risk in [sandbox, deny)", "Execute in isolated sandbox environment"],
              ["deny", "Risk ≥ threshold_deny OR blocked action OR guardrail critical", "Hard block, log threat"],
            ]}
          />
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="quickstart">
          <H2>Quick Start</H2>
          <Lead>Get YOROI running locally in under 5 minutes.</Lead>

          <H3>1. Clone and install</H3>
          <Code lang="bash">{`git clone https://github.com/your-org/agent-wall
cd agent-wall
npm install`}</Code>

          <H3>2. Environment variables</H3>
          <Code lang="bash">{`cp .env.example .env.local

# Required:
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
UPSTASH_REDIS_REST_URL=https://your-redis.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-redis-token`}</Code>

          <H3>3. Run migrations</H3>
          <Code lang="bash">{`# In Supabase SQL editor, run:
supabase/migrations/001_initial.sql`}</Code>

          <H3>4. Start dev server</H3>
          <Code lang="bash">{`npm run dev
# → http://localhost:3000`}</Code>

          <H3>5. Send your first check</H3>
          <Code lang="bash">{`curl -X POST http://localhost:3000/api/yoroi/check \\
  -H "Content-Type: application/json" \\
  -H "x-api-key: YOUR_API_KEY" \\
  -d '{
    "agent_id": "my-agent-001",
    "action": "search_web",
    "tool": "browser",
    "args": { "query": "latest AI news" },
    "source": "user"
  }'`}</Code>
          <Callout type="info">
            If no policy is configured, YOROI runs in permissive mode — all tools allowed, decisions based on risk score only.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="check-api">
          <H2>POST /api/yoroi/check</H2>
          <Lead>
            The primary endpoint. Evaluates an agent action against policies, risk scoring, and guardrails. Returns a decision in milliseconds.
          </Lead>

          <H3>Request</H3>
          <Table
            headers={["Field", "Type", "Required", "Description"]}
            rows={[
              ["agent_id", "string", "✓", "Unique identifier for the agent making the request"],
              ["action", "string", "✓", "The action being requested (e.g. <code class='text-[#FFC400] text-xs'>transfer_funds</code>)"],
              ["tool", "string", "✓", "Tool ID being invoked (matched against allowlist)"],
              ["args", "object", "✗", "Tool arguments. Recursively scanned by guardrails."],
              ["source", "string", "✗", "Origin: <code class='text-[#FFC400] text-xs'>user</code> | <code class='text-[#FFC400] text-xs'>agent</code> | <code class='text-[#FFC400] text-xs'>tool</code> | <code class='text-[#FFC400] text-xs'>web</code>"],
              ["intent", "string", "✗", "High-level goal. Used for intent mismatch detection."],
              ["session_id", "string", "✗", "Session context for grouping related actions."],
            ]}
          />

          <H3>Response</H3>
          <Code lang="json">{`{
  "decision": "allow" | "deny" | "sandbox" | "require_confirmation",
  "risk_score": 0.23,
  "reason": "Action allowed. Risk within threshold.",
  "action_id": "uuid-v4",
  "guardrail_threats": [],
  "policy_violations": [],
  "metadata": {
    "policy_applied": true,
    "cache_hit": true,
    "latency_ms": 7
  }
}`}</Code>

          <H3>Example</H3>
          <Code lang="typescript">{`const res = await fetch("/api/yoroi/check", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": process.env.YOROI_API_KEY,
  },
  body: JSON.stringify({
    agent_id: "agent-001",
    action:   "transfer_funds",
    tool:     "wallet",
    args:     { amount: 500, recipient: "0xabc123" },
    source:   "user",
    intent:   "Pay vendor invoice",
  }),
});

const { decision, risk_score, reason } = await res.json();`}</Code>

          <H3>Error Responses</H3>
          <Table
            headers={["Status", "Code", "Cause"]}
            rows={[
              ["400", "VALIDATION_ERROR", "Request body fails Zod schema validation"],
              ["401", "UNAUTHORIZED", "Missing or invalid x-api-key header"],
              ["429", "RATE_LIMITED", "Exceeded rate limit for this agent_id"],
              ["413", "PAYLOAD_TOO_LARGE", "Request body or args exceeds size limits"],
              ["500", "INTERNAL_ERROR", "Unexpected server error (details in logs)"],
            ]}
          />
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="scan-api">
          <H2>POST /api/yoroi/scan</H2>
          <Lead>
            Run only the guardrail engine on arbitrary content. Useful for scanning tool outputs, web pages, or user messages before feeding them to agents.
          </Lead>
          <Code lang="json">{`// Request
{
  "content": "string or object to scan",
  "source": "web" | "tool" | "user" | "agent"
}

// Response
{
  "threats": [
    {
      "type": "prompt_injection",
      "severity": "critical",
      "detail": "Instruction override pattern detected",
      "field": "content"
    }
  ],
  "risk_boost": 0.45,
  "should_deny": true
}`}</Code>
          <Callout type="warn">
            Indirect sources (<InlineCode>tool</InlineCode>, <InlineCode>web</InlineCode>) trigger stricter denial logic — any high-severity threat causes immediate denial.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="policy-api">
          <H2>GET | POST | DELETE /api/policy</H2>
          <Lead>Retrieve, create/update, or delete the organization&apos;s security policy.</Lead>

          <H3>GET — Retrieve policy</H3>
          <Code lang="bash">{`curl /api/policy -H "x-api-key: YOUR_KEY"
# Returns { policy: PolicyObject | null }`}</Code>

          <H3>POST — Create or update</H3>
          <Table
            headers={["Field", "Type", "Description"]}
            rows={[
              ["allowed_tools", "string[]", "Whitelisted tool IDs. Empty array = all tools permitted."],
              ["blocked_actions", "string[]", "Actions that are always denied."],
              ["trusted_domains", "string[]", "Untrusted domains increase risk score."],
              ["sensitive_actions", "string[]", "Actions flagged for review (not blocked)."],
              ["max_spend_usd", "number | null", "Maximum monetary value per action."],
              ["risk_threshold_allow", "number (0–1)", "Below this score → allow."],
              ["risk_threshold_sandbox", "number (0–1)", "Below this score → require_confirmation."],
              ["risk_threshold_deny", "number (0–1)", "At or above this score → deny."],
            ]}
          />
          <Code lang="typescript">{`await fetch("/api/policy", {
  method: "POST",
  headers: { "Content-Type": "application/json", "x-api-key": KEY },
  body: JSON.stringify({
    allowed_tools: ["browser", "search", "calendar"],
    blocked_actions: ["delete_account", "export_all_data"],
    trusted_domains: ["github.com", "api.openai.com"],
    sensitive_actions: ["payment", "transfer", "send"],
    max_spend_usd: 500,
    risk_threshold_allow: 0.3,
    risk_threshold_sandbox: 0.6,
    risk_threshold_deny: 0.8,
  }),
});`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="tools-api">
          <H2>GET /api/tools · POST /api/tools/register</H2>
          <Lead>List registered tools or register a new tool with YOROI.</Lead>

          <H3>Register a tool</H3>
          <Code lang="typescript">{`await fetch("/api/tools/register", {
  method: "POST",
  headers: { "Content-Type": "application/json", "x-api-key": KEY },
  body: JSON.stringify({
    tool_id:     "browser-use",
    publisher:   "Anthropic",
    description: "Headless browser automation for web research",
    permissions: ["network", "read"],
    risk_level:  "medium",   // "low" | "medium" | "high" | "critical"
  }),
});`}</Code>
          <Callout type="warn">
            Tool <InlineCode>description</InlineCode> and <InlineCode>publisher</InlineCode> fields are scanned for prompt injection on registration. Suspicious content is rejected.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="logs-api">
          <H2>GET /api/logs</H2>
          <Lead>Query the action audit log with optional filters.</Lead>
          <Code lang="bash">{`# Query params:
# agent_id   — filter by agent
# decision   — "allow" | "deny" | "sandbox" | "require_confirmation"
# limit      — max results (default 50, max 500)
# offset     — pagination offset

curl "/api/logs?decision=deny&limit=20" \\
  -H "x-api-key: YOUR_KEY"`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="policy-engine">
          <H2>Policy Engine</H2>
          <Lead>
            The policy engine performs deterministic rule evaluation. It runs before the risk engine, meaning policy violations can short-circuit to immediate denial without scoring.
          </Lead>

          <H3>Evaluation functions</H3>
          <Table
            headers={["Function", "Checks", "On violation"]}
            rows={[
              ["evaluateToolAccess()", "tool in allowed_tools[]", "deny if allowlist non-empty and tool missing"],
              ["evaluateActionPermission()", "action in blocked_actions[]", "deny immediately"],
              ["evaluateDomainTrust()", "domain in trusted_domains[]", "adds 0.2 risk boost"],
              ["evaluateSpendLimit()", "args.amount ≤ max_spend_usd", "deny if exceeded"],
            ]}
          />

          <H3>Redis caching</H3>
          <Lead>
            Policies are cached in Upstash Redis using stale-while-revalidate (SWR). Cache TTL is 5 minutes; stale threshold is 4 minutes. Negative cache (no-policy) TTL is 30 seconds to avoid repeated DB hits.
          </Lead>
          <Code lang="typescript">{`// Cache keys (Redis)
CacheKeys.policy(orgId)       // → "policy:org:<id>"
CacheKeys.toolRegistry(orgId) // → "tools:org:<id>"
CacheKeys.rateLimit(agentId)  // → "rl:agent:<id>"`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="risk-engine">
          <H2>Risk Engine</H2>
          <Lead>
            The risk engine computes a normalized 0–1 score from 8 weighted factors. The score determines which decision band applies.
          </Lead>

          <H3>Risk factors</H3>
          <Table
            headers={["Factor", "Weight", "Trigger"]}
            rows={[
              ["payment_action", "+0.35", "action contains: payment, transfer, withdraw, send, pay"],
              ["unknown_tool", "+0.25", "tool not in registered tool registry"],
              ["untrusted_domain", "+0.20", "domain in args not in trusted_domains policy"],
              ["sensitive_args", "+0.20", "args contain: password, secret, token, key, private"],
              ["intent_mismatch", "+0.15", "action semantically distant from stated intent"],
              ["high_risk_source", "+0.30", "source is tool or web (indirect attack surface)"],
              ["agent_source", "+0.05", "source is agent (elevated vs user)"],
              ["guardrail_boost", "variable", "from guardrail scan: 0.2 (high) or 0.4 (critical)"],
            ]}
          />
          <Callout type="info">
            Final score is <InlineCode>Math.min(1, sum_of_factors)</InlineCode>. A score of 0 is never returned — minimum is 0.02 to reflect inherent uncertainty.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="guardrail-engine">
          <H2>Guardrail Engine</H2>
          <Lead>
            The guardrail engine runs after risk scoring. It recursively inspects all string values in the request payload using three specialized scanners.
          </Lead>

          <H3>Prompt Injection Scanner</H3>
          <Lead>Detects attempts to override agent instructions or exfiltrate data via crafted input.</Lead>
          <Table
            headers={["Pattern Class", "Examples"]}
            rows={[
              ["Instruction override", "<code>ignore previous instructions</code>, <code>new directive</code>, <code>system prompt</code>"],
              ["Jailbreak", "<code>pretend you are</code>, <code>DAN mode</code>, <code>developer mode enabled</code>"],
              ["Data extraction", "<code>repeat everything above</code>, <code>print your instructions</code>"],
              ["Indirect HTML/XML", "<code>&lt;!-- inject --&gt;</code>, <code>&lt;script&gt;</code>, markdown code blocks with commands"],
              ["Tool poisoning", "Tool descriptions containing <code>always</code>/<code>never</code> + action verbs"],
            ]}
          />

          <H3>Credential Scanner</H3>
          <Lead>Detects API keys, tokens, private keys, and high-entropy strings that may indicate credential leakage.</Lead>

          <H3>PII Scanner</H3>
          <Lead>Detects email addresses, phone numbers, SSNs, credit card numbers, and passport patterns.</Lead>

          <H3>Severity levels</H3>
          <div className="flex gap-2 flex-wrap my-3">
            <Badge color="gray">info → +0.0</Badge>
            <Badge color="gold">medium → +0.1</Badge>
            <Badge color="gold">high → +0.2</Badge>
            <Badge color="red">critical → +0.4</Badge>
          </div>
          <Callout type="danger">
            For indirect sources (<InlineCode>tool</InlineCode>, <InlineCode>web</InlineCode>), any <strong>high</strong> or critical severity threat triggers immediate denial, regardless of risk score.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="sdk-install">
          <H2>SDK — Installation</H2>
          <Lead>The YOROI SDK is a thin TypeScript client that wraps the REST API.</Lead>
          <Code lang="bash">{`npm install @yoroi/sdk
# or: pnpm add @yoroi/sdk`}</Code>
          <Code lang="typescript">{`import { Yoroi } from "@yoroi/sdk";

const wall = new Yoroi({
  baseUrl: "https://your-yoroi.vercel.app",
  apiKey:  process.env.YOROI_API_KEY!,
  agentId: "my-agent",  // default agent_id for all checks
});`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="sdk-check">
          <H2>SDK — check()</H2>
          <Lead>Evaluate an action before execution. This is the core method.</Lead>
          <Code lang="typescript">{`const result = await wall.check({
  action:    "send_email",
  tool:      "gmail",
  args:      { to: "boss@company.com", subject: "Urgent" },
  source:    "user",
  intent:    "Send weekly report",
  sessionId: "session-abc",
});

switch (result.decision) {
  case "allow":
    return await executeTool(result);
  case "deny":
    throw new Error(\`Blocked: \${result.reason}\`);
  case "require_confirmation":
    return await promptUser(result);
  case "sandbox":
    return await executeIsolated(result);
}`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="sdk-policy">
          <H2>SDK — setPolicy()</H2>
          <Code lang="typescript">{`await wall.setPolicy({
  allowedTools:        ["browser", "search"],
  blockedActions:      ["delete_account"],
  trustedDomains:      ["api.openai.com"],
  sensitiveActions:    ["payment", "transfer"],
  maxSpendUsd:         1000,
  riskThresholdAllow:  0.3,
  riskThresholdSandbox: 0.6,
  riskThresholdDeny:   0.8,
});`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="sdk-tools">
          <H2>SDK — registerTool()</H2>
          <Code lang="typescript">{`await wall.registerTool({
  toolId:      "browser-use",
  publisher:   "Anthropic",
  description: "Headless browser for web research",
  permissions: ["network", "read"],
  riskLevel:   "medium",
});`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="auth">
          <H2>Authentication</H2>
          <Lead>All API endpoints require an <InlineCode>x-api-key</InlineCode> header. Keys are stored SHA-256 hashed in Supabase.</Lead>
          <Code lang="typescript">{`// Every request:
headers: {
  "x-api-key": "yoroi_live_your_key_here"
}`}</Code>
          <Callout type="danger">
            Never expose API keys in client-side code. Always use environment variables and server-side calls.
          </Callout>
          <H3>Key format</H3>
          <p className="text-sm text-[#888]">Keys follow the pattern <InlineCode>yoroi_live_&lt;random-32-bytes-hex&gt;</InlineCode>. Generate with:</p>
          <Code lang="bash">{`node -e "console.log('yoroi_live_' + require('crypto').randomBytes(32).toString('hex'))"`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="rate-limiting">
          <H2>Rate Limiting</H2>
          <Lead>Sliding window rate limiting enforced per <InlineCode>agent_id</InlineCode> via Upstash Redis.</Lead>
          <Table
            headers={["Parameter", "Default", "Notes"]}
            rows={[
              ["Window", "60 seconds", "Rolling window"],
              ["Limit", "100 requests", "Per agent_id per window"],
              ["Algorithm", "Sliding window", "Redis ZADD + ZREMRANGEBYSCORE"],
              ["Response on limit", "HTTP 429", "Retry-After header included"],
            ]}
          />
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="input-hardening">
          <H2>Input Hardening</H2>
          <Lead>All inputs are hardened before processing. Limits are enforced at the boundary before any business logic runs.</Lead>
          <Table
            headers={["Limit", "Value", "Error"]}
            rows={[
              ["Request body size", "50KB", "HTTP 413"],
              ["Args JSON size", "16KB", "HTTP 413"],
              ["Object nesting depth", "10 levels", "HTTP 400"],
              ["Individual string length", "4096 chars", "HTTP 400"],
              ["tool_id format", "Alphanumeric + - _", "HTTP 400"],
              ["action format", "Alphanumeric + - _ /", "HTTP 400"],
            ]}
          />
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="threat-model">
          <H2>Threat Model</H2>
          <Lead>YOROI is designed to defend against these threat vectors:</Lead>
          <div className="space-y-3 my-4">
            {[
              { kanji: "注", label: "Prompt Injection", desc: "User or tool output crafted to override agent instructions. Detected by the injection scanner on all string values in args." },
              { kanji: "毒", label: "Tool Poisoning", desc: "Malicious tool definitions that embed instructions. Scanned on registration and on every check request." },
              { kanji: "盗", label: "Credential Theft", desc: "Attempts to exfiltrate API keys, tokens, or secrets via tool arguments. High-entropy string detection." },
              { kanji: "窃", label: "Data Exfiltration", desc: "Indirect attacks via web content or tool outputs containing extraction instructions. Stricter rules for source=web/tool." },
              { kanji: "浪", label: "Wallet Drain / Overspend", desc: "Unbounded monetary actions. Enforced via max_spend_usd policy field and payment-action risk weighting." },
              { kanji: "洪", label: "DoS via Payload Size", desc: "Oversized arguments causing ReDoS or processing stalls. Enforced via body size, depth, and string length limits." },
            ].map((t) => (
              <div key={t.kanji} className="flex gap-4 bg-[#0a0a0a] border border-[#1e1e1e] rounded-xl p-4">
                <span className="text-2xl font-black text-[#FFC400] font-display leading-none shrink-0 w-8">{t.kanji}</span>
                <div>
                  <p className="font-bold text-white text-sm">{t.label}</p>
                  <p className="text-[#666] text-sm mt-0.5 leading-relaxed">{t.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="env-vars">
          <H2>Environment Variables</H2>
          <Table
            headers={["Variable", "Required", "Description"]}
            rows={[
              ["NEXT_PUBLIC_SUPABASE_URL", "✓", "Your Supabase project URL"],
              ["NEXT_PUBLIC_SUPABASE_ANON_KEY", "✓", "Supabase anon/public key"],
              ["SUPABASE_SERVICE_ROLE_KEY", "✓", "Service role key (server-side only)"],
              ["UPSTASH_REDIS_REST_URL", "✓", "Upstash Redis REST endpoint"],
              ["UPSTASH_REDIS_REST_TOKEN", "✓", "Upstash Redis REST token"],
              ["YOROI_MASTER_KEY", "✗", "Admin API key for dashboard access"],
            ]}
          />
          <Callout type="danger">
            Never commit <InlineCode>SUPABASE_SERVICE_ROLE_KEY</InlineCode> or <InlineCode>UPSTASH_REDIS_REST_TOKEN</InlineCode> to version control. Add them to <InlineCode>.gitignore</InlineCode> and set them in your deployment environment.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="vercel">
          <H2>Deploy to Vercel</H2>
          <Lead>YOROI is designed to deploy on Vercel with zero configuration changes.</Lead>
          <Code lang="bash">{`# 1. Push to GitHub
git push origin main

# 2. Import project at vercel.com/new
# 3. Add environment variables in Vercel dashboard
# 4. Deploy — done.`}</Code>
          <Callout type="info">
            All API routes use the <InlineCode>nodejs</InlineCode> runtime. Edge runtime is not supported due to the Supabase client. Each route is independently deployed as a serverless function.
          </Callout>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="supabase">
          <H2>Supabase Setup</H2>
          <Lead>YOROI requires five tables in Supabase Postgres.</Lead>
          <Table
            headers={["Table", "Purpose"]}
            rows={[
              ["organizations", "Multi-tenant org records"],
              ["api_keys", "SHA-256 hashed API keys with org_id FK"],
              ["policies", "One policy per org: thresholds, allowlists, blocklists"],
              ["tools", "Registered tool definitions with risk level"],
              ["actions", "Full audit log: every check decision"],
            ]}
          />
          <Code lang="bash">{`# Run in Supabase SQL editor:
# File: supabase/migrations/001_initial.sql`}</Code>
        </Section>

        {/* ──────────────────────────────────────────────────────────────────── */}
        <Section id="redis">
          <H2>Upstash Redis</H2>
          <Lead>Redis is used for three things: policy caching, rate limiting, and agent session context.</Lead>
          <Table
            headers={["Key Pattern", "TTL", "Purpose"]}
            rows={[
              ["policy:org:&lt;id&gt;", "5 min", "Cached policy object (SWR)"],
              ["tools:org:&lt;id&gt;", "5 min", "Cached tool registry"],
              ["rl:agent:&lt;id&gt;", "60 sec", "Rate limit sliding window (sorted set)"],
              ["session:&lt;id&gt;", "30 min", "Agent session context"],
            ]}
          />
          <Callout type="info">
            Create a free Upstash Redis database at <strong className="text-white">upstash.com</strong>. Use the REST API endpoint and token — no connection pooling required.
          </Callout>
        </Section>

      </main>

      {/* Right TOC (on-page) */}
      <div className="hidden xl:block w-48 shrink-0 sticky top-12 h-[calc(100vh-3rem)] py-6 px-4 overflow-y-auto">
        <p className="text-[10px] font-black tracking-[0.2em] text-[#333] mb-3 font-display">ON THIS PAGE</p>
        <div className="space-y-1 text-xs text-[#444]">
          {["Introduction", "Architecture", "Quick Start", "API Reference", "Policy Engine", "Risk Engine", "Guardrails", "SDK", "Security", "Deployment"].map((t) => (
            <div key={t} className="hover:text-[#888] transition-colors cursor-pointer py-0.5">{t}</div>
          ))}
        </div>
      </div>
    </div>
  );
}
