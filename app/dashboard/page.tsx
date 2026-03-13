import { getSupabaseServer } from "@/lib/supabase/server";
import { DecisionBadge } from "@/components/ui/DecisionBadge";
import { RiskBar } from "@/components/ui/RiskBar";
import type { ActionLog, DashboardStats } from "@/types";

async function getDashboardData(): Promise<{ stats: DashboardStats; recentLogs: ActionLog[] }> {
  try {
    const supabase = getSupabaseServer();
    const { data: logs } = await supabase
      .from("actions").select("*").order("timestamp", { ascending: false }).limit(50);
    const allLogs = (logs ?? []) as ActionLog[];
    const stats: DashboardStats = {
      total_checks: allLogs.length,
      allow_count: allLogs.filter((l) => l.decision === "allow").length,
      deny_count: allLogs.filter((l) => l.decision === "deny").length,
      require_confirmation_count: allLogs.filter((l) => l.decision === "require_confirmation").length,
      sandbox_count: allLogs.filter((l) => l.decision === "sandbox").length,
      avg_risk_score: allLogs.length > 0 ? allLogs.reduce((s, l) => s + l.risk_score, 0) / allLogs.length : 0,
      high_risk_alerts: allLogs.filter((l) => l.risk_score >= 0.6).length,
    };
    return { stats, recentLogs: allLogs.slice(0, 10) };
  } catch {
    return {
      stats: { total_checks: 0, allow_count: 0, deny_count: 0, require_confirmation_count: 0, sandbox_count: 0, avg_risk_score: 0, high_risk_alerts: 0 },
      recentLogs: [],
    };
  }
}

function StatItem({
  label, value, sub, subColor = "#22c55e",
}: { label: string; value: string; sub?: string; subColor?: string }) {
  return (
    <div className="flex-1 px-5 py-4 min-w-0">
      <p className="text-[11px] font-semibold tracking-wider text-[#555] uppercase mb-1 font-sans">{label}</p>
      <p className="stat-value text-white">{value}</p>
      {sub && <p className="text-[12px] mt-0.5" style={{ color: subColor }}>{sub}</p>}
    </div>
  );
}

export default async function DashboardPage() {
  const { stats, recentLogs } = await getDashboardData();
  const total = stats.total_checks;

  return (
    <div className="bg-particles min-h-screen">
      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <div className="px-8 pt-10 pb-6 border-b border-[#1e1e1e]">
        <p className="text-xs font-bold tracking-[0.2em] text-[#FFC400] uppercase mb-2 font-display">
          Security Dashboard
        </p>
        <h1 className="font-display text-hero font-black text-white leading-none uppercase">
          MONITOR YOUR <span className="text-[#FFC400]">AGENTS</span>
        </h1>
        <p className="text-[#777] text-sm mt-3 max-w-xl font-sans">
          Real-time evaluation of every agent action by YOROI 鎧. Every request scored, every threat blocked, every decision logged.
        </p>
      </div>

      {/* ── Stats bar ─────────────────────────────────────────────────────── */}
      <div className="border-b border-[#1e1e1e] bg-[#0a0a0a]">
        <div className="flex divide-x divide-[#1e1e1e] overflow-x-auto">
          <StatItem label="Total Checks" value={total.toLocaleString()} sub={total > 0 ? "All time" : "No data yet"} subColor="#555" />
          <StatItem
            label="Allowed"
            value={stats.allow_count.toLocaleString()}
            sub={total > 0 ? `↑ ${Math.round((stats.allow_count / total) * 100)}%` : "—"}
            subColor="#22c55e"
          />
          <StatItem
            label="Denied"
            value={stats.deny_count.toLocaleString()}
            sub={total > 0 ? `↓ ${Math.round((stats.deny_count / total) * 100)}%` : "—"}
            subColor="#ef4444"
          />
          <StatItem
            label="Avg Risk Score"
            value={`${(stats.avg_risk_score * 100).toFixed(1)}%`}
            sub={stats.avg_risk_score >= 0.6 ? "⚠ High" : stats.avg_risk_score >= 0.3 ? "Medium" : "Low"}
            subColor={stats.avg_risk_score >= 0.6 ? "#ef4444" : stats.avg_risk_score >= 0.3 ? "#FFC400" : "#22c55e"}
          />
          <StatItem
            label="High Risk Alerts"
            value={stats.high_risk_alerts.toLocaleString()}
            sub={stats.high_risk_alerts > 0 ? "Require review" : "All clear"}
            subColor={stats.high_risk_alerts > 0 ? "#ef4444" : "#22c55e"}
          />
          <StatItem
            label="Sandboxed"
            value={stats.sandbox_count.toLocaleString()}
            sub={total > 0 ? `${Math.round((stats.sandbox_count / total) * 100)}%` : "—"}
            subColor="#FFC400"
          />
        </div>
      </div>

      {/* ── Main content ──────────────────────────────────────────────────── */}
      <div className="px-8 py-7">
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

          {/* Recent Actions */}
          <div className="xl:col-span-2">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-base font-bold text-white uppercase tracking-wider">Recent Actions</h2>
              <a href="/dashboard/actions" className="text-[11px] text-[#FFC400] font-semibold tracking-wider uppercase hover:text-[#e6b000] transition-colors">
                View All →
              </a>
            </div>
            <div className="card overflow-hidden">
              {recentLogs.length === 0 ? (
                <div className="py-16 text-center">
                  <p className="font-display text-xl font-bold text-[#222] uppercase">No Data Yet</p>
                  <p className="text-[#555] text-sm mt-2 font-sans">
                    Send a request to <code className="bg-[#1a1a1a] text-[#FFC400] px-1.5 py-0.5 rounded text-xs">POST /api/yoroi/check</code>
                  </p>
                </div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Action / Tool</th>
                      <th>Decision</th>
                      <th className="w-32">Risk</th>
                      <th>Source</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentLogs.map((log) => (
                      <tr key={log.action_id}>
                        <td>
                          <p className="text-white font-medium truncate max-w-[180px]">{log.action}</p>
                          <p className="text-[#555] text-xs mt-0.5">{log.tool}</p>
                        </td>
                        <td><DecisionBadge decision={log.decision} size="sm" /></td>
                        <td className="w-32"><RiskBar score={log.risk_score} showLabel={false} /></td>
                        <td>
                          <span className="text-xs text-[#777] bg-[#1a1a1a] border border-[#2a2a2a] px-2 py-0.5 rounded-full">
                            {log.source}
                          </span>
                        </td>
                        <td className="text-[#555] text-xs font-mono">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Right column */}
          <div className="space-y-6">
            {/* Decision breakdown */}
            <div>
              <h2 className="font-display text-base font-bold text-white uppercase tracking-wider mb-4">Decision Breakdown</h2>
              <div className="card p-4 space-y-3">
                {([
                  { label: "Allowed", count: stats.allow_count, color: "#22c55e" },
                  { label: "Denied", count: stats.deny_count, color: "#ef4444" },
                  { label: "Needs Confirm", count: stats.require_confirmation_count, color: "#FFC400" },
                  { label: "Sandboxed", count: stats.sandbox_count, color: "#777" },
                ] as const).map((item) => {
                  const pct = total > 0 ? Math.round((item.count / total) * 100) : 0;
                  return (
                    <div key={item.label}>
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs font-semibold text-[#888] uppercase tracking-wider">{item.label}</span>
                        <span className="font-display text-sm font-bold" style={{ color: item.color }}>
                          {item.count} <span className="text-[#444] font-normal text-xs">({pct}%)</span>
                        </span>
                      </div>
                      <div className="h-1 bg-[#1a1a1a] rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: item.color }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Quick start */}
            <div>
              <h2 className="font-display text-base font-bold text-white uppercase tracking-wider mb-4">Quick Start</h2>
              <div className="card p-4">
                <p className="text-[10px] font-bold tracking-widest text-[#555] uppercase mb-2">API Request</p>
                <pre className="text-xs text-[#FFC400] font-mono leading-relaxed overflow-x-auto bg-[#0a0a0a] rounded-lg p-3 border border-[#1e1e1e]">{`curl -X POST /api/yoroi/check \\
  -H "x-api-key: yoroi_key" \\
  -d '{
    "agent_id": "agent-001",
    "action": "transfer",
    "tool": "wallet",
    "source": "user"
  }'`}</pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
