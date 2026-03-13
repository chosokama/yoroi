import type { ActionLog } from "@/types";
import { DecisionBadge } from "@/components/ui/DecisionBadge";

interface RiskAlertsProps {
  logs: ActionLog[];
}

export function RiskAlerts({ logs }: RiskAlertsProps) {
  const alerts = logs.filter((l) => l.risk_score >= 0.6).slice(0, 5);

  if (alerts.length === 0) {
    return (
      <div className="card p-5 text-center">
        <div className="size-10 rounded-full bg-[#22c55e]/10 flex items-center justify-center mx-auto mb-3">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none" className="text-[#22c55e]">
            <path d="M9 1L1.5 4v5c0 4.5 3.5 7 7.5 7.5C14 16 17.5 13.5 17.5 9V4L9 1z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/>
            <path d="M6 9l2 2 4-4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
        <p className="font-display text-sm font-bold text-[#333] uppercase">All Clear</p>
        <p className="text-xs text-[#444] mt-1 font-sans">No high-risk actions detected.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {alerts.map((log) => (
        <div key={log.action_id} className="bg-[#ef4444]/6 border border-[#ef4444]/25 rounded-xl p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <p className="text-sm font-semibold text-white truncate">{log.action}</p>
                <DecisionBadge decision={log.decision} size="sm" />
              </div>
              <p className="text-xs text-[#666] mt-1 font-sans">{log.tool} · {log.agent_id.slice(0, 12)}…</p>
            </div>
            <div className="shrink-0 text-right">
              <p className="font-display text-lg font-black" style={{ color: "#ef4444" }}>
                {Math.round(log.risk_score * 100)}%
              </p>
              <p className="text-[10px] text-[#555] font-sans uppercase tracking-wider">Risk</p>
            </div>
          </div>
          {log.reason && (
            <p className="text-[11px] text-[#888] mt-2 line-clamp-2 font-sans leading-relaxed">{log.reason}</p>
          )}
        </div>
      ))}
    </div>
  );
}
