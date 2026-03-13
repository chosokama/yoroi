"use client";

import { useState } from "react";
import type { ActionLog } from "@/types";
import { DecisionBadge } from "@/components/ui/DecisionBadge";
import { RiskBar } from "@/components/ui/RiskBar";

interface ActionLogsTableProps {
  logs: ActionLog[];
}

export function ActionLogsTable({ logs }: ActionLogsTableProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all" ? logs : logs.filter((l) => l.decision === filter);

  if (logs.length === 0) {
    return (
      <div className="card py-20 text-center">
        <p className="font-display text-2xl font-black text-[#1e1e1e] uppercase">No Actions Yet</p>
        <p className="text-[#555] text-sm mt-2 font-sans">Start sending requests to see your audit log here.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {(["all", "allow", "deny", "require_confirmation", "sandbox"] as const).map((d) => {
          const labels = { all: "All", allow: "Allow", deny: "Deny", require_confirmation: "Confirm", sandbox: "Sandbox" };
          const counts = { all: logs.length, allow: logs.filter(l => l.decision === "allow").length, deny: logs.filter(l => l.decision === "deny").length, require_confirmation: logs.filter(l => l.decision === "require_confirmation").length, sandbox: logs.filter(l => l.decision === "sandbox").length };
          return (
            <button
              key={d}
              onClick={() => setFilter(d)}
              className={`text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-lg border transition-all font-sans ${
                filter === d
                  ? "bg-[#FFC400] text-black border-[#FFC400]"
                  : "border-[#2a2a2a] text-[#777] hover:text-white hover:border-[#444]"
              }`}
            >
              {labels[d]} <span className={`ml-1 ${filter === d ? "text-black/60" : "text-[#555]"}`}>({counts[d]})</span>
            </button>
          );
        })}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Agent ID</th>
                <th>Action / Tool</th>
                <th>Decision</th>
                <th className="w-32">Risk Score</th>
                <th>Source</th>
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((log) => (
                <>
                  <tr
                    key={log.action_id}
                    className="cursor-pointer"
                    onClick={() => setExpanded(expanded === log.action_id ? null : log.action_id)}
                  >
                    <td className="text-[#666] text-xs font-mono whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="font-mono text-xs text-[#888]">
                      {log.agent_id.slice(0, 14)}…
                    </td>
                    <td>
                      <p className="text-white font-semibold">{log.action}</p>
                      <p className="text-[#555] text-xs mt-0.5">{log.tool}</p>
                    </td>
                    <td><DecisionBadge decision={log.decision} size="sm" /></td>
                    <td className="w-32"><RiskBar score={log.risk_score} /></td>
                    <td>
                      <span className="text-xs text-[#777] bg-[#1a1a1a] border border-[#2a2a2a] px-2 py-0.5 rounded-full">
                        {log.source}
                      </span>
                    </td>
                    <td className="text-[#444] text-xs text-center">
                      {expanded === log.action_id ? "▲" : "▼"}
                    </td>
                  </tr>
                  {expanded === log.action_id && (
                    <tr key={`${log.action_id}-exp`}>
                      <td colSpan={7} className="bg-[#0a0a0a] px-6 py-5 border-t border-[#1e1e1e]">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                          <div>
                            <p className="text-[10px] font-bold tracking-widest text-[#444] uppercase mb-2 font-display">Decision Reason</p>
                            <p className="text-sm text-[#aaa] leading-relaxed">{log.reason}</p>
                          </div>
                          <div>
                            <p className="text-[10px] font-bold tracking-widest text-[#444] uppercase mb-2 font-display">Action Details</p>
                            <div className="space-y-1 text-xs">
                              <div className="flex gap-2">
                                <span className="text-[#555] w-16">Action</span>
                                <span className="text-[#ccc]">{log.action}</span>
                              </div>
                              <div className="flex gap-2">
                                <span className="text-[#555] w-16">Tool</span>
                                <span className="text-[#ccc]">{log.tool}</span>
                              </div>
                              <div className="flex gap-2">
                                <span className="text-[#555] w-16">Agent</span>
                                <span className="text-[#ccc] font-mono">{log.agent_id}</span>
                              </div>
                              <div className="flex gap-2">
                                <span className="text-[#555] w-16">Risk</span>
                                <span className="text-[#FFC400]">{(log.risk_score * 100).toFixed(1)}%</span>
                              </div>
                            </div>
                          </div>
                          <div>
                            <p className="text-[10px] font-bold tracking-widest text-[#444] uppercase mb-2 font-display">Arguments</p>
                            <pre className="text-xs text-[#FFC400] bg-[#000] rounded-lg p-3 overflow-x-auto font-mono border border-[#1e1e1e] max-h-28">
                              {JSON.stringify(log.args, null, 2)}
                            </pre>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-xs text-[#555] text-right font-sans">
        Showing {filtered.length} of {logs.length} actions
      </p>
    </div>
  );
}
