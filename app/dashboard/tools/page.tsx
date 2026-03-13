import { getSupabaseServer } from "@/lib/supabase/server";
import { ToolRegistryTable } from "@/components/tools/ToolRegistryTable";
import type { Tool } from "@/types";

async function getTools(): Promise<Tool[]> {
  try {
    const supabase = getSupabaseServer();
    const { data } = await supabase.from("tools").select("*").order("created_at", { ascending: false }).limit(100);
    return (data ?? []) as Tool[];
  } catch { return []; }
}

export default async function ToolsPage() {
  const tools = await getTools();
  const byRisk = { low: tools.filter((t) => t.risk_level === "low").length, medium: tools.filter((t) => t.risk_level === "medium").length, high: tools.filter((t) => t.risk_level === "high").length };

  return (
    <div className="bg-particles min-h-screen">
      {/* Hero */}
      <div className="px-8 pt-10 pb-6 border-b border-[#1e1e1e]">
        <p className="text-xs font-bold tracking-[0.2em] text-[#FFC400] uppercase mb-2 font-display">Tool Registry</p>
        <h1 className="font-display text-hero font-black text-white leading-none uppercase">
          MANAGE YOUR <span className="text-[#FFC400]">ARSENAL</span>
        </h1>
        <p className="text-[#777] text-sm mt-3 max-w-xl font-sans">
          Register, inspect, and govern the tools available to your AI agents. Only registered tools are tracked by YOROI.
        </p>
      </div>

      {/* Stats bar */}
      <div className="border-b border-[#1e1e1e] bg-[#0a0a0a]">
        <div className="flex divide-x divide-[#1e1e1e] overflow-x-auto">
          {([
            { label: "Registered", value: tools.length, color: "#fff" },
            { label: "Low Risk", value: byRisk.low, color: "#22c55e" },
            { label: "Medium Risk", value: byRisk.medium, color: "#FFC400" },
            { label: "High Risk", value: byRisk.high, color: "#ef4444" },
          ] as const).map((s) => (
            <div key={s.label} className="flex-1 px-5 py-4 min-w-[100px]">
              <p className="text-[11px] font-semibold tracking-wider text-[#555] uppercase mb-1 font-sans">{s.label}</p>
              <p className="stat-value" style={{ color: s.color }}>{s.value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Info banner */}
      <div className="px-8 pt-6">
        <div className="flex items-start gap-3 bg-[#111] border border-[#1e1e1e] rounded-xl p-4">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[#FFC400] shrink-0 mt-0.5">
            <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.3"/>
            <path d="M8 7v4M8 5v1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
          </svg>
          <p className="text-xs text-[#777] leading-relaxed font-sans">
            Tool definitions are scanned on registration for prompt injection by YOROI. The <code className="text-[#FFC400] bg-[#FFC400]/10 px-1 py-0.5 rounded text-[11px]">tool_id</code> field is used
            to match tools in policy <span className="text-white">allowed_tools</span> and action check requests.
          </p>
        </div>
      </div>

      {/* Table + Register form */}
      <div className="px-8 py-6">
        <ToolRegistryTable initialTools={tools} />
      </div>
    </div>
  );
}
