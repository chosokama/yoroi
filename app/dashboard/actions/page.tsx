import { getSupabaseServer } from "@/lib/supabase/server";
import { ActionLogsTable } from "@/components/actions/ActionLogsTable";
import type { ActionLog } from "@/types";

async function getLogs(): Promise<ActionLog[]> {
  try {
    const supabase = getSupabaseServer();
    const { data } = await supabase.from("actions").select("*").order("timestamp", { ascending: false }).limit(100);
    return (data ?? []) as ActionLog[];
  } catch { return []; }
}

export default async function ActionsPage() {
  const logs = await getLogs();
  const counts = {
    allow: logs.filter((l) => l.decision === "allow").length,
    deny: logs.filter((l) => l.decision === "deny").length,
    require_confirmation: logs.filter((l) => l.decision === "require_confirmation").length,
    sandbox: logs.filter((l) => l.decision === "sandbox").length,
  };

  return (
    <div className="bg-particles min-h-screen">
      {/* Hero */}
      <div className="px-8 pt-10 pb-6 border-b border-[#1e1e1e]">
        <p className="text-xs font-bold tracking-[0.2em] text-[#FFC400] uppercase mb-2 font-display">Audit Trail</p>
        <h1 className="font-display text-hero font-black text-white leading-none uppercase">
          EVERY ACTION: <span className="text-[#FFC400]">LOGGED</span>
        </h1>
        <p className="text-[#777] text-sm mt-3 max-w-xl font-sans">
          Complete audit trail of every agent action evaluated by YOROI 鎧. Click any row to inspect arguments and threat details.
        </p>
      </div>

      {/* Stats bar */}
      <div className="border-b border-[#1e1e1e] bg-[#0a0a0a]">
        <div className="flex divide-x divide-[#1e1e1e] overflow-x-auto">
          {([
            { label: "Total", value: logs.length, color: "#fff" },
            { label: "Allowed", value: counts.allow, color: "#22c55e" },
            { label: "Denied", value: counts.deny, color: "#ef4444" },
            { label: "Needs Confirm", value: counts.require_confirmation, color: "#FFC400" },
            { label: "Sandboxed", value: counts.sandbox, color: "#777" },
          ] as const).map((s) => (
            <div key={s.label} className="flex-1 px-5 py-4 min-w-[100px]">
              <p className="text-[11px] font-semibold tracking-wider text-[#555] uppercase mb-1 font-sans">{s.label}</p>
              <p className="stat-value" style={{ color: s.color }}>{s.value.toLocaleString()}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="px-8 py-7">
        <ActionLogsTable logs={logs} />
      </div>
    </div>
  );
}
