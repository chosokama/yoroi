"use client";

import { useEffect, useState, useCallback } from "react";
import { PolicyEditor } from "@/components/policies/PolicyEditor";
import type { Policy } from "@/types";

export default function PoliciesPage() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPolicy = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await fetch("/api/policy", { headers: { "x-api-key": "" } });
      if (res.ok) {
        const data = await res.json() as { policy: Policy | null };
        setPolicy(data.policy);
      } else {
        setError(`HTTP ${res.status}`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void fetchPolicy(); }, [fetchPolicy]);

  async function handleSave(data: Partial<Policy>) {
    const res = await fetch("/api/policy", {
      method: "POST", headers: { "Content-Type": "application/json", "x-api-key": "" },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const b = await res.json().catch(() => ({})) as { error?: string };
      throw new Error(b.error ?? `HTTP ${res.status}`);
    }
    const json = await res.json() as { policy: Policy };
    setPolicy(json.policy);
  }

  async function handleDelete() {
    const res = await fetch("/api/policy", { method: "DELETE", headers: { "x-api-key": "" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    setPolicy(null);
  }

  return (
    <div className="bg-particles min-h-screen">
      {/* Hero */}
      <div className="px-8 pt-10 pb-6 border-b border-[#1e1e1e]">
        <p className="text-xs font-bold tracking-[0.2em] text-[#FFC400] uppercase mb-2 font-display">Access Control</p>
        <h1 className="font-display text-hero font-black text-white leading-none uppercase">
          DEFINE THE <span className="text-[#FFC400]">RULES</span>
        </h1>
        <p className="text-[#777] text-sm mt-3 max-w-xl font-sans">
          Configure allowed tools, blocked actions, domain trust, spend limits, and risk thresholds for your agents.
        </p>

        {/* Policy status */}
        {!loading && (
          <div className="flex items-center gap-4 mt-4">
            {policy ? (
              <>
                <span className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[#22c55e] font-sans">
                  <span className="size-1.5 rounded-full bg-[#22c55e]" /> Policy Active
                </span>
                {policy.updated_at && (
                  <span className="text-xs text-[#555] font-sans">
                    Last updated {new Date(policy.updated_at).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </span>
                )}
              </>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[#FFC400] font-sans">
                <span className="size-1.5 rounded-full bg-[#FFC400]" /> Default Policy Active
              </span>
            )}
            <button onClick={() => void fetchPolicy()} disabled={loading}
              className="ml-auto btn-ghost text-xs">
              ↻ Refresh
            </button>
          </div>
        )}
      </div>

      <div className="px-8 py-7 space-y-6 max-w-5xl">
        {/* Banners */}
        {!loading && !error && !policy && (
          <div className="border border-[#FFC400]/30 bg-[#FFC400]/5 rounded-xl p-4 flex gap-3 items-start">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[#FFC400] shrink-0 mt-0.5">
              <path d="M8 1L1 14h14L8 1z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
              <path d="M8 6v4M8 11v1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
            </svg>
            <div>
              <p className="text-sm font-bold text-[#FFC400] font-display uppercase tracking-wide">Default Permissive Policy Active</p>
              <p className="text-xs text-[#888] mt-1 font-sans">No custom policy configured. All tools permitted, no actions blocked. Configure and save a policy below to enforce restrictions.</p>
            </div>
          </div>
        )}

        {error && (
          <div className="border border-[#ef4444]/30 bg-[#ef4444]/8 rounded-xl p-4 flex gap-3 items-start">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[#ef4444] shrink-0 mt-0.5">
              <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.3"/>
              <path d="M8 4.5V8M8 10v1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
            </svg>
            <div>
              <p className="text-sm font-bold text-[#ef4444]">Could not load policy</p>
              <p className="text-xs text-[#888] mt-1">{error}</p>
              <button onClick={() => void fetchPolicy()} className="text-xs text-[#FFC400] underline mt-1.5">Retry</button>
            </div>
          </div>
        )}

        {/* Editor */}
        {loading ? (
          <div className="card p-10 flex items-center justify-center gap-3">
            <svg className="animate-spin size-5 text-[#FFC400]" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="60" strokeDashoffset="20"/>
            </svg>
            <span className="text-[#777] font-sans">Loading policy…</span>
          </div>
        ) : !error ? (
          <PolicyEditor policy={policy} onSave={handleSave} onDelete={policy ? handleDelete : undefined} />
        ) : null}

        {/* Reference */}
        <div className="card p-6">
          <h2 className="font-display text-sm font-bold text-white uppercase tracking-wider mb-4">Field Reference</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              { label: "Allowed Tools", desc: "Whitelist of tool IDs. Empty = all tools permitted.", accent: "#FFC400" },
              { label: "Blocked Actions", desc: "Always denied, regardless of risk score.", accent: "#ef4444" },
              { label: "Trusted Domains", desc: "Untrusted domains increase risk score.", accent: "#FFC400" },
              { label: "Sensitive Actions", desc: "Not blocked but flagged for extra scrutiny.", accent: "#FFC400" },
              { label: "Max Spend USD", desc: "Monetary cap enforced on transaction args.", accent: "#777" },
              { label: "Risk Thresholds", desc: "Score bands: allow / confirm / sandbox / deny.", accent: "#FFC400" },
            ].map((item) => (
              <div key={item.label} className="flex gap-3">
                <span className="size-1.5 rounded-full shrink-0 mt-1.5" style={{ background: item.accent }} />
                <div>
                  <p className="text-sm font-semibold text-white">{item.label}</p>
                  <p className="text-xs text-[#666] mt-0.5 leading-relaxed font-sans">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
