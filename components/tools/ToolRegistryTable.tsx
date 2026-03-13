"use client";

import { useState } from "react";
import type { Tool } from "@/types";

interface ToolRegistryTableProps { initialTools: Tool[]; }

const RISK_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  low:    { bg: "#22c55e18", text: "#22c55e", border: "#22c55e40" },
  medium: { bg: "#FFC40018", text: "#FFC400", border: "#FFC40040" },
  high:   { bg: "#ef444418", text: "#ef4444", border: "#ef444440" },
};

export function ToolRegistryTable({ initialTools }: ToolRegistryTableProps) {
  const [tools, setTools] = useState<Tool[]>(initialTools);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const [form, setForm] = useState({
    tool_id: "", description: "", publisher: "",
    permissions: "", risk_level: "low" as "low" | "medium" | "high",
  });

  function setF<K extends keyof typeof form>(k: K, v: (typeof form)[K]) {
    setForm((p) => ({ ...p, [k]: v }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true); setError(null); setSuccess(false);
    try {
      const perms = form.permissions.split(",").map((s) => s.trim()).filter(Boolean);
      const body = { tool_id: form.tool_id, description: form.description, publisher: form.publisher, permissions: perms, risk_level: form.risk_level };
      const res = await fetch("/api/tools/register", { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": "" }, body: JSON.stringify(body) });
      if (!res.ok) {
        const j = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(j.error ?? `HTTP ${res.status}`);
      }
      const j = await res.json() as { tool: Tool };
      setTools((prev) => [j.tool, ...prev.filter((t) => t.tool_id !== j.tool.tool_id)]);
      setForm({ tool_id: "", description: "", publisher: "", permissions: "", risk_level: "low" });
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally { setSaving(false); }
  }

  return (
    <div className="space-y-5">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-display text-base font-bold text-white uppercase tracking-wider">
            Registered Tools
            <span className="ml-3 text-xs font-sans font-normal text-[#555] normal-case tracking-normal">{tools.length} tools</span>
          </h2>
        </div>
        <button onClick={() => setShowForm((v) => !v)} className="btn-primary">
          {showForm ? "— Cancel" : "+ Register Tool"}
        </button>
      </div>

      {/* Register form */}
      {showForm && (
        <form onSubmit={(e) => void handleSubmit(e)} className="card p-6 space-y-5">
          <div className="flex items-center justify-between">
            <p className="font-display text-sm font-bold text-white uppercase tracking-wider">New Tool Registration</p>
            {success && <span className="text-sm text-[#22c55e] font-sans">✓ Registered</span>}
            {error && <span className="text-sm text-[#ef4444] font-sans">{error}</span>}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <p className="text-xs font-bold text-[#888] uppercase tracking-wider mb-1.5 font-display">Tool ID *</p>
              <input required value={form.tool_id} onChange={(e) => setF("tool_id", e.target.value)} placeholder="e.g. browser-use" className="field" />
            </div>
            <div>
              <p className="text-xs font-bold text-[#888] uppercase tracking-wider mb-1.5 font-display">Publisher *</p>
              <input required value={form.publisher} onChange={(e) => setF("publisher", e.target.value)} placeholder="e.g. Anthropic" className="field" />
            </div>
            <div className="sm:col-span-2">
              <p className="text-xs font-bold text-[#888] uppercase tracking-wider mb-1.5 font-display">Description</p>
              <textarea rows={2} value={form.description} onChange={(e) => setF("description", e.target.value)} placeholder="What this tool does…" className="field resize-none" />
            </div>
            <div>
              <p className="text-xs font-bold text-[#888] uppercase tracking-wider mb-1.5 font-display">Risk Level</p>
              <select value={form.risk_level} onChange={(e) => setF("risk_level", e.target.value as "low" | "medium" | "high")} className="field">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
            <div>
              <p className="text-xs font-bold text-[#888] uppercase tracking-wider mb-1.5 font-display">Permissions <span className="normal-case font-normal text-[#555] tracking-normal">(comma-separated)</span></p>
              <input value={form.permissions} onChange={(e) => setF("permissions", e.target.value)} placeholder="read, write, network" className="field" />
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2 border-t border-[#1e1e1e]">
            <button type="submit" disabled={saving} className="btn-primary">
              {saving ? "Registering…" : "Register Tool"}
            </button>
            <button type="button" onClick={() => setShowForm(false)} className="btn-ghost">Cancel</button>
          </div>
        </form>
      )}

      {/* Table */}
      {tools.length === 0 ? (
        <div className="card py-20 text-center">
          <p className="font-display text-2xl font-black text-[#1e1e1e] uppercase">No Tools Registered</p>
          <p className="text-[#555] text-sm mt-2 font-sans">Register a tool above to start tracking it.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tool ID</th>
                <th>Publisher</th>
                <th>Description</th>
                <th>Permissions</th>
                <th>Risk</th>
                <th>Registered</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => {
                const rs = RISK_STYLES[t.risk_level] ?? RISK_STYLES["low"]!;
                return (
                  <tr key={t.tool_id}>
                    <td className="font-mono text-sm text-[#FFC400] font-semibold">{t.tool_id}</td>
                    <td className="text-[#aaa] text-sm">{t.publisher}</td>
                    <td className="text-[#777] text-sm max-w-[240px]">
                      <span className="line-clamp-2">{t.description || "—"}</span>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {(t.permissions ?? []).slice(0, 3).map((p) => (
                          <span key={p} className="tag text-[11px] border-[#2a2a2a] text-[#666]">{p}</span>
                        ))}
                        {(t.permissions ?? []).length > 3 && (
                          <span className="text-xs text-[#444]">+{(t.permissions ?? []).length - 3}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="tag text-xs font-bold uppercase tracking-wide"
                        style={{ color: rs.text, background: rs.bg, borderColor: rs.border }}>
                        {t.risk_level}
                      </span>
                    </td>
                    <td className="text-xs text-[#555] font-mono whitespace-nowrap">
                      {t.created_at ? new Date(t.created_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
