"use client";

import { useState, useCallback, useMemo } from "react";
import type { Policy, DecisionType } from "@/types";

// ─── Types ────────────────────────────────────────────────────────────────────

interface PolicyEditorProps {
  policy: Policy | null;
  onSave: (data: PolicyFormValues) => Promise<void>;
  onDelete?: () => Promise<void>;
}

interface PolicyFormValues {
  allowed_tools: string[];
  blocked_actions: string[];
  trusted_domains: string[];
  sensitive_actions: string[];
  max_spend_usd: number | null;
  risk_threshold_allow: number;
  risk_threshold_sandbox: number;
  risk_threshold_deny: number;
}

type Tab = "editor" | "json";

function parseF(val: string, fallback: number) {
  const n = parseFloat(val);
  return isNaN(n) ? fallback : Math.min(1, Math.max(0, n));
}

function decisionForScore(score: number, a: number, s: number, d: number): DecisionType {
  if (score < a) return "allow";
  if (score < s) return "require_confirmation";
  if (score < d) return "sandbox";
  return "deny";
}

function getInitial(policy: Policy | null): PolicyFormValues {
  return {
    allowed_tools:          policy?.allowed_tools        ?? [],
    blocked_actions:        policy?.blocked_actions       ?? [],
    trusted_domains:        policy?.trusted_domains       ?? [],
    sensitive_actions:      policy?.sensitive_actions     ?? ["payment", "transfer", "delete", "withdraw", "send"],
    max_spend_usd:          policy?.max_spend_usd         ?? null,
    risk_threshold_allow:   policy?.risk_threshold_allow   ?? 0.3,
    risk_threshold_sandbox: policy?.risk_threshold_sandbox ?? 0.6,
    risk_threshold_deny:    policy?.risk_threshold_deny    ?? 0.8,
  };
}

// ─── TagInput ─────────────────────────────────────────────────────────────────

function TagInput({
  label, description, values, onChange, placeholder, tagBg = "bg-[#FFC400]/20 text-[#FFC400] border-[#FFC400]/30",
  validate,
}: {
  label: string; description?: string; values: string[];
  onChange: (v: string[]) => void; placeholder?: string;
  tagBg?: string; validate?: (v: string) => string | null;
}) {
  const [input, setInput] = useState("");
  const [err, setErr] = useState<string | null>(null);

  function add() {
    const t = input.trim();
    if (!t) return;
    if (values.includes(t)) { setErr("Already in list"); return; }
    if (validate) { const e = validate(t); if (e) { setErr(e); return; } }
    onChange([...values, t]);
    setInput(""); setErr(null);
  }

  return (
    <div className="space-y-2">
      <div>
        <p className="text-sm font-semibold text-white">{label}</p>
        {description && <p className="text-xs text-[#666] mt-0.5 font-sans">{description}</p>}
      </div>
      <div className="min-h-10 flex flex-wrap gap-1.5 p-2.5 rounded-lg border border-[#2a2a2a] bg-[#0a0a0a]">
        {values.map((v) => (
          <span key={v} className={`tag ${tagBg}`}>
            {v}
            <button type="button" onClick={() => onChange(values.filter((x) => x !== v))}
              className="opacity-60 hover:opacity-100 leading-none transition-opacity">×</button>
          </span>
        ))}
        {values.length === 0 && <span className="text-xs text-[#444] self-center select-none">None</span>}
      </div>
      <div className="flex gap-2">
        <input type="text" value={input} placeholder={placeholder}
          onChange={(e) => { setInput(e.target.value); setErr(null); }}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
          className="field flex-1 text-sm" />
        <button type="button" onClick={add} className="btn-ghost text-xs">Add</button>
      </div>
      {err && <p className="text-xs text-[#ef4444]">{err}</p>}
    </div>
  );
}

// ─── ThresholdBar ─────────────────────────────────────────────────────────────

function ThresholdBar({ allow, sandbox, deny, simScore }: { allow: number; sandbox: number; deny: number; simScore: number }) {
  const a = Math.min(allow, sandbox, deny) * 100;
  const s = Math.max(allow, Math.min(sandbox, deny)) * 100;
  const d = Math.max(sandbox, Math.min(deny, 1)) * 100;
  const sp = Math.min(100, Math.max(0, simScore * 100));

  return (
    <div className="space-y-2">
      <div className="relative h-4 rounded-full overflow-hidden">
        <div className="absolute inset-0" style={{
          background: `linear-gradient(to right, #FFC400 0%, #FFC400 ${a}%, #f97316 ${a}%, #f97316 ${s}%, #f97316 ${s}%, #f97316 ${d}%, #ef4444 ${d}%, #ef4444 100%)`
        }} />
        {[a, s, d].map((p, i) => (
          <div key={i} className="absolute top-0 bottom-0 w-0.5 bg-black/60" style={{ left: `${p}%` }} />
        ))}
        <div className="absolute top-0 bottom-0 w-1 bg-white" style={{ left: `${sp}%`, transform: "translateX(-50%)" }} />
      </div>
      <div className="flex justify-between text-[10px] text-[#444] px-0.5 font-mono">
        {[0, 0.25, 0.5, 0.75, 1].map((v) => <span key={v}>{v.toFixed(2)}</span>)}
      </div>
    </div>
  );
}

// ─── Section ──────────────────────────────────────────────────────────────────

function Section({ title, badge, badgeColor = "#777", desc, children }: {
  title: string; badge?: string; badgeColor?: string; desc: string; children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-[200px_1fr] gap-5 py-5 border-b border-[#1e1e1e] last:border-0">
      <div>
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="font-display text-sm font-bold text-white uppercase tracking-wider">{title}</h3>
          {badge && (
            <span className="tag text-[11px]" style={{ color: badgeColor, borderColor: `${badgeColor}40`, background: `${badgeColor}18` }}>
              {badge}
            </span>
          )}
        </div>
        <p className="text-xs text-[#666] mt-1.5 leading-relaxed font-sans">{desc}</p>
      </div>
      <div className="card-sm p-4">{children}</div>
    </div>
  );
}

// ─── PolicyEditor ──────────────────────────────────────────────────────────────

export function PolicyEditor({ policy, onSave, onDelete }: PolicyEditorProps) {
  const initial = useMemo(() => getInitial(policy), [policy]);

  const [tab, setTab] = useState<Tab>("editor");
  const [values, setValues] = useState<PolicyFormValues>(initial);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [simScore, setSimScore] = useState("0.50");

  const [ta, setTa] = useState(String(initial.risk_threshold_allow));
  const [ts, setTs] = useState(String(initial.risk_threshold_sandbox));
  const [td, setTd] = useState(String(initial.risk_threshold_deny));

  const tA = parseF(ta, 0.3), tS = parseF(ts, 0.6), tD = parseF(td, 0.8);

  const isDirty = useMemo(() => (
    JSON.stringify(values) !== JSON.stringify(initial) ||
    tA !== initial.risk_threshold_allow || tS !== initial.risk_threshold_sandbox || tD !== initial.risk_threshold_deny
  ), [values, initial, tA, tS, tD]);

  const threshErr = tA >= tS ? "Allow must be less than Confirm" : tS >= tD ? "Confirm must be less than Deny" : null;

  const set = useCallback(<K extends keyof PolicyFormValues>(k: K, v: PolicyFormValues[K]) =>
    setValues((p) => ({ ...p, [k]: v })), []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (threshErr) return;
    setSaving(true); setStatus("idle"); setErrMsg(null);
    try {
      await onSave({ ...values, risk_threshold_allow: tA, risk_threshold_sandbox: tS, risk_threshold_deny: tD });
      setStatus("success");
      setTimeout(() => setStatus("idle"), 3000);
    } catch (err) {
      setStatus("error");
      setErrMsg(err instanceof Error ? err.message : "Save failed");
    } finally { setSaving(false); }
  }

  async function handleDelete() {
    if (!onDelete) return;
    setDeleting(true);
    try { await onDelete(); } finally { setDeleting(false); setConfirmDel(false); }
  }

  const simN = parseFloat(simScore);
  const validSim = !isNaN(simN) && simN >= 0 && simN <= 1;
  const simDecision = validSim ? decisionForScore(simN, tA, tS, tD) : null;
  const simColors: Record<DecisionType, string> = { allow: "#22c55e", deny: "#ef4444", require_confirmation: "#FFC400", sandbox: "#777" };

  const jsonPreview = JSON.stringify({ ...values, risk_threshold_allow: tA, risk_threshold_sandbox: tS, risk_threshold_deny: tD }, null, 2);

  return (
    <div>
      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-5 flex-wrap">
        {/* Tabs */}
        <div className="flex gap-1 bg-[#111] border border-[#1e1e1e] rounded-lg p-1">
          {(["editor", "json"] as Tab[]).map((t) => (
            <button key={t} type="button" onClick={() => setTab(t)}
              className={`px-4 py-1.5 text-xs font-bold uppercase tracking-wider rounded-md transition-all font-sans ${
                tab === t ? "bg-[#FFC400] text-black" : "text-[#666] hover:text-white"
              }`}>
              {t === "json" ? "JSON" : "Editor"}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto flex-wrap">
          {isDirty && (
            <span className="text-xs text-[#FFC400] flex items-center gap-1.5 font-sans">
              <span className="size-1.5 rounded-full bg-[#FFC400]" /> Unsaved changes
            </span>
          )}
          {isDirty && (
            <button type="button" onClick={() => {
              setValues(initial); setTa(String(initial.risk_threshold_allow));
              setTs(String(initial.risk_threshold_sandbox)); setTd(String(initial.risk_threshold_deny));
              setStatus("idle");
            }} className="btn-ghost text-xs">Discard</button>
          )}
          {onDelete && (
            <button type="button" onClick={() => setConfirmDel(true)}
              className="text-xs px-3 py-2 rounded-lg text-[#ef4444] border border-[#ef4444]/40 hover:bg-[#ef4444]/10 transition-all font-sans font-bold uppercase tracking-wider">
              Delete
            </button>
          )}
        </div>
      </div>

      {/* Delete confirm */}
      {confirmDel && (
        <div className="mb-5 card p-4 border-[#ef4444]/40 bg-[#ef4444]/8 flex items-start justify-between gap-4">
          <div>
            <p className="font-display text-sm font-bold text-[#ef4444] uppercase tracking-wider">Delete this policy?</p>
            <p className="text-xs text-[#888] mt-1 font-sans">Default permissive policy becomes active immediately.</p>
          </div>
          <div className="flex gap-2 shrink-0">
            <button onClick={() => setConfirmDel(false)} className="btn-ghost text-xs">Cancel</button>
            <button onClick={() => void handleDelete()} disabled={deleting}
              className="text-xs px-3 py-2 rounded-lg bg-[#ef4444] text-white font-bold uppercase tracking-wider disabled:opacity-50 font-sans transition-colors hover:bg-[#dc2626]">
              {deleting ? "Deleting…" : "Confirm Delete"}
            </button>
          </div>
        </div>
      )}

      {/* JSON tab */}
      {tab === "json" && (
        <div className="relative">
          <button onClick={() => void navigator.clipboard.writeText(jsonPreview)}
            className="absolute top-3 right-3 btn-ghost text-xs z-10">Copy</button>
          <pre className="text-xs text-[#FFC400] bg-[#0a0a0a] rounded-xl border border-[#2a2a2a] p-5 overflow-x-auto font-mono leading-relaxed">{jsonPreview}</pre>
        </div>
      )}

      {/* Editor tab */}
      {tab === "editor" && (
        <form onSubmit={(e) => void handleSubmit(e)}>
          <div className="card divide-y divide-[#1e1e1e]">
            <Section title="Tool Access" badge={values.allowed_tools.length > 0 ? `${values.allowed_tools.length} tools` : "All"} badgeColor="#FFC400"
              desc="Whitelist of tool IDs allowed. Empty = all registered tools permitted.">
              <TagInput label="Allowed Tools" values={values.allowed_tools} onChange={(v) => set("allowed_tools", v)}
                placeholder="e.g. browser, search, calendar" tagBg="bg-[#FFC400]/15 text-[#FFC400] border-[#FFC400]/30" />
            </Section>

            <Section title="Action Control"
              badge={values.blocked_actions.length > 0 ? `${values.blocked_actions.length} blocked` : "No blocks"} badgeColor="#ef4444"
              desc="Blocked actions are always denied. Sensitive actions raise risk without blocking.">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <TagInput label="Blocked Actions" values={values.blocked_actions} onChange={(v) => set("blocked_actions", v)}
                  placeholder="e.g. delete_account" tagBg="bg-[#ef4444]/15 text-[#ef4444] border-[#ef4444]/30" />
                <TagInput label="Sensitive Actions" values={values.sensitive_actions} onChange={(v) => set("sensitive_actions", v)}
                  placeholder="e.g. payment, transfer" tagBg="bg-[#FFC400]/15 text-[#FFC400] border-[#FFC400]/30" />
              </div>
            </Section>

            <Section title="Domain Trust"
              badge={values.trusted_domains.length > 0 ? `${values.trusted_domains.length} trusted` : "All"} badgeColor="#FFC400"
              desc="Requests to unlisted domains increase risk score.">
              <TagInput label="Trusted Domains" values={values.trusted_domains} onChange={(v) => set("trusted_domains", v)}
                placeholder="e.g. github.com, api.company.com" tagBg="bg-[#FFC400]/15 text-[#FFC400] border-[#FFC400]/30"
                validate={(v) => v.startsWith("http") ? "Enter domain only, no https://" : null} />
            </Section>

            <Section title="Spend Limit"
              badge={values.max_spend_usd !== null ? `$${values.max_spend_usd}` : "No limit"} badgeColor="#777"
              desc="Max USD allowed in a single action's monetary arguments.">
              <div className="max-w-xs">
                <p className="text-sm font-semibold text-white mb-1.5">Maximum Spend (USD)</p>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[#555] text-sm select-none">$</span>
                  <input type="number" min="0" step="1" value={values.max_spend_usd ?? ""}
                    onChange={(e) => set("max_spend_usd", e.target.value ? parseFloat(e.target.value) : null)}
                    placeholder="No limit" className="field pl-7" />
                </div>
                <p className="text-xs text-[#555] mt-1.5 font-sans">Leave empty for no limit.</p>
              </div>
            </Section>

            <Section title="Risk Thresholds" desc="Score bands (0–1) controlling when actions are allowed, confirmed, sandboxed, or denied.">
              <div className="space-y-5">
                <ThresholdBar allow={tA} sandbox={tS} deny={tD} simScore={validSim ? simN : 0.5} />

                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: "Allow below", hint: "→ allow", val: ta, set: setTa, color: "#FFC400" },
                    { label: "Sandbox below", hint: "→ confirm", val: ts, set: setTs, color: "#FFC400" },
                    { label: "Deny above", hint: "→ deny", val: td, set: setTd, color: "#ef4444" },
                  ].map((f) => (
                    <div key={f.label}>
                      <p className="text-xs font-bold uppercase tracking-wider mb-1.5 font-display" style={{ color: f.color }}>{f.label}</p>
                      <input type="number" min="0" max="1" step="0.05" value={f.val}
                        onChange={(e) => f.set(e.target.value)}
                        className="field text-sm" style={{ borderColor: `${f.color}50` }} />
                      <p className="text-xs text-[#555] mt-1 font-sans">{f.hint}</p>
                    </div>
                  ))}
                </div>

                {threshErr && <p className="text-xs text-[#ef4444] font-sans">⚠ {threshErr}</p>}

                {/* Simulator */}
                <div className="bg-[#0a0a0a] border border-[#1e1e1e] rounded-lg p-4">
                  <p className="text-[10px] font-bold tracking-widest text-[#444] uppercase mb-3 font-display">Live Risk Simulator</p>
                  <div className="flex items-center gap-4 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[#555] font-sans">Score</span>
                      <input type="number" min="0" max="1" step="0.01" value={simScore}
                        onChange={(e) => setSimScore(e.target.value)}
                        className="w-20 field text-sm" />
                    </div>
                    {validSim && simDecision && (
                      <span className="tag font-bold" style={{ color: simColors[simDecision], background: `${simColors[simDecision]}20`, borderColor: `${simColors[simDecision]}50` }}>
                        <span className="size-1.5 rounded-full" style={{ background: simColors[simDecision] }} />
                        {simDecision.replace("_", " ").toUpperCase()}
                      </span>
                    )}
                    {validSim && (
                      <p className="text-xs text-[#555] ml-auto font-sans">
                        Score <span className="text-white font-mono">{simN.toFixed(2)}</span> → {simDecision?.replace("_", " ")}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </Section>
          </div>

          {/* Save */}
          <div className="flex items-center gap-3 mt-5 pt-4 border-t border-[#1e1e1e]">
            <button type="submit" disabled={saving || !!threshErr} className="btn-primary">
              {saving ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin size-3.5" viewBox="0 0 24 24" fill="none">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="60" strokeDashoffset="20"/>
                  </svg>
                  Saving…
                </span>
              ) : "Save Policy"}
            </button>
            {status === "success" && (
              <span className="text-sm text-[#22c55e] flex items-center gap-1.5 font-sans">
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M2.5 7l3 3 6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                Saved
              </span>
            )}
            {status === "error" && <span className="text-sm text-[#ef4444] font-sans">{errMsg}</span>}
          </div>
        </form>
      )}
    </div>
  );
}
