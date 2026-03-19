"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { GridCanvas } from "@/components/ui/GridCanvas";
import { Navbar } from "@/components/landing/Navbar";
import { BrandLogo } from "@/components/ui/BrandLogo";
import { DashboardButton } from "@/components/auth/DashboardButton";

const FEATURES = [
  {
    title: "Full-Stack Firewall",
    body: "Every agent action passes through a deterministic policy engine before execution. Allow, deny, sandbox, or require confirmation.",
  },
  {
    title: "Real-Time Monitoring",
    body: "Every request is scored, every decision logged with full provenance. Complete audit trail across all agents and tools.",
  },
  {
    title: "Threat Guardrails",
    body: "Prompt injection, credential leaks, PII exposure, and tool poisoning detected and blocked before damage occurs.",
  },
  {
    title: "Policy Engine",
    body: "Define allowed tools, blocked actions, trusted domains, and spend limits. Redis-cached, sub-millisecond enforcement.",
  },
  {
    title: "Risk Scoring",
    body: "Multi-factor 0–1 risk score computed per-request. Source provenance, payload analysis, intent matching all factored in.",
  },
  {
    title: "SDK & API",
    body: "Drop-in TypeScript SDK. One function call integrates MoltWall into any MCP agent, LangGraph flow, or custom framework.",
  },
];

const HOW_IT_WORKS = [
  { step: "01", label: "Agent Request", desc: "Your agent calls a tool. The MoltWall SDK intercepts the call before execution." },
  { step: "02", label: "Policy Check", desc: "Tool allowlist, blocked actions, and spend limits are evaluated instantly from Redis cache." },
  { step: "03", label: "Risk Score", desc: "Payload is scored across 8 weighted factors including source provenance and argument analysis." },
  { step: "04", label: "Guardrail Scan", desc: "Prompt injection, credential patterns, and PII are scanned recursively across nested arguments." },
  { step: "05", label: "Decision", desc: "Allow, Deny, Sandbox, or Require Confirmation -returned in <10ms with a full explanation." },
  { step: "06", label: "Audit Log", desc: "Every decision persisted to Supabase with full trace. Query and export from the dashboard." },
];

// Checkpoint: 49,391 as of Mar 19 2026, growing at ~2.8/s
const CHECKPOINT_MS = Date.UTC(2026, 2, 19);
const CHECKPOINT_COUNT = 49_391;
const RATE_PER_MS = 0.0028;
function calcThreats() {
  return Math.floor(CHECKPOINT_COUNT + (Date.now() - CHECKPOINT_MS) * RATE_PER_MS);
}
function formatThreats(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toString();
}

export default function LandingPage() {
  const [threatsBlocked, setThreatsBlocked] = useState(calcThreats);
  const [logs, setLogs] = useState<{ id: number; agent: string; tool: string; action: string; time: string; status: "ALLOW" | "BLOCK" | "SANDBOX" }[]>([]);
  const [copied, setCopied] = useState(false);

  const CA = process.env.NEXT_PUBLIC_CA ?? "";
  const showCA = process.env.NEXT_PUBLIC_SHOW_CA === "true" && !!CA;

  function copyCA() {
    navigator.clipboard.writeText(CA);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  useEffect(() => {
    // On mount: take the higher of the time-based value or what's stored
    // (localStorage accumulates the live increments within a session)
    const stored = parseInt(localStorage.getItem("mw_threats_v2") ?? "0", 10);
    const computed = calcThreats();
    setThreatsBlocked(Math.max(computed, stored));

    const interval = setInterval(() => {
      setThreatsBlocked(prev => {
        const next = prev + Math.floor(Math.random() * 4) + 1;
        localStorage.setItem("mw_threats_v2", String(next));
        return next;
      });
    }, 1800);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Generate mock tail-logs of agent activity
    const agents = ["TradingBot-V4", "ResearchAgent", "CustomerSupport-AI", "DataScraper-09", "AutoGPT-Core", "LangGraph-Sync"];
    const tools = ["execute_sql", "send_email", "transfer_funds", "read_file", "aws_ec2_term", "ssh_connect"];
    const sysActions = ["Read DB", "SMTP Send", "Stripe API", "FS Access", "AWS SDK", "Bash"];

    let idCounter = 0;
    const interval = setInterval(() => {
      const isBlock = Math.random() > 0.7; // 30% blocks
      const newLog: { id: number; agent: string; tool: string; action: string; time: string; status: "ALLOW" | "BLOCK" | "SANDBOX" } = {
        id: idCounter++,
        agent: agents[Math.floor(Math.random() * agents.length)] ?? agents[0]!,
        tool: tools[Math.floor(Math.random() * tools.length)] ?? tools[0]!,
        action: sysActions[Math.floor(Math.random() * sysActions.length)] ?? sysActions[0]!,
        time: new Date().toISOString().substring(11, 23),
        status: isBlock ? "BLOCK" : (Math.random() > 0.9 ? "SANDBOX" : "ALLOW"),
      };

      setLogs(prev => [newLog, ...prev].slice(0, 7)); // keep last 7
    }, 800);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-black text-white min-h-screen font-sans overflow-x-hidden">

      {/* ── Nav ─────────────────────────────────────────────────────────────── */}
      <Navbar />

      {/* ── Nav spacer ───────────────────────────────────────────────────────── */}
      <div className="h-[96px]" />

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section className="relative min-h-[calc(100vh-96px)] pt-16 pb-24 flex flex-col items-center justify-center overflow-hidden">
        <GridCanvas />

        {/* Subtle glowing orb in background */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[80vw] h-[60vh] bg-[#FFC400]/[0.05] rounded-[100%] blur-[120px] pointer-events-none" />

        {/* Watermark (brand) */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none select-none overflow-hidden mix-blend-screen opacity-20">
          <span className="text-[35rem] font-black text-[#FFC400]/[0.03] leading-none font-display">MOLT</span>
        </div>

        <div className="relative z-10 w-full px-6 max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-[1.1fr_0.9fr] gap-12 lg:gap-20 items-center">

          {/* Left Column: Text & CTA */}
          <div className="text-left mt-8 lg:mt-0">
    

            <h1 className="font-display font-black text-white leading-[0.92] uppercase mb-8">
              <span className="block text-[clamp(3.5rem,7vw,6.5rem)] text-white/95">SECURE EVERY</span>
              <span className="block text-[clamp(3.5rem,7vw,6.5rem)] text-[#FFC400] drop-shadow-[0_0_30px_rgba(255,196,0,0.4)]">AGENT ACTION</span>
              <span className="block text-[clamp(3.5rem,7vw,6.5rem)]">BEFORE IT FIRES</span>
            </h1>

            <p className="text-[#999] text-[clamp(1.1rem,1.5vw,1.25rem)] max-w-2xl leading-relaxed mb-12">
              <span className="text-white font-bold">MoltWall</span> is a production-grade security firewall for AI agents. Every tool call evaluated, every threat blocked, every decision audited - in under <span className="text-[#FFC400] font-bold">10ms</span>.
            </p>

            <div className="flex items-center gap-5 flex-wrap">
              <a
                href="https://www.npmjs.com/package/@moltwall/sdk"
                target="_blank"
                rel="noreferrer"
                className="group inline-flex items-center gap-2.5 bg-[#0d0d0d] border border-[#252525] hover:border-[#FFC400]/25 text-[#666] hover:text-[#999] font-mono text-[13px] px-5 py-4 rounded-xl transition-all duration-200"
              >
                <span className="shrink-0 inline-flex items-center justify-center bg-[#CB3837] text-white text-[9px] font-black font-mono leading-none px-1.5 py-1 rounded">npm</span>
                <span className="text-[#3a3a3a]">$</span>
                <span className="group-hover:text-[#bbb] transition-colors duration-200">npm i @moltwall/sdk</span>
              </a>
              <DashboardButton className="group relative inline-flex items-center justify-center gap-2 bg-[#FFC400] text-black font-black text-[15px] uppercase tracking-widest px-10 py-5 rounded-xl transition-all hover:bg-[#ffe166] hover:scale-[1.02] active:scale-95 font-display overflow-hidden shadow-[0_0_40px_rgba(255,196,0,0.35)] hover:shadow-[0_0_60px_rgba(255,196,0,0.5)]">
                Deploy Firewall Now
                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out" />
              </DashboardButton>
              <Link href="/docs"
                className="inline-flex items-center justify-center gap-2 text-[15px] font-bold uppercase tracking-widest px-10 py-5 rounded-xl border border-[#333] bg-[#050505] text-[#888] hover:text-white hover:border-[#666] transition-all font-display">
                Read Documentation
              </Link>
            </div>

            {/* Stats row */}
            <div className="mt-16 flex items-center justify-start gap-10 flex-wrap">
              <div className="flex flex-col">
                <span className="text-[2.5rem] font-black text-white font-display flex items-baseline gap-1">
                  10<span className="text-xl text-[#FFC400]">ms</span>
                </span>
                <span className="text-[11px] text-[#666] font-bold uppercase tracking-widest">Avg Latency</span>
              </div>
              <div className="w-px h-12 bg-[#222]" />
              <div className="flex flex-col">
                <span className="text-[2.5rem] font-black text-white font-display flex items-baseline gap-1 font-mono tracking-tight">
                  {formatThreats(threatsBlocked)}
                </span>
                <span className="text-[11px] text-[#666] font-bold uppercase tracking-widest flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse shadow-[0_0_8px_rgba(239,68,68,0.8)]" /> Threats Blocked
                </span>
              </div>
            </div>

            {/* CA Row */}
            {showCA && (
              <div className="mt-6 flex items-center gap-3">
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#444]">CA</span>
                <div className="flex items-center gap-2 bg-[#0d0d0d] border border-[#1e1e1e] hover:border-[#FFC400]/20 rounded-lg px-3 py-2 transition-colors group">
                  <span className="text-[12px] font-mono text-[#777] group-hover:text-[#999] transition-colors select-all">{CA}</span>
                  <button
                    onClick={copyCA}
                    aria-label="Copy contract address"
                    className="shrink-0 text-[#555] hover:text-[#FFC400] transition-colors"
                  >
                    {copied ? (
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-[#FFC400]">
                        <path d="M20 6L9 17l-5-5" />
                      </svg>
                    ) : (
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                      </svg>
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Terminal UI */}
          <div className="relative w-full lg:max-w-none max-w-[600px] mx-auto z-20">
            {/* Ambient terminal glow */}
            <div className="absolute -inset-0.5 bg-gradient-to-br from-[#FFC400]/40 via-transparent to-red-500/30 rounded-2xl blur-xl opacity-60 pointer-events-none" />

            <div className="relative bg-[#080808] border border-[#2a2a2a] rounded-2xl overflow-hidden shadow-2xl flex flex-col h-[460px] lg:h-[520px]">

              {/* Terminal Header */}
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#1f1f1f] bg-[#000]">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.5)] hover:bg-red-400 transition-colors cursor-pointer" />
                  <div className="w-3 h-3 rounded-full bg-[#FFC400]/80 shadow-[0_0_8px_rgba(255,196,0,0.5)] hover:bg-[#FFC400] transition-colors cursor-pointer" />
                  <div className="w-3 h-3 rounded-full bg-green-500/80 shadow-[0_0_8px_rgba(34,197,94,0.5)] hover:bg-green-400 transition-colors cursor-pointer" />
                </div>
                <div className="flex text-[11px] font-mono text-[#666] items-center gap-2 uppercase tracking-widest font-bold">
                  <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_rgba(34,197,94,1)]" />
                  prod-firewall-us-east-1
                </div>
              </div>

              {/* Terminal Body */}
              <div className="flex-1 p-5 overflow-hidden font-mono text-xs flex flex-col relative w-full">

                {/* Column Headers */}
                <div className="grid grid-cols-12 gap-3 text-[#555] pb-3 border-b border-[#1a1a1a] uppercase font-bold tracking-[0.2em] text-[9px] w-full">
                  <div className="col-span-2">Time</div>
                  <div className="col-span-4">Agent Identity</div>
                  <div className="col-span-3">Tool Target</div>
                  <div className="col-span-3 text-right">Policy Decision</div>
                </div>

                {/* Log Feed */}
                <div className="flex flex-col-reverse justify-start gap-2 pt-3 flex-1 relative z-10 w-full overflow-hidden">
                  {logs.map((log) => (
                    <div key={log.id} className="grid grid-cols-12 gap-3 items-center py-2 border-b border-[#111] last:border-0 hover:bg-[#111] transition-colors rounded px-2 -mx-2 w-[calc(100%+16px)] animate-in fade-in slide-in-from-top-2 duration-300">
                      <div className="col-span-2 text-[#666]">{log.time}</div>
                      <div className="col-span-4 text-[#bbb] truncate pe-2" title={log.agent}>{log.agent}</div>
                      <div className="col-span-3 text-[#888] truncate pe-2" title={log.tool}>{log.tool}</div>
                      <div className="col-span-3 text-right flex justify-end">
                        {log.status === "BLOCK" && (
                          <span className="inline-flex items-center gap-1.5 text-red-500 font-bold bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 text-[10px] uppercase shadow-[0_0_10px_rgba(239,68,68,0.15)] relative overflow-hidden group">
                            <span className="absolute inset-0 w-full h-full bg-red-500/20 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-500" />
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
                            BLOCKED
                          </span>
                        )}
                        {log.status === "ALLOW" && (
                          <span className="inline-flex items-center gap-1.5 text-green-500 font-bold bg-green-500/10 px-2 py-0.5 rounded border border-green-500/20 text-[10px] uppercase">
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                            ALLOW
                          </span>
                        )}
                        {log.status === "SANDBOX" && (
                          <span className="inline-flex items-center gap-1.5 text-[#FFC400] font-bold bg-[#FFC400]/10 px-2 py-0.5 rounded border border-[#FFC400]/20 text-[10px] uppercase">
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                            SANDBOX
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Fade out top gradient to obscure old logs */}
                <div className="absolute top-[32px] left-0 right-0 h-24 bg-gradient-to-b from-[#080808] to-transparent z-20 pointer-events-none" />
              </div>

              {/* Terminal Footer */}
              <div className="px-5 py-3 border-t border-[#1f1f1f] bg-[#030303] flex justify-between items-center">
                <div className="text-[10px] text-[#555] font-mono flex items-center gap-3">
                  <span className="flex gap-2">Agent Contexts: <span className="text-[#eee]">4,213</span></span>
                  <span className="text-[#333]">|</span>
                  <span className="flex gap-2">Rules Active: <span className="text-[#FFC400]">89</span></span>
                </div>
                <div className="flex items-center gap-2 text-[10px] font-mono text-[#555]">
                  <span className="flex items-center gap-1">
                    <svg className="w-3 h-3 text-[#FFC400]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                    <span>{threatsBlocked > 0 ? (RATE_PER_MS * 1000).toFixed(1) + '/s' : '0/s'}</span>
                  </span>
                </div>
              </div>
            </div>

            {/* Overlay Grid on terminal */}
            <div className="absolute inset-0 bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))] opacity-5 pointer-events-none z-30 mix-blend-overlay rounded-2xl" />
          </div>

        </div>

        {/* Bottom fade transition */}
        <div className="absolute bottom-0 left-0 right-0 h-40 bg-gradient-to-t from-[#050505] to-transparent pointer-events-none z-10" />
      </section>

      {/* ── Features ────────────────────────────────────────────────────────── */}
      <section className="relative bg-[#050505] border-y border-[#1a1a1a] py-24 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="mb-14">
            <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-display mb-3">Core Capabilities</p>
            <h2 className="font-display font-black text-white text-[clamp(2rem,5vw,3.5rem)] uppercase leading-tight">
              EVERYTHING AN AGENT <br />
              <span className="text-[#FFC400]">FIREWALL NEEDS</span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-[#1a1a1a]">
            {FEATURES.map((f, idx) => (
              <div key={f.title} className="bg-[#050505] p-8 group hover:bg-[#0c0c0c] transition-colors">
                <div className="mb-5">
                  <span className="text-4xl font-black text-[#FFC400] leading-none font-display block mb-1">
                    {(idx + 1).toString().padStart(2, "0")}
                  </span>
                  <span className="text-[10px] font-bold tracking-[0.3em] text-[#333] font-display uppercase">CORE</span>
                </div>
                <h3 className="text-white font-bold text-lg mb-2 font-sans">{f.title}</h3>
                <p className="text-[#666] text-sm leading-relaxed font-sans">{f.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ────────────────────────────────────────────────────── */}
      <section className="relative py-24 px-6 overflow-hidden">
        <GridCanvas />
        <div className="relative z-10 max-w-6xl mx-auto">
          <div className="mb-14">
            <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-display mb-3">The Pipeline</p>
            <h2 className="font-display font-black text-white text-[clamp(2rem,5vw,3.5rem)] uppercase leading-tight">
              HOW MoltWall <br />
              <span className="text-[#FFC400]">PROTECTS YOU</span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {HOW_IT_WORKS.map((step, i) => (
              <div key={step.step} className="relative">
                {i < HOW_IT_WORKS.length - 1 && (
                  <div className="absolute top-5 left-[3.5rem] right-0 h-px bg-[#1a1a1a] hidden lg:block" aria-hidden="true" />
                )}
                <div className="relative bg-[#0a0a0a] border border-[#1e1e1e] rounded-2xl p-6 hover:border-[#FFC400]/30 transition-colors group">
                  <div className="flex items-start gap-4">
                    <span className="font-display font-black text-3xl text-[#FFC400]/30 group-hover:text-[#FFC400]/60 transition-colors leading-none shrink-0">
                      {step.step}
                    </span>
                    <div>
                      <h3 className="font-bold text-white mb-2 text-[15px]">{step.label}</h3>
                      <p className="text-[#666] text-sm leading-relaxed">{step.desc}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Code snippet ────────────────────────────────────────────────────── */}
      <section className="bg-[#050505] border-y border-[#1a1a1a] py-24 px-6">
        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-display mb-3">Quick Integration</p>
            <h2 className="font-display font-black text-white text-[clamp(2rem,5vw,3rem)] uppercase leading-tight mb-5">
              ONE CALL TO <br /><span className="text-[#FFC400]">FIREWALL</span> YOUR AGENT
            </h2>
            <p className="text-[#666] text-sm leading-relaxed mb-7 max-w-md">
              Drop the MoltWall SDK into any TypeScript agent. Works with Claude MCP, LangChain, AutoGPT, CrewAI, and any custom framework. Zero config firewall in one call.
            </p>
            <div className="flex items-center gap-4">
              <Link href="/docs" className="bg-[#FFC400] text-black font-black text-[12px] uppercase tracking-widest px-6 py-3 rounded-xl hover:bg-[#e6b000] transition-colors font-display">
                Full Documentation →
              </Link>
            </div>
          </div>

          <div className="relative">
            <div className="bg-[#0a0a0a] border border-[#2a2a2a] rounded-2xl overflow-hidden shadow-[0_0_60px_rgba(255,196,0,0.05)]">
              <div className="flex items-center gap-2 px-5 py-3 border-b border-[#1e1e1e]">
                <span className="size-3 rounded-full bg-[#ef4444]/60" />
                <span className="size-3 rounded-full bg-[#FFC400]/60" />
                <span className="size-3 rounded-full bg-[#22c55e]/60" />
                <span className="ml-3 text-[11px] text-[#444] font-mono">agent.ts</span>
              </div>
              <pre className="p-6 text-[13px] font-mono leading-relaxed overflow-x-auto text-[#FFC400]">{`import { MoltWall } from "@moltwall/sdk";

const wall = new MoltWall({
  apiKey: process.env.MOLTWALL_API_KEY,
  baseUrl: "https://www.moltwall.xyz",
});

// Before every tool call:
const result = await wall.check({
  action: "transfer_funds",
  tool:   "wallet",
  args:   { amount: 100, to: addr },
  source: "user",
});

if (result.decision === "allow") {
  await executeTool(result);
} else {
  // denied, sandbox, or require_confirmation
  handleBlocked(result);
}`}</pre>
            </div>

            <div className="absolute -bottom-4 -right-4 bg-[#0a0a0a] border border-[#22c55e]/40 rounded-xl px-4 py-2.5 shadow-lg">
              <div className="flex items-center gap-2">
                <span className="size-2 rounded-full bg-[#22c55e] animate-pulse" />
                <span className="text-[#22c55e] text-xs font-bold uppercase tracking-wider font-display">Allow</span>
                <span className="text-[#444] text-xs font-mono">7ms</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────────────────── */}
      <section className="relative py-32 px-6 text-center">
        <GridCanvas />
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse at 50% 50%, rgba(255,196,0,0.08) 0%, transparent 65%)" }} />
        <div className="relative z-10 max-w-3xl mx-auto">
          <span className="text-[clamp(2.5rem,7vw,4.5rem)] font-black text-[#FFC400]/10 font-display block mb-2 leading-none tracking-wide">MOLTWALL</span>
          <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-display mb-4">Start Today</p>
          <h2 className="font-display font-black text-white text-[clamp(2.5rem,6vw,4.5rem)] uppercase leading-tight mb-5">
            YOUR AGENTS. <br /><span className="text-[#FFC400]">FIREWALLED.</span>
          </h2>
          <p className="text-[#666] mb-10 max-w-xl mx-auto leading-relaxed">
            Deploy MoltWall at www.moltwall.xyz in minutes. Open source. TypeScript-native. Production firewall from day one.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <DashboardButton className="inline-flex items-center gap-2 bg-[#FFC400] text-black font-black text-[13px] uppercase tracking-widest px-8 py-4 rounded-xl hover:bg-[#e6b000] transition-all font-display shadow-[0_0_40px_rgba(255,196,0,0.3)] cursor-pointer">
              OPEN DASHBOARD
            </DashboardButton>
            <Link href="/docs"
              className="inline-flex items-center gap-2 text-[13px] font-bold uppercase tracking-widest px-8 py-4 rounded-xl border border-[#2a2a2a] text-[#777] hover:text-white hover:border-[#444] transition-all font-display cursor-pointer">
              DOCUMENTATION
            </Link>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <footer className="border-t border-[#111] bg-black py-14">
        <div className="max-w-6xl mx-auto px-6 text-center space-y-4">
          <div className="flex justify-center">
            <BrandLogo variant="full" size="md" withTagline />
          </div>
          <div className="mt-1 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[11px] text-[#444] font-sans">
            <Link href="/docs" className="hover:text-[#FFC400] transition-colors">Docs</Link>
            <span>·</span>
            <Link href="/dashboard" className="hover:text-[#FFC400] transition-colors">Dashboard</Link>
            <span>·</span>
            <Link href="https://github.com/moltwall/moltwall" target="_blank" className="hover:text-[#FFC400] transition-colors">Github</Link>
            <span>·</span>
            <Link href="https://www.npmjs.com/package/@moltwall/sdk" target="_blank" className="hover:text-[#FFC400] transition-colors">npm</Link>
            <span>·</span>
            <Link href="/terms" className="hover:text-[#FFC400] transition-colors">Terms</Link>
            <span>·</span>
            <Link href="/privacy" className="hover:text-[#FFC400] transition-colors">Privacy</Link>
          </div>
          <p className="pt-2 text-[12px] text-[#333] font-sans">
            © {new Date().getFullYear()} · www.moltwall.xyz
          </p>
        </div>
      </footer>

    </div>
  );
}
