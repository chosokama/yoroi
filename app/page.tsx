import Link from "next/link";
import { GridCanvas } from "@/components/ui/GridCanvas";

const FEATURES = [
  {
    kanji: "鎧",
    reading: "YOROI",
    title: "Full-Stack Firewall",
    body: "Every agent action passes through a deterministic policy engine before execution. Allow, deny, sandbox, or require confirmation.",
  },
  {
    kanji: "監",
    reading: "KAN",
    title: "Real-Time Monitoring",
    body: "Every request is scored, every decision logged with full provenance. Complete audit trail across all agents and tools.",
  },
  {
    kanji: "盾",
    reading: "TATE",
    title: "Threat Guardrails",
    body: "Prompt injection, credential leaks, PII exposure, and tool poisoning detected and blocked before damage occurs.",
  },
  {
    kanji: "鍵",
    reading: "KAGI",
    title: "Policy Engine",
    body: "Define allowed tools, blocked actions, trusted domains, and spend limits. Redis-cached, sub-millisecond enforcement.",
  },
  {
    kanji: "禁",
    reading: "KIN",
    title: "Risk Scoring",
    body: "Multi-factor 0–1 risk score computed per-request. Source provenance, payload analysis, intent matching all factored in.",
  },
  {
    kanji: "検",
    reading: "KEN",
    title: "SDK & API",
    body: "Drop-in TypeScript SDK. One function call integrates YOROI into any MCP agent, LangGraph flow, or custom framework.",
  },
];

const HOW_IT_WORKS = [
  { step: "01", label: "Agent Request", desc: "Your agent calls a tool. The YOROI SDK intercepts the call before execution." },
  { step: "02", label: "Policy Check", desc: "Tool allowlist, blocked actions, and spend limits are evaluated instantly from Redis cache." },
  { step: "03", label: "Risk Score", desc: "Payload is scored across 8 weighted factors including source provenance and argument analysis." },
  { step: "04", label: "Guardrail Scan", desc: "Prompt injection, credential patterns, and PII are scanned recursively across nested arguments." },
  { step: "05", label: "Decision", desc: "Allow, Deny, Sandbox, or Require Confirmation — returned in <10ms with a full explanation." },
  { step: "06", label: "Audit Log", desc: "Every decision persisted to Supabase with full trace. Query and export from the dashboard." },
];

export default function LandingPage() {
  return (
    <div className="bg-black text-white min-h-screen font-sans overflow-x-hidden">

      {/* ── Nav ─────────────────────────────────────────────────────────────── */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-[#1a1a1a] bg-black/80 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="size-7 rounded-lg bg-[#FFC400] flex items-center justify-center">
              <span className="text-black text-[12px] font-black font-display">鎧</span>
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-sm font-black tracking-widest font-display text-white">YOROI</span>
              <span className="text-[10px] text-[#555] tracking-widest font-display">鎧</span>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-7 text-[13px] text-[#666]">
            <Link href="/docs" className="hover:text-white transition-colors">Docs</Link>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a>
            <Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/docs"
              className="hidden md:block text-[13px] text-[#888] hover:text-white transition-colors font-medium px-3 py-1.5">
              Docs
            </Link>
            <Link href="/dashboard"
              className="bg-[#FFC400] text-black text-[13px] font-bold uppercase tracking-wider px-4 py-1.5 rounded-lg hover:bg-[#e6b000] transition-colors font-display">
              Try Demo
            </Link>
          </div>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section className="relative min-h-screen flex flex-col items-center justify-center pt-14 overflow-hidden">
        <GridCanvas />

        {/* Kanji watermark */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none select-none overflow-hidden">
          <span className="text-[22rem] font-black text-[#FFC400]/[0.03] leading-none font-display">鎧</span>
        </div>

        <div className="relative z-10 text-center px-6 max-w-5xl mx-auto">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 border border-[#FFC400]/30 bg-[#FFC400]/8 rounded-full px-4 py-1.5 mb-8">
            <span className="size-1.5 rounded-full bg-[#FFC400] animate-pulse" />
            <span className="text-[11px] font-bold tracking-[0.2em] text-[#FFC400] uppercase font-display">AI Agent Security Firewall</span>
          </div>

          {/* Headline */}
          <h1 className="font-display font-black text-white leading-[0.92] uppercase mb-6">
            <span className="block text-[clamp(3.5rem,10vw,7.5rem)]">SECURE EVERY</span>
            <span className="block text-[clamp(3.5rem,10vw,7.5rem)] text-[#FFC400]">AGENT ACTION</span>
            <span className="block text-[clamp(3.5rem,10vw,7.5rem)]">BEFORE IT FIRES</span>
          </h1>

          <p className="text-[#777] text-lg max-w-2xl mx-auto leading-relaxed mb-10">
            YOROI 鎧 is a production-grade security firewall for AI agents. Every tool call evaluated, every threat blocked, every decision audited — in under 10ms.
          </p>

          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link href="/dashboard"
              className="inline-flex items-center gap-2.5 bg-[#FFC400] text-black font-black text-[13px] uppercase tracking-widest px-8 py-4 rounded-xl hover:bg-[#e6b000] transition-all font-display shadow-[0_0_40px_rgba(255,196,0,0.2)]">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 1L1.5 4v4.5c0 3.5 2.8 5.8 6.5 6.5 3.7-.7 6.5-3 6.5-6.5V4L8 1z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                <path d="M5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              Launch Dashboard
            </Link>
            <Link href="/docs"
              className="inline-flex items-center gap-2 text-[13px] font-bold uppercase tracking-widest px-8 py-4 rounded-xl border border-[#2a2a2a] text-[#888] hover:text-white hover:border-[#444] transition-all font-display">
              Read Docs →
            </Link>
          </div>

          {/* Stats row */}
          <div className="mt-16 flex items-center justify-center gap-0 flex-wrap max-w-2xl mx-auto border border-[#1e1e1e] rounded-2xl overflow-hidden bg-[#0a0a0a]/80 backdrop-blur-sm divide-x divide-[#1e1e1e]">
            {([
              { val: "<10ms", label: "Avg Latency" },
              { val: "8+", label: "Threat Vectors" },
              { val: "4", label: "Decision Types" },
              { val: "100%", label: "Audit Coverage" },
            ] as const).map((s) => (
              <div key={s.label} className="flex-1 px-5 py-4 text-center min-w-[100px]">
                <p className="font-display font-black text-xl text-[#FFC400]">{s.val}</p>
                <p className="text-[11px] text-[#555] uppercase tracking-wider mt-0.5 font-sans">{s.label}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-black to-transparent pointer-events-none" />
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
            {FEATURES.map((f) => (
              <div key={f.kanji} className="bg-[#050505] p-8 group hover:bg-[#0c0c0c] transition-colors">
                <div className="mb-5">
                  <span className="text-4xl font-black text-[#FFC400] leading-none font-display block mb-1">{f.kanji}</span>
                  <span className="text-[10px] font-bold tracking-[0.3em] text-[#333] font-display">{f.reading}</span>
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
              HOW YOROI <br />
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
              Drop the YOROI SDK into any TypeScript agent. Works with Claude MCP, LangChain, AutoGPT, CrewAI, and any custom framework. Zero config firewall in one call.
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
              <pre className="p-6 text-[13px] font-mono leading-relaxed overflow-x-auto text-[#FFC400]">{`import { Yoroi } from "@yoroi/sdk";

const wall = new Yoroi({
  apiKey: process.env.YOROI_API_KEY,
  agentId: "my-agent-001",
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
      <section className="relative py-32 px-6 text-center overflow-hidden">
        <GridCanvas />
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse at 50% 50%, rgba(255,196,0,0.08) 0%, transparent 65%)" }} />
        <div className="relative z-10 max-w-3xl mx-auto">
          <span className="text-8xl font-black text-[#FFC400]/10 font-display block mb-2 leading-none">鎧</span>
          <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-display mb-4">Start Today</p>
          <h2 className="font-display font-black text-white text-[clamp(2.5rem,6vw,4.5rem)] uppercase leading-tight mb-5">
            YOUR AGENTS. <br /><span className="text-[#FFC400]">FIREWALLED.</span>
          </h2>
          <p className="text-[#666] mb-10 max-w-xl mx-auto leading-relaxed">
            Deploy YOROI on Vercel in minutes. Open source. TypeScript-native. Production firewall from day one.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link href="/dashboard"
              className="inline-flex items-center gap-2 bg-[#FFC400] text-black font-black text-[13px] uppercase tracking-widest px-8 py-4 rounded-xl hover:bg-[#e6b000] transition-all font-display shadow-[0_0_40px_rgba(255,196,0,0.3)]">
              Open Dashboard
            </Link>
            <Link href="/docs"
              className="inline-flex items-center gap-2 text-[13px] font-bold uppercase tracking-widest px-8 py-4 rounded-xl border border-[#2a2a2a] text-[#777] hover:text-white hover:border-[#444] transition-all font-display">
              Documentation
            </Link>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <footer className="border-t border-[#1a1a1a] py-10 px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="size-6 rounded-md bg-[#FFC400] flex items-center justify-center">
              <span className="text-black text-[11px] font-black font-display">鎧</span>
            </div>
            <span className="text-sm font-black tracking-widest font-display text-white">YOROI</span>
            <span className="text-[#333] text-sm">鎧 — AI Agent Security Firewall</span>
          </div>
          <div className="flex items-center gap-6 text-[13px] text-[#555]">
            <Link href="/docs" className="hover:text-[#FFC400] transition-colors">Docs</Link>
            <Link href="/dashboard" className="hover:text-[#FFC400] transition-colors">Dashboard</Link>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-[#FFC400] transition-colors">GitHub</a>
            <span className="text-[#333]">v0.1.0</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
