"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Navbar } from "@/components/landing/Navbar";
import { GridCanvas } from "@/components/ui/GridCanvas";
import { BrandLogo } from "@/components/ui/BrandLogo";

const PHASES = [
  {
    id: "phase-1",
    phase: "01",
    label: "FOUNDATION",
    period: "March 2026",
    status: "live" as const,
    tag: "LIVE NOW",
    summary: "Core firewall shipped. SDK live. First agents secured.",
    items: [
      { done: true,  text: "Core SDK v1.0 · @moltwall/sdk on npm" },
      { done: true,  text: "8-factor risk scoring engine" },
      { done: true,  text: "Policy engine · allowlists, blocklists, spend limits" },
      { done: true,  text: "Guardrails · prompt injection, PII, credential leak" },
      { done: true,  text: "Decision types · ALLOW / DENY / SANDBOX / CONFIRM" },
      { done: true,  text: "Real-time audit logs via Supabase" },
      { done: true,  text: "Dashboard v1 · live feed + policy manager" },
      { done: true,  text: "5 global instances · sub-10ms latency" },
    ],
  },
  {
    id: "phase-2",
    phase: "02",
    label: "DEVELOPER PLATFORM",
    period: "Q2 2026",
    status: "building" as const,
    tag: "BUILDING",
    summary: "Multi-language support, team tools, and deeper integrations.",
    items: [
      { done: false, text: "Python & Go SDK" },
      { done: false, text: "Custom rule builder · YAML-based policies" },
      { done: false, text: "Webhook notifications · Slack, PagerDuty, custom" },
      { done: false, text: "Team workspaces with RBAC" },
      { done: false, text: "API key scoping & rotation" },
      { done: false, text: "Dashboard v2 · analytics + threat heatmap" },
      { done: false, text: "GitHub Actions integration" },
      { done: false, text: "Rate limiting & per-agent quota management" },
    ],
  },
  {
    id: "phase-3",
    phase: "03",
    label: "ENTERPRISE",
    period: "Q3 2026",
    status: "planned" as const,
    tag: "PLANNED",
    summary: "Enterprise-grade compliance, on-prem, and ML threat detection.",
    items: [
      { done: false, text: "SSO / SAML / OIDC" },
      { done: false, text: "On-premise deployment · Docker + Kubernetes" },
      { done: false, text: "Compliance exports · SOC2, GDPR, HIPAA" },
      { done: false, text: "ML-powered anomaly detection" },
      { done: false, text: "99.99% uptime SLA" },
      { done: false, text: "Dedicated support & priority SLAs" },
      { done: false, text: "Custom model & provider integrations" },
    ],
  },
  {
    id: "phase-4",
    phase: "04",
    label: "ECOSYSTEM",
    period: "Q4 2026",
    status: "planned" as const,
    tag: "PLANNED",
    summary: "Native integrations, community marketplace, threat intelligence.",
    items: [
      { done: false, text: "Native · LangChain, CrewAI, AutoGPT, Dify" },
      { done: false, text: "MoltWall Marketplace · community rule packs" },
      { done: false, text: "Public threat intelligence feed" },
      { done: false, text: "Cross-org threat sharing · opt-in" },
      { done: false, text: "Agent reputation scoring system" },
      { done: false, text: "Partner API & reseller program" },
    ],
  },
  {
    id: "phase-5",
    phase: "05",
    label: "INTELLIGENCE",
    period: "2027",
    status: "future" as const,
    tag: "FUTURE",
    summary: "Adaptive AI security, open protocol, zero-trust agent mesh.",
    items: [
      { done: false, text: "Adaptive policies · ML-driven auto-tuning" },
      { done: false, text: "Zero-trust agent mesh networking" },
      { done: false, text: "MoltWall Protocol · open security standard for agents" },
      { done: false, text: "Agent identity & cryptographic attestation" },
      { done: false, text: "Federated cross-network threat graph" },
      { done: false, text: "On-chain audit trail · optional" },
    ],
  },
];

const STATUS_CONFIG = {
  live:     { color: "#22c55e", bg: "bg-green-500/10",  border: "border-green-500/20",  text: "text-green-400"  },
  building: { color: "#FFC400", bg: "bg-[#FFC400]/10",  border: "border-[#FFC400]/20",  text: "text-[#FFC400]"  },
  planned:  { color: "#555",    bg: "bg-[#555]/10",     border: "border-[#555]/20",     text: "text-[#666]"     },
  future:   { color: "#333",    bg: "bg-[#222]/50",     border: "border-[#222]",        text: "text-[#444]"     },
};

function PhaseCard({
  phase,
  index,
  visible,
}: {
  phase: (typeof PHASES)[number];
  index: number;
  visible: boolean;
}) {
  const cfg = STATUS_CONFIG[phase.status];
  const isLeft = index % 2 === 0;

  return (
    <div
      className={`w-full lg:w-[calc(50%-2.5rem)] transition-all duration-700 ease-out ${
        visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
      } ${isLeft ? "lg:ml-0 lg:mr-auto lg:pr-10" : "lg:ml-auto lg:pl-10"}`}
      style={{ transitionDelay: `${index * 60}ms` }}
    >
      <div
        className={`relative bg-[#080808] border rounded-2xl p-6 group transition-all duration-300 hover:border-[#FFC400]/20 hover:shadow-[0_0_40px_rgba(255,196,0,0.05)] ${
          phase.status === "live"
            ? "border-green-500/30 shadow-[0_0_30px_rgba(34,197,94,0.06)]"
            : "border-[#1e1e1e]"
        }`}
      >
        {/* Phase number + tag */}
        <div className="flex items-center justify-between mb-4">
          <span className="font-display font-black text-4xl text-[#FFC400]/20 leading-none">
            {phase.phase}
          </span>
          <span
            className={`text-[9px] font-bold uppercase tracking-[0.2em] px-2.5 py-1 rounded-lg border font-mono ${cfg.bg} ${cfg.border} ${cfg.text}`}
          >
            {phase.tag}
          </span>
        </div>

        {/* Label + period */}
        <h3 className="font-display font-black text-white text-xl uppercase tracking-wide mb-1">
          {phase.label}
        </h3>
        <p className="text-[11px] font-mono text-[#444] uppercase tracking-widest mb-3">
          {phase.period}
        </p>
        <p className="text-[#555] text-[13px] leading-relaxed mb-5 border-b border-[#111] pb-5">
          {phase.summary}
        </p>

        {/* Items */}
        <ul className="space-y-2.5">
          {phase.items.map((item, i) => (
            <li key={i} className="flex items-start gap-3">
              <span
                className={`shrink-0 mt-0.5 w-4 h-4 rounded flex items-center justify-center text-[9px] font-bold ${
                  item.done
                    ? "bg-green-500/20 border border-green-500/40 text-green-400"
                    : phase.status === "building"
                    ? "bg-[#FFC400]/10 border border-[#FFC400]/20 text-[#FFC400]/60"
                    : "bg-[#111] border border-[#2a2a2a] text-[#333]"
                }`}
              >
                {item.done ? "✓" : "·"}
              </span>
              <span
                className={`text-[12px] font-mono leading-relaxed ${
                  item.done ? "text-[#888]" : "text-[#444]"
                }`}
              >
                {item.text}
              </span>
            </li>
          ))}
        </ul>

        {/* Live pulse */}
        {phase.status === "live" && (
          <div className="absolute -top-1.5 -right-1.5 flex items-center gap-1.5 bg-black border border-green-500/30 rounded-full px-2.5 py-1">
            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse shadow-[0_0_6px_rgba(34,197,94,1)]" />
            <span className="text-[9px] font-bold text-green-400 uppercase tracking-wider font-mono">Live</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function RoadmapPage() {
  const ladderRef = useRef<HTMLDivElement>(null);
  const [fillPct, setFillPct] = useState(0);
  const [visiblePhases, setVisiblePhases] = useState<Set<number>>(new Set());
  const phaseRefs = useRef<(HTMLDivElement | null)[]>([]);

  // Scroll-driven ladder fill
  useEffect(() => {
    const handleScroll = () => {
      if (!ladderRef.current) return;
      const rect = ladderRef.current.getBoundingClientRect();
      const total = ladderRef.current.offsetHeight;
      const scrolled = -rect.top + window.innerHeight * 0.5;
      setFillPct(Math.max(0, Math.min(100, (scrolled / total) * 100)));
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Intersection observer for phase cards
  useEffect(() => {
    const observers: IntersectionObserver[] = [];
    phaseRefs.current.forEach((el, i) => {
      if (!el) return;
      const obs = new IntersectionObserver(
        ([entry]) => {
          if (entry?.isIntersecting) {
            setVisiblePhases((prev) => new Set([...prev, i]));
          }
        },
        { threshold: 0.15 }
      );
      obs.observe(el);
      observers.push(obs);
    });
    return () => observers.forEach((o) => o.disconnect());
  }, []);

  // Climber rung index based on fill
  const climberPhase = Math.min(
    PHASES.length - 1,
    Math.floor((fillPct / 100) * PHASES.length)
  );

  return (
    <div className="bg-black text-white min-h-screen font-sans overflow-x-hidden">
      <Navbar />
      <div className="h-[96px]" />

      {/* ── Hero ── */}
      <section className="relative py-20 px-6 overflow-hidden">
        <GridCanvas />
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse at 50% 0%, rgba(255,196,0,0.07) 0%, transparent 60%)" }} />
        <div className="relative z-10 max-w-4xl mx-auto text-center">
          <p className="text-[11px] font-bold tracking-[0.25em] text-[#FFC400] uppercase font-mono mb-4">
            MoltWall · Public Roadmap
          </p>
          <h1 className="font-display font-black text-white text-[clamp(3rem,8vw,6rem)] uppercase leading-none mb-6">
            BUILDING THE<br />
            <span className="text-[#FFC400] drop-shadow-[0_0_40px_rgba(255,196,0,0.4)]">FUTURE</span>
          </h1>
          <p className="text-[#555] text-[15px] leading-relaxed max-w-lg mx-auto mb-8">
            Every phase takes us closer to a world where no AI agent can cause harm without being caught.
          </p>
          <div className="flex items-center justify-center gap-6 flex-wrap text-[11px] font-mono uppercase tracking-widest">
            {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
              <div key={key} className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: cfg.color }} />
                <span className="text-[#444]">{key}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Ladder + Phases ── */}
      <section className="relative py-16 px-6" ref={ladderRef}>
        <div className="max-w-5xl mx-auto">

          {/* ── Center ladder (desktop) ── */}
          <div className="hidden lg:block absolute left-1/2 -translate-x-1/2 top-16 bottom-16 w-10 pointer-events-none" aria-hidden="true">
            {/* Left rail */}
            <div className="absolute left-1 top-0 bottom-0 w-px bg-[#1a1a1a]" />
            {/* Right rail */}
            <div className="absolute right-1 top-0 bottom-0 w-px bg-[#1a1a1a]" />

            {/* Fill overlay — left rail */}
            <div
              className="absolute left-1 top-0 w-px bg-gradient-to-b from-[#FFC400] to-[#FFC400]/40 transition-all duration-150"
              style={{ height: `${fillPct}%` }}
            />
            {/* Fill overlay — right rail */}
            <div
              className="absolute right-1 top-0 w-px bg-gradient-to-b from-[#FFC400] to-[#FFC400]/40 transition-all duration-150"
              style={{ height: `${fillPct}%` }}
            />

            {/* Rungs */}
            {PHASES.map((_, i) => {
              const pct = ((i + 0.5) / PHASES.length) * 100;
              const reached = fillPct >= pct - 2;
              return (
                <div
                  key={i}
                  className="absolute left-0 right-0 h-px transition-colors duration-500"
                  style={{
                    top: `${pct}%`,
                    backgroundColor: reached ? "#FFC400" : "#1e1e1e",
                  }}
                />
              );
            })}

            {/* Climber orb */}
            <div
              className="absolute left-1/2 -translate-x-1/2 -translate-y-1/2 transition-all duration-300 ease-out"
              style={{ top: `${fillPct}%` }}
            >
              {/* Outer glow */}
              <div className="absolute inset-0 w-6 h-6 -translate-x-1/2 -translate-y-1/2 rounded-full bg-[#FFC400]/20 blur-md animate-pulse" />
              {/* Core */}
              <div className="relative w-4 h-4 -translate-x-1/2 -translate-y-1/2 rounded-full bg-[#FFC400] shadow-[0_0_16px_rgba(255,196,0,0.9),0_0_4px_rgba(255,196,0,1)] flex items-center justify-center">
                <div className="w-1.5 h-1.5 rounded-full bg-black" />
              </div>
              {/* Phase label tooltip */}
              <div className="absolute left-6 top-1/2 -translate-y-1/2 -translate-x-0 whitespace-nowrap bg-[#0a0a0a] border border-[#FFC400]/30 rounded-lg px-2.5 py-1 pointer-events-none">
                <span className="text-[9px] font-mono font-bold text-[#FFC400] uppercase tracking-wider">
                  {PHASES[climberPhase]?.period}
                </span>
              </div>
            </div>
          </div>

          {/* ── Phase rows ── */}
          <div className="space-y-16 lg:space-y-24">
            {PHASES.map((phase, i) => {
              const pct = ((i + 0.5) / PHASES.length) * 100;
              const isLeft = i % 2 === 0;
              const reached = fillPct >= pct - 2;

              return (
                <div
                  key={phase.id}
                  ref={(el) => { phaseRefs.current[i] = el; }}
                  className="relative flex flex-col lg:flex-row items-center"
                >
                  {/* Mobile: left line indicator */}
                  <div className="lg:hidden absolute left-4 top-0 bottom-0 w-px bg-[#1a1a1a]">
                    <div
                      className="w-full bg-[#FFC400] transition-all duration-700"
                      style={{ height: visiblePhases.has(i) ? "100%" : "0%" }}
                    />
                  </div>

                  {/* Center rung node (desktop) */}
                  <div className="hidden lg:flex absolute left-1/2 -translate-x-1/2 items-center justify-center z-10">
                    <div
                      className={`w-3 h-3 rounded-full border-2 transition-all duration-700 ${
                        reached
                          ? "bg-[#FFC400] border-[#FFC400] shadow-[0_0_12px_rgba(255,196,0,0.8)]"
                          : "bg-black border-[#333]"
                      }`}
                    />
                  </div>

                  {/* Mobile: node */}
                  <div className="lg:hidden absolute left-4 -translate-x-1/2 top-6 z-10">
                    <div
                      className={`w-3 h-3 rounded-full border-2 transition-all duration-700 ${
                        visiblePhases.has(i)
                          ? "bg-[#FFC400] border-[#FFC400] shadow-[0_0_10px_rgba(255,196,0,0.7)]"
                          : "bg-black border-[#333]"
                      }`}
                    />
                  </div>

                  {/* Spacer for left side on desktop */}
                  {!isLeft && <div className="hidden lg:block w-[calc(50%-2.5rem)]" />}

                  {/* Card */}
                  <PhaseCard
                    phase={phase}
                    index={i}
                    visible={visiblePhases.has(i)}
                  />

                  {/* Spacer for right side on desktop */}
                  {isLeft && <div className="hidden lg:block w-[calc(50%-2.5rem)]" />}
                </div>
              );
            })}
          </div>

          {/* ── Bottom cap ── */}
          <div className="relative flex flex-col items-center mt-24 pt-16 border-t border-[#111]">
            <div className="text-center max-w-md">
              <span className="text-[clamp(2rem,5vw,3.5rem)] font-black text-[#FFC400]/10 font-display block leading-none mb-4">∞</span>
              <p className="text-[11px] font-mono text-[#333] uppercase tracking-widest mb-2">And beyond</p>
              <p className="text-[#444] text-sm leading-relaxed">
                The roadmap evolves with the threat landscape. Follow{" "}
                <a href="https://x.com/usemoltwall" target="_blank" rel="noreferrer" className="text-[#FFC400] hover:underline">
                  @usemoltwall
                </a>{" "}
                for real-time updates.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
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
            <Link href="/roadmap" className="hover:text-[#FFC400] transition-colors">Roadmap</Link>
            <span>·</span>
            <Link href="/terms" className="hover:text-[#FFC400] transition-colors">Terms</Link>
            <span>·</span>
            <Link href="/privacy" className="hover:text-[#FFC400] transition-colors">Privacy</Link>
            <span>·</span>
            <a href="https://x.com/usemoltwall" target="_blank" rel="noreferrer" aria-label="Follow on X" className="hover:text-[#FFC400] transition-colors inline-flex items-center">
              <svg width="11" height="11" viewBox="0 0 1200 1227" fill="currentColor">
                <path d="M714.163 519.284L1160.89 0H1055.03L667.137 450.887L357.328 0H0L468.492 681.821L0 1226.37H105.866L515.491 750.218L842.672 1226.37H1200L714.163 519.284ZM569.165 687.828L521.697 619.934L144.011 79.6944H306.615L611.412 515.685L658.88 583.579L1055.08 1150.3H892.476L569.165 687.828Z"/>
              </svg>
            </a>
          </div>
          <p className="pt-2 text-[12px] text-[#333] font-sans">
            © {new Date().getFullYear()} · www.moltwall.xyz
          </p>
        </div>
      </footer>
    </div>
  );
}
