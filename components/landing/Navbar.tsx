"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { BrandLogo } from "@/components/ui/BrandLogo";
import { DashboardButton } from "@/components/auth/DashboardButton";

const NAV_ITEMS = [
  { label: "Docs", href: "/docs" },
  { label: "Dashboard", href: "/dashboard" },
  { label: "Roadmap", href: "/roadmap" },
  { label: "GitHub", href: "https://github.com/moltwall/moltwall", external: true },
  { label: "npm", href: "https://www.npmjs.com/package/@moltwall/sdk", external: true },
];

export function Navbar() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handle(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, [open]);

  // Close on Escape
  useEffect(() => {
    function handle(e: KeyboardEvent) { if (e.key === "Escape") setOpen(false); }
    document.addEventListener("keydown", handle);
    return () => document.removeEventListener("keydown", handle);
  }, []);

  return (
    <div className="fixed top-5 left-0 right-0 z-50 flex justify-center px-4 pointer-events-none">
      <div ref={ref} className="w-full max-w-xl pointer-events-auto">

        {/* ── Pill bar ──────────────────────────────────────────────────────── */}
        <div className={`flex items-center justify-between px-5 py-3 bg-black border rounded-2xl transition-all duration-200 ${open ? "border-[#FFC400]/40 shadow-[0_0_30px_rgba(255,196,0,0.08)]" : "border-[#2a2a2a] hover:border-[#3a3a3a]"
          }`}>

          {/* Logo + tagline */}
          <BrandLogo variant="full" size="md" href="/" withTagline />

          {/* Right side */}
          <div className="flex items-center gap-3">
            {/* Try Demo -visible when menu closed */}
            <DashboardButton
              onBeforeAction={() => setOpen(false)}
              className={`hidden sm:flex items-center gap-1.5 bg-[#FFC400] text-black text-[12px] font-black uppercase tracking-[0.12em] px-4 py-2 rounded-lg hover:bg-[#e6b000] transition-all font-display ${open ? "opacity-0 pointer-events-none" : "opacity-100"}`}
            >
              TRY DEMO
            </DashboardButton>

            {/* X / Twitter */}
            <a
              href="https://x.com/usemoltwall"
              target="_blank"
              rel="noreferrer"
              aria-label="Follow on X"
              className="size-10 flex items-center justify-center rounded-xl border border-[#2a2a2a] text-[#666] hover:text-white hover:border-[#444] transition-all"
            >
              <svg width="14" height="14" viewBox="0 0 1200 1227" fill="currentColor">
                <path d="M714.163 519.284L1160.89 0H1055.03L667.137 450.887L357.328 0H0L468.492 681.821L0 1226.37H105.866L515.491 750.218L842.672 1226.37H1200L714.163 519.284ZM569.165 687.828L521.697 619.934L144.011 79.6944H306.615L611.412 515.685L658.88 583.579L1055.08 1150.3H892.476L569.165 687.828Z"/>
              </svg>
            </a>

            {/* Hamburger */}
            <button
              onClick={() => setOpen((v) => !v)}
              aria-label="Toggle menu"
              className={`size-10 flex items-center justify-center rounded-xl border transition-all ${open
                ? "border-[#FFC400]/40 bg-[#FFC400]/10 text-[#FFC400]"
                : "border-[#2a2a2a] text-[#666] hover:text-white hover:border-[#444]"
                }`}
            >
              {open ? (
                /* X close */
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M2 2l10 10M12 2L2 12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                </svg>
              ) : (
                /* Hamburger ≡ */
                <svg width="16" height="12" viewBox="0 0 16 12" fill="none">
                  <path d="M1 1h14M1 6h14M1 11h14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                </svg>
              )}
            </button>
          </div>
        </div>

        {/* ── Dropdown ──────────────────────────────────────────────────────── */}
        <div className={`mt-2.5 overflow-hidden transition-all duration-200 ease-out ${open ? "opacity-100 translate-y-0" : "opacity-0 -translate-y-2 pointer-events-none h-0"
          }`}>
          <div className="bg-black border border-[#2a2a2a] rounded-2xl overflow-hidden shadow-[0_16px_48px_rgba(0,0,0,0.6),0_0_0_1px_rgba(255,196,0,0.04)]">

            {/* Nav links */}
            <div className="p-2">
              {NAV_ITEMS.map((item, i) => (
                <div key={item.href}>
                  {i > 0 && <div className="mx-3 border-t border-[#111]" />}
                  {item.external ? (
                    <a
                      href={item.href}
                      target="_blank"
                      rel="noreferrer"
                      onClick={() => setOpen(false)}
                      className="group flex items-center justify-between px-4 py-3.5 rounded-xl hover:bg-[#0f0f0f] transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="size-2 rounded-full bg-[#FFC400]/30 group-hover:bg-[#FFC400]/60 transition-colors shrink-0" />
                        <div>
                          <p className="text-[13px] font-bold text-white tracking-wide">{item.label}</p>
                          <p className="text-[11px] text-[#444] font-mono mt-0.5 tracking-wider">{
                            item.label === "GitHub" ? "↗ github.com/moltwall/moltwall" :
                            item.label === "npm" ? "↗ npmjs.com/package/@moltwall/sdk" : "↗ EXTERNAL"
                          }</p>
                        </div>
                      </div>
                      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#333] group-hover:text-[#555] transition-colors">
                        <path d="M3 11L11 3M11 3H6M11 3v5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </a>
                  ) : (
                    <Link
                      href={item.href}
                      onClick={() => setOpen(false)}
                      className="group flex items-center justify-between px-4 py-3.5 rounded-xl hover:bg-[#0f0f0f] transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="size-2 rounded-full bg-[#FFC400]/30 group-hover:bg-[#FFC400]/60 transition-colors shrink-0" />
                        <div>
                          <p className="text-[13px] font-bold text-white tracking-wide">{item.label}</p>
                          <p className="text-[11px] text-[#444] font-mono mt-0.5 tracking-wider uppercase">{
                            item.href === "/docs" ? "Documentation & API" :
                              item.href === "/dashboard" ? "Security Console" :
                              item.href === "/roadmap" ? "What we're building" : ""
                          }</p>
                        </div>
                      </div>
                      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#333] group-hover:text-[#555] transition-colors">
                        <path d="M3 7h8M8 4l3 3-3 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </Link>
                  )}
                </div>
              ))}
            </div>

            {/* CTA footer */}
            <div className="px-3 pb-3">
              <DashboardButton
                onBeforeAction={() => setOpen(false)}
                className="flex items-center justify-between w-full bg-[#FFC400] text-black px-5 py-3.5 rounded-xl hover:bg-[#e6b000] transition-all group"
              >
                <div>
                  <p className="text-[13px] font-black uppercase tracking-[0.12em] font-display">Launch Dashboard</p>
                  <p className="text-[10px] font-bold tracking-wider text-black/50 mt-0.5 font-mono">FREE · SIGN IN TO CONTINUE</p>
                </div>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="shrink-0 group-hover:translate-x-0.5 transition-transform">
                  <path d="M8 1L1.5 4v4.5c0 3.5 2.8 5.8 6.5 6.5 3.7-.7 6.5-3 6.5-6.5V4L8 1z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                  <path d="M5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </DashboardButton>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}
