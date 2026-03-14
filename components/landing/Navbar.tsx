"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";

const NAV_ITEMS = [
  { label: "Docs",       href: "/docs",      kanji: "書" },
  { label: "Dashboard",  href: "/dashboard", kanji: "監" },
  { label: "GitHub",     href: "https://github.com", kanji: "源", external: true },
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
    <div className="fixed top-5 left-0 right-0 z-50 flex justify-center px-4">
      <div ref={ref} className="w-full max-w-xl">

        {/* ── Pill bar ──────────────────────────────────────────────────────── */}
        <div className={`flex items-center justify-between px-5 py-3 bg-black border rounded-2xl transition-all duration-200 ${
          open ? "border-[#FFC400]/40 shadow-[0_0_30px_rgba(255,196,0,0.08)]" : "border-[#2a2a2a] hover:border-[#3a3a3a]"
        }`}>

          {/* Logo + tagline */}
          <Link href="/" onClick={() => setOpen(false)} className="flex items-center gap-2.5 group min-w-0">
            <div className="size-7 shrink-0 rounded-lg bg-[#FFC400] flex items-center justify-center shadow-[0_0_12px_rgba(255,196,0,0.25)] group-hover:shadow-[0_0_20px_rgba(255,196,0,0.4)] transition-shadow">
              <span className="text-black text-[13px] font-black font-display leading-none">鎧</span>
            </div>
            <span className="text-[14px] font-black tracking-[0.16em] font-display text-white whitespace-nowrap truncate">
              YOROI <span className="text-[#444] font-normal tracking-normal mx-1.5">|</span> <span className="text-[#666] font-sans text-[12px] font-medium tracking-wide normal-case">AI Agent Security Firewall</span>
            </span>
          </Link>

          {/* Right side */}
          <div className="flex items-center gap-3">
            {/* Try Demo — visible when menu closed */}
            <Link
              href="/dashboard"
              onClick={() => setOpen(false)}
              className={`hidden sm:flex items-center gap-1.5 bg-[#FFC400] text-black text-[11px] font-black uppercase tracking-[0.12em] px-4 py-1.5 rounded-lg hover:bg-[#e6b000] transition-all font-display ${open ? "opacity-0 pointer-events-none" : "opacity-100"}`}
            >
              試 TRY DEMO
            </Link>

            {/* Hamburger */}
            <button
              onClick={() => setOpen((v) => !v)}
              aria-label="Toggle menu"
              className={`size-9 flex items-center justify-center rounded-xl border transition-all ${
                open
                  ? "border-[#FFC400]/40 bg-[#FFC400]/10 text-[#FFC400]"
                  : "border-[#2a2a2a] text-[#666] hover:text-white hover:border-[#444]"
              }`}
            >
              {open ? (
                /* X close */
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M2 2l10 10M12 2L2 12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
                </svg>
              ) : (
                /* Hamburger ≡ */
                <svg width="16" height="12" viewBox="0 0 16 12" fill="none">
                  <path d="M1 1h14M1 6h14M1 11h14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/>
                </svg>
              )}
            </button>
          </div>
        </div>

        {/* ── Dropdown ──────────────────────────────────────────────────────── */}
        <div className={`mt-2 overflow-hidden transition-all duration-200 ease-out ${
          open ? "opacity-100 translate-y-0" : "opacity-0 -translate-y-2 pointer-events-none"
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
                        <span className="text-lg font-black text-[#FFC400]/30 group-hover:text-[#FFC400]/60 font-display transition-colors leading-none w-6">{item.kanji}</span>
                        <div>
                          <p className="text-[13px] font-bold text-white tracking-wide">{item.label}</p>
                          <p className="text-[11px] text-[#444] font-mono mt-0.5 tracking-wider">↗ EXTERNAL</p>
                        </div>
                      </div>
                      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#333] group-hover:text-[#555] transition-colors">
                        <path d="M3 11L11 3M11 3H6M11 3v5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </a>
                  ) : (
                    <Link
                      href={item.href}
                      onClick={() => setOpen(false)}
                      className="group flex items-center justify-between px-4 py-3.5 rounded-xl hover:bg-[#0f0f0f] transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-lg font-black text-[#FFC400]/30 group-hover:text-[#FFC400]/60 font-display transition-colors leading-none w-6">{item.kanji}</span>
                        <div>
                          <p className="text-[13px] font-bold text-white tracking-wide">{item.label}</p>
                          <p className="text-[11px] text-[#444] font-mono mt-0.5 tracking-wider uppercase">{
                            item.href === "/docs" ? "Documentation & API" :
                            item.href === "/dashboard" ? "Security Console" : ""
                          }</p>
                        </div>
                      </div>
                      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#333] group-hover:text-[#555] transition-colors">
                        <path d="M3 7h8M8 4l3 3-3 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </Link>
                  )}
                </div>
              ))}
            </div>

            {/* CTA footer */}
            <div className="px-3 pb-3">
              <Link
                href="/dashboard"
                onClick={() => setOpen(false)}
                className="flex items-center justify-between w-full bg-[#FFC400] text-black px-5 py-3.5 rounded-xl hover:bg-[#e6b000] transition-all group"
              >
                <div>
                  <p className="text-[13px] font-black uppercase tracking-[0.12em] font-display">試 Launch Dashboard</p>
                  <p className="text-[10px] font-bold tracking-wider text-black/50 mt-0.5 font-mono">FREE · NO SIGNUP REQUIRED</p>
                </div>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="shrink-0 group-hover:translate-x-0.5 transition-transform">
                  <path d="M8 1L1.5 4v4.5c0 3.5 2.8 5.8 6.5 6.5 3.7-.7 6.5-3 6.5-6.5V4L8 1z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                  <path d="M5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </Link>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}
