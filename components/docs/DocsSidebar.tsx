"use client";

import { useEffect, useState } from "react";

const NAV = [
  {
    group: "OVERVIEW",
    items: [
      { id: "introduction", label: "Introduction" },
      { id: "architecture", label: "Architecture" },
      { id: "quickstart", label: "Quick Start" },
    ],
  },
  {
    group: "API REFERENCE",
    items: [
      { id: "check-api", label: "POST /check" },
      { id: "scan-api", label: "POST /scan" },
      { id: "policy-api", label: "GET|POST /policy" },
      { id: "tools-api", label: "GET /tools" },
      { id: "logs-api", label: "GET /logs" },
    ],
  },
  {
    group: "ENGINES",
    items: [
      { id: "policy-engine", label: "Policy Engine" },
      { id: "risk-engine", label: "Risk Engine" },
      { id: "guardrail-engine", label: "Guardrail Engine" },
    ],
  },
  {
    group: "SDK",
    items: [
      { id: "sdk-install", label: "Installation" },
      { id: "sdk-check", label: "check()" },
      { id: "sdk-policy", label: "setPolicy()" },
      { id: "sdk-tools", label: "registerTool()" },
    ],
  },
  {
    group: "SECURITY",
    items: [
      { id: "auth", label: "Authentication" },
      { id: "rate-limiting", label: "Rate Limiting" },
      { id: "input-hardening", label: "Input Hardening" },
      { id: "threat-model", label: "Threat Model" },
    ],
  },
  {
    group: "DEPLOYMENT",
    items: [
      { id: "env-vars", label: "Environment Variables" },
      { id: "vercel", label: "Deploy to Vercel" },
      { id: "supabase", label: "Supabase Setup" },
      { id: "redis", label: "Upstash Redis" },
    ],
  },
];

export function DocsSidebar() {
  const [active, setActive] = useState("introduction");

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) setActive(e.target.id);
        }
      },
      { rootMargin: "-20% 0% -70% 0%", threshold: 0 }
    );
    document.querySelectorAll("[data-section]").forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  return (
    <aside className="w-52 shrink-0 sticky top-12 h-[calc(100vh-3rem)] overflow-y-auto border-r border-[#1a1a1a] py-6">
      {NAV.map((section) => (
        <div key={section.group} className="mb-5">
          <p className="px-5 text-[10px] font-black tracking-[0.2em] text-[#333] mb-1.5 font-display">
            {section.group}
          </p>
          <div className="space-y-px px-2">
            {section.items.map((item) => (
              <a
                key={item.id}
                href={`#${item.id}`}
                onClick={() => setActive(item.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[13px] transition-all ${
                  active === item.id
                    ? "text-[#FFC400] bg-[#FFC400]/10"
                    : "text-[#555] hover:text-[#aaa] hover:bg-[#0f0f0f]"
                }`}
              >
                {active === item.id && <span className="size-1 rounded-full bg-[#FFC400] shrink-0" />}
                {item.label}
              </a>
            ))}
          </div>
        </div>
      ))}
    </aside>
  );
}
