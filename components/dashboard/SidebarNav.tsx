"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  {
    group: "MONITOR",
    items: [
      {
        href: "/dashboard",
        label: "Overview",
        exact: true,
        icon: (
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <rect x="1" y="1" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.3"/>
            <rect x="8" y="1" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.3"/>
            <rect x="1" y="8" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.3"/>
            <rect x="8" y="8" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.3"/>
          </svg>
        ),
      },
      {
        href: "/dashboard/actions",
        label: "Action Logs",
        icon: (
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M1 3h12M1 7h8M1 11h10" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
          </svg>
        ),
      },
    ],
  },
  {
    group: "CONFIGURE",
    items: [
      {
        href: "/dashboard/policies",
        label: "Policies",
        icon: (
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M7 1L1.5 3.5v3.5c0 3 2.5 5 5.5 5.5 3-.5 5.5-2.5 5.5-5.5V3.5L7 1z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
            <path d="M4.5 7l1.5 1.5L9.5 5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        ),
      },
      {
        href: "/dashboard/tools",
        label: "Tool Registry",
        icon: (
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M8.5 2a2.5 2.5 0 00-3.54 3.54L1 9.5a1.2 1.2 0 001.7 1.7l3.96-3.96a2.5 2.5 0 003.54-3.54L8.5 5.4 7.1 4 9.5 1.6 8.5 2z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round"/>
          </svg>
        ),
      },
    ],
  },
];

export function SidebarNav() {
  const pathname = usePathname();

  function isActive(href: string, exact?: boolean) {
    if (exact) return pathname === href;
    return pathname === href || pathname.startsWith(href + "/");
  }

  return (
    <nav className="flex-1 py-4 overflow-y-auto">
      {NAV.map((section) => (
        <div key={section.group} className="mb-5">
          <p className="px-5 text-[10px] font-bold tracking-[0.15em] text-[#444] mb-1.5 font-display">
            {section.group}
          </p>
          <div className="space-y-0.5 px-2">
            {section.items.map((item) => {
              const active = isActive(item.href, item.exact);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    active
                      ? "bg-[#FFC400] text-black"
                      : "text-[#777] hover:text-white hover:bg-[#1a1a1a]"
                  }`}
                >
                  <span className={active ? "text-black" : "text-[#555]"}>{item.icon}</span>
                  {item.label}
                </Link>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}
