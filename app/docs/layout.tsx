import Link from "next/link";
import { BrandLogo } from "@/components/ui/BrandLogo";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-black text-white min-h-screen font-sans">
      {/* Top nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-[#111] bg-black/95 backdrop-blur-xl h-12 flex items-center px-6">
        <div className="flex items-center gap-4 w-full max-w-7xl mx-auto">
          <BrandLogo size="sm" />
          <span className="text-[#222] font-mono">/</span>
          <span className="text-[11px] font-black text-[#FFC400] tracking-[0.15em] font-display uppercase">Docs</span>
          <div className="ml-auto flex items-center gap-1">
            <Link href="/" className="px-3 py-1 text-[12px] text-[#444] hover:text-white transition-colors font-sans">Home</Link>
            <Link href="/dashboard" className="px-3 py-1 text-[12px] text-[#444] hover:text-white transition-colors font-sans">Dashboard</Link>
            <a href="https://github.com/moltwall" target="_blank" rel="noreferrer" className="px-3 py-1 text-[12px] text-[#444] hover:text-white transition-colors font-sans">X ↗</a>
          </div>
        </div>
      </nav>

      <div className="h-12" />
      {children}
    </div>
  );
}
