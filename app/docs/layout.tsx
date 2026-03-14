import Link from "next/link";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-black text-white min-h-screen font-sans">
      {/* Top nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-[#111] bg-black/95 backdrop-blur-xl h-12 flex items-center px-6">
        <div className="flex items-center gap-4 w-full max-w-7xl mx-auto">
          <Link href="/" className="flex items-center gap-2.5 shrink-0 group">
            <div className="size-6 rounded-md bg-[#FFC400] flex items-center justify-center shadow-[0_0_10px_rgba(255,196,0,0.2)]">
              <span className="text-black text-[11px] font-black font-display">鎧</span>
            </div>
            <span className="text-[12px] font-black tracking-[0.18em] font-display text-white">YOROI</span>
          </Link>
          <span className="text-[#222] font-mono">/</span>
          <span className="text-[11px] font-black text-[#FFC400] tracking-[0.15em] font-display uppercase">Docs</span>
          <div className="ml-auto flex items-center gap-1">
            <Link href="/" className="px-3 py-1 text-[12px] text-[#444] hover:text-white transition-colors font-sans">Home</Link>
            <Link href="/dashboard" className="px-3 py-1 text-[12px] text-[#444] hover:text-white transition-colors font-sans">Dashboard</Link>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="px-3 py-1 text-[12px] text-[#444] hover:text-white transition-colors font-sans">GitHub ↗</a>
          </div>
        </div>
      </nav>

      <div className="h-12" />
      {children}
    </div>
  );
}
