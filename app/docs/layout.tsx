import Link from "next/link";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-black text-white min-h-screen font-sans">
      {/* Top nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-[#1a1a1a] bg-black/90 backdrop-blur-md h-12 flex items-center px-6">
        <div className="flex items-center gap-6 w-full max-w-7xl mx-auto">
          <Link href="/" className="flex items-center gap-2 shrink-0">
            <div className="size-6 rounded-md bg-[#FFC400] flex items-center justify-center">
              <span className="text-black text-[10px] font-black font-display">鎧</span>
            </div>
            <span className="text-[12px] font-black tracking-widest font-display text-white">YOROI</span>
          </Link>
          <span className="text-[#333]">/</span>
          <span className="text-[12px] font-bold text-[#FFC400] tracking-wider font-display uppercase">Docs</span>
          <div className="ml-auto flex items-center gap-5 text-[12px] text-[#555]">
            <Link href="/" className="hover:text-white transition-colors">Home</Link>
            <Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a>
          </div>
        </div>
      </nav>

      {children}
    </div>
  );
}
