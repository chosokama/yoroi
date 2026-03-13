interface RiskBarProps {
  score: number;
  showLabel?: boolean;
}

export function RiskBar({ score, showLabel = true }: RiskBarProps) {
  const pct = Math.round(Math.min(1, Math.max(0, score)) * 100);
  const color = score >= 0.8 ? "#ef4444" : score >= 0.6 ? "#f97316" : score >= 0.3 ? "#FFC400" : "#22c55e";
  const label = score >= 0.8 ? "Critical" : score >= 0.6 ? "High" : score >= 0.3 ? "Medium" : "Low";

  return (
    <div className="flex items-center gap-2 min-w-0">
      <div className="flex-1 h-1 bg-[#1a1a1a] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all duration-300" style={{ width: `${pct}%`, background: color }} />
      </div>
      {showLabel && (
        <span className="text-[11px] font-bold shrink-0 font-sans" style={{ color }}>
          {label}
        </span>
      )}
    </div>
  );
}
