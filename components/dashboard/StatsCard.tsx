interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: "up" | "down" | "neutral";
  trendValue?: string;
  accent?: "yellow" | "green" | "red" | "gray";
}

const ACCENT_STYLES = {
  yellow: "text-[#FFC400]",
  green: "text-[#22c55e]",
  red: "text-[#ef4444]",
  gray: "text-[#888]",
};

export function StatsCard({
  title,
  value,
  subtitle,
  trend,
  trendValue,
  accent = "yellow",
}: StatsCardProps) {
  return (
    <div className="rounded-xl border border-[#2a2a2a] bg-[#1a1a1a] p-5">
      <p className="text-xs font-medium text-[#888] uppercase tracking-wider">{title}</p>
      <p className={`mt-2 text-2xl font-bold ${ACCENT_STYLES[accent]}`}>
        {value}
      </p>
      {(subtitle || trendValue) && (
        <div className="mt-1.5 flex items-center gap-2">
          {subtitle && <p className="text-xs text-[#666]">{subtitle}</p>}
          {trendValue && (
            <span
              className={`text-xs font-medium ${
                trend === "up"
                  ? "text-[#22c55e]"
                  : trend === "down"
                  ? "text-[#ef4444]"
                  : "text-[#888]"
              }`}
            >
              {trendValue}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
