import type { DecisionType } from "@/types";

interface DecisionBadgeProps {
  decision: DecisionType;
  size?: "sm" | "md";
}

const CONFIGS: Record<DecisionType, { label: string; color: string; bg: string; border: string; dot: string }> = {
  allow:                { label: "Allow",   color: "#22c55e", bg: "#22c55e18", border: "#22c55e40", dot: "#22c55e" },
  deny:                 { label: "Deny",    color: "#ef4444", bg: "#ef444418", border: "#ef444440", dot: "#ef4444" },
  require_confirmation: { label: "Confirm", color: "#FFC400", bg: "#FFC40018", border: "#FFC40040", dot: "#FFC400" },
  sandbox:              { label: "Sandbox", color: "#888888", bg: "#88888818", border: "#88888840", dot: "#888888" },
};

export function DecisionBadge({ decision, size = "md" }: DecisionBadgeProps) {
  const c = CONFIGS[decision];
  const textSize = size === "sm" ? "text-[10px]" : "text-xs";
  const px = size === "sm" ? "px-2 py-0.5" : "px-2.5 py-1";
  const dotSize = size === "sm" ? "size-1" : "size-1.5";

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-bold uppercase tracking-wider rounded-full border font-sans ${textSize} ${px}`}
      style={{ color: c.color, background: c.bg, borderColor: c.border }}
    >
      <span className={`${dotSize} rounded-full shrink-0`} style={{ background: c.dot }} />
      {c.label}
    </span>
  );
}
