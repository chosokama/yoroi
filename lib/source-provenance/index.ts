import type { SourceType } from "@/types";

/**
 * Trust-risk delta per source origin.
 * Higher value = more risk added to the total score.
 * System/developer sources are fully trusted; external is maximally risky.
 */
const SOURCE_RISK_DELTAS: Record<SourceType, number> = {
  system: 0.0,
  developer: 0.05,
  user: 0.1,
  memory: 0.15,
  tool: 0.2,
  web: 0.3,
  external: 0.4,
};

/**
 * Returns the risk delta contributed by the request source.
 */
export function getSourceRiskDelta(source: SourceType): number {
  return SOURCE_RISK_DELTAS[source] ?? SOURCE_RISK_DELTAS.external;
}

/**
 * Returns a human-readable trust label for a source.
 */
export function getSourceTrustLabel(source: SourceType): string {
  const labels: Record<SourceType, string> = {
    system: "Fully trusted (system)",
    developer: "Highly trusted (developer)",
    user: "Trusted (authenticated user)",
    memory: "Moderate trust (agent memory)",
    tool: "Moderate trust (tool output)",
    web: "Low trust (web content)",
    external: "Untrusted (external source)",
  };
  return labels[source] ?? "Unknown source";
}

/**
 * Determines if a source is considered high risk for indirect prompt attacks.
 * Tool outputs and web content can contain injected instructions.
 */
export function isHighRiskSource(source: SourceType): boolean {
  return source === "tool" || source === "web" || source === "external";
}
