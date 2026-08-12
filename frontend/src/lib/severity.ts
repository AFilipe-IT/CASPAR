import type { Severity } from "@/api/types";

const COLORS: Record<Severity, string> = {
  Critical: "var(--sev-critical)",
  High: "var(--sev-high)",
  Medium: "var(--sev-medium)",
  Low: "var(--sev-low)",
  None: "var(--sev-none)",
};

// Os mesmos valores dos tokens, em literal: SVG e Recharts não resolvem
// `var(--...)` em todos os atributos. Têm de acompanhar tokens.css à mão —
// `#F59E08` e `#10B981` tinham ficado para trás de uma passagem anterior e
// pintavam o gauge com um laranja e um verde que não existiam em mais lado
// nenhum da consola.
const RESOLVED_COLORS: Record<Severity, string> = {
  Critical: "#EF4444",
  High: "#F59E0B",
  Medium: "#EAB308",
  Low: "#22C55E",
  None: "#9CA3AF",
};

export function severityColor(sev: string): string {
  return COLORS[sev as Severity] ?? COLORS.None;
}

// Resolved (non-var) hex for contexts like SVG/Recharts that need a literal.
export function severityColorHex(sev: string): string {
  return RESOLVED_COLORS[sev as Severity] ?? RESOLVED_COLORS.None;
}

export function scoreToSeverity(score: number): Severity {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "None";
}

export function scoreToRiskLabel(score: number): string {
  const sev = scoreToSeverity(score);
  if (sev === "Critical") return "CRITICAL RISK";
  if (sev === "High") return "HIGH RISK";
  if (sev === "Medium") return "MEDIUM RISK";
  if (sev === "Low") return "LOW RISK";
  return "SECURE";
}

export function scoreToHex(score: number): string {
  return severityColorHex(scoreToSeverity(score));
}
