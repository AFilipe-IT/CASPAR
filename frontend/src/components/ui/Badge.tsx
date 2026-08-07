import type { ReactNode } from "react";
import styles from "./Badge.module.css";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "None";

interface BadgeProps {
  children: ReactNode;
  tone?: Severity | "accent" | "neutral" | "ok";
}

const SEVERITY_TONES: Record<string, string> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  None: "neutral",
};

export function severityTone(severity: string): BadgeProps["tone"] {
  return (SEVERITY_TONES[severity] as BadgeProps["tone"]) ?? "neutral";
}

export function Badge({ children, tone = "neutral" }: BadgeProps) {
  const key = SEVERITY_TONES[tone] ?? tone;
  return <span className={[styles.badge, styles[key]].filter(Boolean).join(" ")}>{children}</span>;
}
