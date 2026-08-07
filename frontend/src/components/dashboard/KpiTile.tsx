import type { ReactNode } from "react";
import { ArrowUp, ArrowDown } from "lucide-react";
import styles from "./KpiTile.module.css";

interface KpiTileProps {
  label: string;
  value: ReactNode;
  icon: ReactNode;
  delta?: number;
  deltaLabel?: string;
  tone?: "neutral" | "critical";
}

export function KpiTile({ label, value, icon, delta, deltaLabel, tone = "neutral" }: KpiTileProps) {
  return (
    <div className={styles.tile}>
      <div className={[styles.icon, tone === "critical" ? styles.critical : ""].join(" ")}>{icon}</div>
      <div className={styles.body}>
        <span className={styles.label}>{label}</span>
        <span className={styles.value}>{value}</span>
        {delta !== undefined && (
          <span className={[styles.delta, delta >= 0 ? styles.up : styles.down].join(" ")}>
            {delta >= 0 ? <ArrowUp size={12} /> : <ArrowDown size={12} />}
            {Math.abs(delta)} {deltaLabel}
          </span>
        )}
      </div>
    </div>
  );
}
