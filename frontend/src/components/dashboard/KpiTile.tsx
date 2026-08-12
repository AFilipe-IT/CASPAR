import type { ReactNode } from "react";
import { ArrowUp, ArrowDown } from "lucide-react";
import styles from "./KpiTile.module.css";

/** Cor do quadrado do ícone. Identidade do indicador, não severidade — ver a
 *  nota nos tokens sobre porque são paletas separadas. */
export type KpiTone = "blue" | "teal" | "orange" | "purple" | "red" | "amber";

interface KpiTileProps {
  label: string;
  value: ReactNode;
  icon: ReactNode;
  delta?: number;
  deltaLabel?: string;
  tone?: KpiTone;
}

export function KpiTile({ label, value, icon, delta, deltaLabel, tone = "blue" }: KpiTileProps) {
  return (
    <div className={styles.tile}>
      <div className={[styles.icon, styles[tone]].join(" ")}>{icon}</div>
      <div className={styles.body}>
        {/* Valor primeiro: o número é o que se procura, a etiqueta só o
            qualifica — trocados, lia-se a etiqueta antes do dado. */}
        <span className={styles.value}>{value}</span>
        <span className={styles.label}>{label}</span>
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
