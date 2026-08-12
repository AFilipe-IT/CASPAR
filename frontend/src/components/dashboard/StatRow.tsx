import type { ReactNode } from "react";
import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import styles from "./StatRow.module.css";

interface StatRowProps {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: ReactNode;
  /** Variação do score. Positivo = piorou, e é por isso que sobe a vermelho. */
  delta?: number;
}

export function StatRow({ label, value, hint, icon, delta }: StatRowProps) {
  return (
    <div className={styles.row}>
      {icon && <span className={styles.icon}>{icon}</span>}
      <div className={styles.body}>
        <span className={styles.label}>{label}</span>
        {hint && <span className={styles.hint}>{hint}</span>}
      </div>
      <div className={styles.valueGroup}>
        <span className={styles.value}>{value}</span>
        {delta !== undefined && <DeltaPill delta={delta} />}
      </div>
    </div>
  );
}

/**
 * A variação do score, com o sinal explícito.
 *
 * Num medidor de vulnerabilidade "para cima" é a má notícia, ao contrário do
 * que um painel de negócio sugere. A seta e a cor dizem o mesmo — a cor não é
 * o único portador do significado.
 */
function DeltaPill({ delta }: { delta: number }) {
  // Abaixo de um décimo é ruído de arredondamento do próprio score, não
  // movimento: "+0.0" a vermelho leria-se como uma regressão que não houve.
  if (Math.abs(delta) < 0.05) {
    return (
      <span className={[styles.delta, styles.flat].join(" ")}>
        <Minus size={12} aria-hidden /> no change
      </span>
    );
  }
  const worse = delta > 0;
  return (
    <span className={[styles.delta, worse ? styles.worse : styles.better].join(" ")}>
      {worse ? <ArrowUpRight size={12} aria-hidden /> : <ArrowDownRight size={12} aria-hidden />}
      {worse ? "+" : "−"}
      {Math.abs(delta).toFixed(1)}
    </span>
  );
}
