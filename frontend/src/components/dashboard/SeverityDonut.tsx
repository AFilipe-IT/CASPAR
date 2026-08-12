import { useMemo } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";
import { EmptyState } from "@/components/ui/EmptyState";
import { ShieldCheck } from "lucide-react";
import { scoreToSeverity, severityColorHex } from "@/lib/severity";
import type { Misconfiguration } from "@/api/types";
import styles from "./SeverityDonut.module.css";

/* Ordem fixa, do mais grave para o menos: a cor de cada fatia é a mesma da
   severidade em toda a consola, portanto a legenda tem de a seguir e não pode
   ser reordenada por contagem. */
const ORDER = ["Critical", "High", "Medium", "Low"] as const;

export function SeverityDonut({ issues }: { issues: Misconfiguration[] }) {
  const data = useMemo(() => {
    const counts = new Map<string, number>();
    for (const issue of issues) {
      const sev = scoreToSeverity(issue.temporal_score);
      counts.set(sev, (counts.get(sev) ?? 0) + 1);
    }
    return ORDER.map((sev) => ({
      name: sev,
      value: counts.get(sev) ?? 0,
      color: severityColorHex(sev),
    })).filter((d) => d.value > 0);
  }, [issues]);

  if (data.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck size={22} />}
        title="No open findings"
        description="Nothing to distribute — every assessed directive is compliant."
      />
    );
  }

  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className={styles.wrap}>
      <div className={styles.chart}>
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={58}
              outerRadius={84}
              paddingAngle={2}
              startAngle={90}
              endAngle={-270}
              stroke="var(--panel)"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        {/* O total ao centro: sem ele a rosca dá proporções e esconde a escala
            — 2 de 4 e 200 de 400 desenham-se exactamente igual. */}
        <div className={styles.center}>
          <span className={styles.total}>{total}</span>
          <span className={styles.totalLabel}>findings</span>
        </div>
      </div>

      {/* Legenda sempre presente: a identidade das fatias não pode depender só
          da cor. */}
      <ul className={styles.legend}>
        {data.map((d) => (
          <li key={d.name} className={styles.legendItem}>
            <span className={styles.swatch} style={{ background: d.color }} aria-hidden />
            <span className={styles.legendName}>{d.name}</span>
            <span className={styles.legendValue}>{d.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
