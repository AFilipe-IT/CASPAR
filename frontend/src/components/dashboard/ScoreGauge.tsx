import { RadialBarChart, RadialBar, PolarAngleAxis } from "recharts";
import { scoreToHex, scoreToRiskLabel } from "@/lib/severity";
import styles from "./ScoreGauge.module.css";

interface ScoreGaugeProps {
  score: number;
  max?: number;
}

export function ScoreGauge({ score, max = 10 }: ScoreGaugeProps) {
  const color = scoreToHex(score);
  const data = [{ value: score, fill: color }];

  return (
    <div className={styles.wrap}>
      <div className={styles.chart}>
        <RadialBarChart
          width={200}
          height={140}
          cx="50%"
          cy="100%"
          innerRadius={80}
          outerRadius={110}
          barSize={14}
          data={data}
          startAngle={180}
          endAngle={0}
        >
          <PolarAngleAxis type="number" domain={[0, max]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: "var(--panel-alt)" }} dataKey="value" cornerRadius={8} />
        </RadialBarChart>
        <div className={styles.value}>
          <span className={styles.number} style={{ color }}>
            {score.toFixed(1)}
          </span>
        </div>
      </div>
      <span className={styles.label} style={{ color }}>
        {scoreToRiskLabel(score)}
      </span>
      <span className={styles.scale}>Scale: 0 (Safe) – 10 (Critical)</span>
    </div>
  );
}
