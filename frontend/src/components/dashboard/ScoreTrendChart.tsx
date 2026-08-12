import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { EmptyState } from "@/components/ui/EmptyState";
import { LineChart as LineChartIcon } from "lucide-react";
import type { TrendSeries } from "@/api/types";
import styles from "./ScoreTrendChart.module.css";

/**
 * A evolução do pior score ao longo do tempo.
 *
 * Um eixo só, e é sempre o mesmo 0–10 do gauge: a pergunta é "estamos melhor
 * ou pior do que na semana passada?", e uma escala que se ajustasse aos dados
 * faria uma descida de 0.2 parecer uma queda a pique.
 */

interface Point {
  t: number;
  label: string;
  score: number;
}

function buildSeries(trends: TrendSeries[]): Point[] {
  // As séries vêm por `input_path`, e a curva segue UMA — a do alvo que fixa o
  // score actual, o mesmo que o gauge mostra.
  //
  // Sobrepor todos os alvos numa linha só, tomando o máximo instante a
  // instante, parecia a leitura "global" certa e não era: cada alvo é avaliado
  // em alturas diferentes, portanto em cada instante só um tem leitura nova e
  // a linha saltava entre o pior e o melhor alvo a cada ponto. Desenhava um
  // dente-de-serra entre 2 e 10 que não descrevia movimento nenhum — só a
  // ordem por que os scans foram corridos.
  const worst = [...trends].sort((a, b) => b.last - a.last)[0];
  if (!worst) return [];

  const points = worst.timestamps
    .map((ts, i) => ({ t: new Date(ts).getTime(), score: worst.scores[i] }))
    .filter((p) => Number.isFinite(p.t) && p.score !== undefined)
    .sort((a, b) => a.t - b.t);

  // Com tudo avaliado no mesmo dia — o caso normal em desenvolvimento — o eixo
  // repetia a mesma data em todas as marcas e não dizia nada. Aí a hora é que
  // separa as leituras.
  const sameDay =
    points.length > 0 &&
    new Date(points[0].t).toDateString() ===
      new Date(points[points.length - 1].t).toDateString();

  return points.map(({ t, score }) => ({
    t,
    score,
    label: sameDay
      ? new Date(t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
      : new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
  }));
}

function TrendTooltip({ active, payload }: {
  active?: boolean;
  payload?: { payload: Point }[];
}) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;
  return (
    <div className={styles.tooltip}>
      <div className={styles.tooltipDate}>{new Date(point.t).toLocaleString()}</div>
      <div className={styles.tooltipValue}>{point.score.toFixed(1)} / 10</div>
    </div>
  );
}

export function ScoreTrendChart({ trends }: { trends: TrendSeries[] }) {
  const data = useMemo(() => buildSeries(trends), [trends]);

  // Uma leitura só não é uma tendência — desenhar uma linha de um ponto
  // sugeria uma estabilidade que ainda não foi medida.
  if (data.length < 2) {
    return (
      <EmptyState
        icon={<LineChartIcon size={22} />}
        title="Not enough history yet"
        description="Run at least two assessments of the same target to see how the score moves."
      />
    );
  }

  return (
    <div className={styles.wrap}>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
          <defs>
            <linearGradient id="scoreTrendFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.24} />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: "var(--text-faint)", fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: "var(--border)" }}
            minTickGap={24}
          />
          <YAxis
            domain={[0, 10]}
            ticks={[0, 2, 4, 6, 8, 10]}
            tick={{ fill: "var(--text-faint)", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={44}
          />
          <Tooltip content={<TrendTooltip />} cursor={{ stroke: "var(--border-strong)" }} />
          <Area
            type="monotone"
            dataKey="score"
            stroke="var(--accent)"
            strokeWidth={2}
            fill="url(#scoreTrendFill)"
            dot={false}
            activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--panel)" }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
