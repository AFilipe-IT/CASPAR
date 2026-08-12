import { scoreToHex, scoreToRiskLabel } from "@/lib/severity";
import styles from "./ScoreGauge.module.css";

interface ScoreGaugeProps {
  score: number;
  max?: number;
}

/* Geometria do arco. Semicírculo de 180° a 0°, desenhado em SVG à mão em vez
   de com o RadialBarChart: o gauge precisa de bandas de risco e de marcas nos
   limiares (0/4/7/10), e nenhum dos dois sai de uma <RadialBar>. */
const W = 280;
const H = 162;
const CX = W / 2;
const CY = 140;
const R = 100;
const TRACK = 16;

function polar(angleDeg: number, radius: number) {
  const rad = (Math.PI * angleDeg) / 180;
  return { x: CX + radius * Math.cos(rad), y: CY - radius * Math.sin(rad) };
}

/** Um arco entre dois valores da escala, como caminho traçável. */
function arcPath(from: number, to: number, max: number, radius: number) {
  const a0 = 180 - (from / max) * 180;
  const a1 = 180 - (to / max) * 180;
  const p0 = polar(a0, radius);
  const p1 = polar(a1, radius);
  const large = Math.abs(a1 - a0) > 180 ? 1 : 0;
  return `M ${p0.x} ${p0.y} A ${radius} ${radius} 0 ${large} 1 ${p1.x} ${p1.y}`;
}

/* As bandas são os mesmos limiares de `scoreToSeverity` — o arco tem de contar
   a mesma história que a etiqueta por baixo dele. */
const BANDS = [
  { from: 0, to: 4, color: "var(--sev-low)" },
  { from: 4, to: 7, color: "var(--sev-medium)" },
  { from: 7, to: 9, color: "var(--sev-high)" },
  { from: 9, to: 10, color: "var(--sev-critical)" },
];

const TICKS = [0, 4, 7, 10];

export function ScoreGauge({ score, max = 10 }: ScoreGaugeProps) {
  const color = scoreToHex(score);
  const clamped = Math.max(0, Math.min(score, max));

  return (
    <div className={styles.wrap}>
      <div className={styles.chart}>
        <svg
          width={W}
          height={H}
          viewBox={`0 0 ${W} ${H}`}
          className={styles.svg}
          role="img"
          aria-label={`Score ${score.toFixed(1)} of ${max} — ${scoreToRiskLabel(score)}`}
        >
          {/* Calha neutra: mostra a escala inteira mesmo com score baixo. */}
          <path
            d={arcPath(0, max, max, R)}
            fill="none"
            stroke="var(--panel-alt)"
            strokeWidth={TRACK}
            strokeLinecap="round"
          />

          {/* Bandas de risco num anel fino POR FORA da calha, não por baixo do
              arco do valor: desenhadas por baixo, um score de 10 tapava-as
              todas e a escala desaparecia exactamente no caso em que mais
              interessa perceber onde é que 10 cai. */}
          {BANDS.map((b) => (
            <path
              key={b.from}
              d={arcPath(b.from, b.to, max, R + TRACK / 2 + 5)}
              fill="none"
              stroke={b.color}
              strokeWidth={3}
              opacity={0.55}
            />
          ))}

          {/* O valor, a cheio, por cima das bandas. */}
          {clamped > 0 && (
            <path
              d={arcPath(0, clamped, max, R)}
              fill="none"
              stroke={color}
              strokeWidth={TRACK}
              strokeLinecap="round"
              className={styles.valueArc}
            />
          )}

          {/* Marcas nos limiares, para a escala se ler sem legenda. */}
          {TICKS.map((t) => {
            const a = 180 - (t / max) * 180;
            // Por fora do anel de bandas, senão a marca cruzava-o.
            const inner = polar(a, R + TRACK / 2 + 8);
            const outer = polar(a, R + TRACK / 2 + 12);
            const label = polar(a, R + TRACK / 2 + 21);
            return (
              <g key={t}>
                <line
                  x1={inner.x}
                  y1={inner.y}
                  x2={outer.x}
                  y2={outer.y}
                  stroke="var(--border-strong)"
                  strokeWidth={1}
                />
                <text
                  x={label.x}
                  y={label.y}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  className={styles.tick}
                >
                  {t}
                </text>
              </g>
            );
          })}
        </svg>

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
