import type { Misconfiguration } from "@/api/types";
import { METRIC_LABELS, METRIC_ORDER, parseNarrative } from "@/lib/narrative";
import styles from "./FindingDetail.module.css";

/**
 * O corpo do detalhe de uma misconfiguration: o que é, que impacto tem, como
 * se explora, como se remedeia, e porque é que cada métrica CCSS tem o valor
 * que tem.
 *
 * Está separado do `RuleDetailPanel` (que lhe dá a moldura e o botão de
 * fechar) para poder ser usado tal e qual a partir dos resultados de um scan,
 * onde a mesma informação faz falta e não havia forma de lá chegar.
 */
export function FindingDetail({ rule }: { rule: Misconfiguration }) {
  const narrative = parseNarrative(rule.narrative);
  const metrics = narrative?.metric_justifications;
  // Os valores vivem na regra; as justificações, na narrativa. O vector
  // mostra-se sempre — é o que sustenta a pontuação — e cada linha ganha a
  // explicação quando existir.
  const vector: Record<string, string> = {
    av: rule.av,
    au: rule.au,
    ac: rule.ac,
    c: rule.c,
    i: rule.i,
    a: rule.a,
    gel: rule.gel,
    grl: rule.grl,
  };

  return (
    <>
      {narrative?.description && (
        <section className={styles.section}>
          <h4>What this is</h4>
          <p>{narrative.description}</p>
        </section>
      )}

      {rule.justification && (
        <section className={styles.section}>
          <h4>Why it matters</h4>
          <p>{rule.justification}</p>
        </section>
      )}

      {(narrative?.potential_impact?.length ?? 0) > 0 && (
        <section className={styles.section}>
          <h4>Potential impact</h4>
          <ul className={styles.list}>
            {narrative!.potential_impact!.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      )}

      {narrative?.exploitation_scenario && (
        <section className={styles.section}>
          <h4>How it gets exploited</h4>
          {(narrative.exploitation_scenario.prerequisites?.length ?? 0) > 0 && (
            <p className={styles.meta}>
              <strong>Prerequisites:</strong>{" "}
              {narrative.exploitation_scenario.prerequisites!.join("; ")}
            </p>
          )}
          {narrative.exploitation_scenario.example && (
            <p>{narrative.exploitation_scenario.example}</p>
          )}
          {narrative.exploitation_scenario.result && (
            <p className={styles.result}>
              <strong>Result:</strong> {narrative.exploitation_scenario.result}
            </p>
          )}
        </section>
      )}

      <section className={styles.section}>
        <h4>How to remediate</h4>
        {rule.recommendation ? (
          <p>{rule.recommendation}</p>
        ) : (
          <p className={styles.muted}>No remediation text recorded for this rule.</p>
        )}
        {rule.good_value && (
          <p className={styles.fix}>
            Set <code>{rule.directive}</code> to <code>{rule.good_value}</code>
            {rule.bad_value && (
              <>
                {" "}
                (currently <code>{rule.bad_value}</code>)
              </>
            )}
          </p>
        )}
      </section>

      <section className={styles.section}>
        <h4>Score breakdown (CCSS)</h4>
        <p className={styles.meta}>
          Base {rule.base_score.toFixed(1)} · Temporal {rule.temporal_score.toFixed(1)}
          {rule.version_amplification !== 1 && (
            <> · version factor ×{rule.version_amplification.toFixed(2)}</>
          )}
        </p>
        {rule.version_risk_note && <p className={styles.meta}>{rule.version_risk_note}</p>}
        <dl className={styles.metrics}>
          {METRIC_ORDER.map((key) => (
            <div key={key} className={styles.metricRow}>
              <dt>
                <span className={styles.metricName}>{METRIC_LABELS[key]}</span>
                <code className={styles.metricValue}>{vector[key] || "—"}</code>
              </dt>
              <dd>
                {metrics?.[key] ?? (
                  <span className={styles.muted}>No recorded justification.</span>
                )}
              </dd>
            </div>
          ))}
        </dl>
        {!narrative && (
          // Distinguir "esta regra não tem narrativa" de "a consola perdeu-a"
          // evita exactamente a dúvida que motivou isto.
          <p className={styles.muted}>
            This rule has no LLM-generated narrative — it predates the pipeline or was
            curated by hand. The metric values above still drive its score.
          </p>
        )}
      </section>
    </>
  );
}
