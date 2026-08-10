import { ArrowRight } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { scoreToSeverity } from "@/lib/severity";
import type { AttackChain, Misconfiguration } from "@/api/types";
import styles from "./ChainDetail.module.css";

/**
 * O que uma cadeia de ataque é, para lá do número.
 *
 * A lista mostrava só a justificação e o score amplificado. Tudo o resto já
 * vinha na resposta da API — que directivas a compõem, quais a dispararam, o
 * factor de amplificação — e não havia forma de lá chegar.
 *
 * `findings` é o conjunto de achados do mesmo scan: serve para ligar cada
 * directiva da cadeia ao problema concreto encontrado, com o seu score. Uma
 * directiva pode aparecer sem achado correspondente (a regra existe mas não
 * disparou), e nesse caso é mostrada à mesma, sem score.
 */
export function ChainDetail({
  chain,
  findings = [],
}: {
  chain: AttackChain;
  findings?: Misconfiguration[];
}) {
  const sev = scoreToSeverity(chain.amplified_score);
  const triggered = new Set(chain.triggered_by);

  const links = chain.misconfig_directives.map((directive) => ({
    directive,
    fired: triggered.has(directive),
    finding: findings.find((f) => f.directive === directive),
  }));

  return (
    <div className={styles.wrap}>
      <header className={styles.header}>
        <div>
          <h3 className={styles.title}>{chain.chain_id}</h3>
          <p className={styles.target}>{chain.target_name}</p>
        </div>
        <Badge tone={severityTone(sev)}>{chain.amplified_score.toFixed(1)}</Badge>
      </header>

      <section className={styles.section}>
        <h4>Why these combine</h4>
        <p className={styles.body}>{chain.justification}</p>
      </section>

      <section className={styles.section}>
        <h4>The chain</h4>
        <ol className={styles.steps}>
          {links.map((link, i) => (
            <li key={link.directive} className={styles.step}>
              {i > 0 && <ArrowRight className={styles.arrow} size={14} aria-hidden />}
              <div className={styles.stepBody}>
                <code className={styles.directive}>{link.directive}</code>
                {link.finding ? (
                  <span className={styles.stepScore}>
                    {link.finding.temporal_score.toFixed(1)}
                    {link.finding.bad_value && (
                      <span className={styles.badValue}> — {link.finding.bad_value}</span>
                    )}
                  </span>
                ) : (
                  <span className={styles.muted}>no matching finding in this scan</span>
                )}
                {!link.fired && (
                  <span className={styles.muted}> · did not trigger the chain</span>
                )}
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className={styles.section}>
        <h4>Scoring</h4>
        <p className={styles.meta}>
          Amplification ×{chain.amplification.toFixed(2)} · amplified score{" "}
          {chain.amplified_score.toFixed(1)}
          {chain.cross_target && " · spans more than one service"}
        </p>
        {/* Esclarece uma dúvida recorrente: uma cadeia a 10.0 ao lado de um
            score global de 8.7 não é incoerência. */}
        <p className={styles.muted}>
          Chains are reported but do not raise the global score, which is the worst
          individual finding. Breaking a chain can remove more real risk than its
          components' scores suggest.
        </p>
      </section>
    </div>
  );
}
