import { scoreToHex } from "@/lib/severity";
import styles from "./ServiceScoreList.module.css";

export interface ServiceScore {
  name: string;
  score: number;
  /** Caminho avaliado. Vários alvos partilham o mesmo `name` — um host pode ter
   *  o apache do sistema, uma fixture e uma cópia de trabalho, todos
   *  "apache-httpd". Sem o caminho a lista mostra o mesmo nome repetido e não
   *  há como saber a que configuração pertence cada score. */
  input?: string;
}

/** O nome do ficheiro, que é o que distingue dois alvos com o mesmo serviço.
 *  O caminho completo não cabe na linha e a parte informativa é o fim. */
function shortPath(input: string): string {
  const parts = input.split("/").filter(Boolean);
  return parts.length <= 2 ? input : `…/${parts.slice(-2).join("/")}`;
}

export function ServiceScoreList({ services, max = 10 }: { services: ServiceScore[]; max?: number }) {
  return (
    <div className={styles.list}>
      {services.map((svc) => {
        const color = scoreToHex(svc.score);
        const pct = Math.min(100, (svc.score / max) * 100);
        return (
          // A chave inclui o caminho: com `name` sozinho, alvos homónimos
          // colidiam e o React reordenava linhas erradas entre actualizações.
          <div key={`${svc.name}:${svc.input ?? ""}`} className={styles.row}>
            <span className={styles.name}>
              {svc.name}
              {svc.input && (
                <span className={styles.path} title={svc.input}>
                  {shortPath(svc.input)}
                </span>
              )}
            </span>
            <div className={styles.track}>
              <div className={styles.fill} style={{ width: `${pct}%`, background: color }} />
            </div>
            <span className={styles.score} style={{ color }}>
              {svc.score.toFixed(1)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
