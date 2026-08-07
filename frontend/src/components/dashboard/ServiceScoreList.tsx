import { scoreToHex } from "@/lib/severity";
import styles from "./ServiceScoreList.module.css";

export interface ServiceScore {
  name: string;
  score: number;
}

export function ServiceScoreList({ services, max = 10 }: { services: ServiceScore[]; max?: number }) {
  return (
    <div className={styles.list}>
      {services.map((svc) => {
        const color = scoreToHex(svc.score);
        const pct = Math.min(100, (svc.score / max) * 100);
        return (
          <div key={svc.name} className={styles.row}>
            <span className={styles.name}>{svc.name}</span>
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
