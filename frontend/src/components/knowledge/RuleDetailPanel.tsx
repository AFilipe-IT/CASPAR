import { X } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { scoreToSeverity } from "@/lib/severity";
import type { Misconfiguration } from "@/api/types";
import { FindingDetail } from "./FindingDetail";
import styles from "./RuleDetailPanel.module.css";

export function RuleDetailPanel({ rule, onClose }: { rule: Misconfiguration; onClose: () => void }) {
  const sev = scoreToSeverity(rule.base_score);

  return (
    <div className={styles.panel}>
      <header className={styles.header}>
        <div>
          <span className={styles.eyebrow}>{rule.target_name}</span>
          <h3 className={styles.title}>{rule.directive}</h3>
        </div>
        <button className={styles.close} onClick={onClose} aria-label="Close">
          <X size={16} />
        </button>
      </header>

      <div className={styles.badges}>
        <Badge tone={severityTone(sev)}>{sev}</Badge>
        <Badge tone="accent">base {rule.base_score.toFixed(1)}</Badge>
        <Badge tone="neutral">temporal {rule.temporal_score.toFixed(1)}</Badge>
      </div>

      <dl className={styles.grid}>
        <dt>Insecure value</dt>
        <dd>{rule.bad_value || "—"}</dd>
        <dt>Recommended value</dt>
        <dd>{rule.good_value || "—"}</dd>
        <dt>CIS section</dt>
        <dd>{rule.cis_section || "—"}</dd>
        <dt>CCE ID</dt>
        <dd>{rule.cce_id || "—"}</dd>
        <dt>Rule type</dt>
        <dd>{rule.rule_type}</dd>
        <dt>CVEs</dt>
        <dd>{rule.cves.length > 0 ? rule.cves.join(", ") : "none"}</dd>
      </dl>

      <FindingDetail rule={rule} />
    </div>
  );
}
