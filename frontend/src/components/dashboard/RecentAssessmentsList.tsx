import { Link } from "react-router-dom";
import { History } from "lucide-react";
import { Badge, severityTone } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import type { ScanListItem } from "@/api/types";
import styles from "./RecentAssessmentsList.module.css";

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function RecentAssessmentsList({ scans }: { scans: ScanListItem[] }) {
  if (scans.length === 0) {
    return <EmptyState icon={<History size={22} />} title="No assessments recorded yet" />;
  }

  return (
    <ul className={styles.list}>
      {scans.map((scan) => (
        <li key={scan.id} className={styles.item}>
          <div className={styles.meta}>
            <span className={styles.time}>{formatTimestamp(scan.timestamp)}</span>
          </div>
          <span className={styles.target}>{scan.target_name}</span>
          <Badge tone={severityTone(scan.severity)}>{scan.global_temporal_score.toFixed(1)}</Badge>
        </li>
      ))}
      <li className={styles.viewAll}>
        <Link to="/assessment">View full history →</Link>
      </li>
    </ul>
  );
}
