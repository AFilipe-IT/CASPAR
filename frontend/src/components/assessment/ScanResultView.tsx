import { CheckCircle2, XCircle } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge, severityTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ScoreGauge } from "@/components/dashboard/ScoreGauge";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { AttackChainsList } from "@/components/dashboard/AttackChainsList";
import { downloadBlob, useExportReport } from "@/api/reports";
import type { ScanResponse } from "@/api/types";
import styles from "@/pages/AssessmentPage.module.css";

export function ScanResultView({ result }: { result: ScanResponse }) {
  const exportReport = useExportReport();

  async function handleExport(format: "html" | "sarif" | "json") {
    const blob = await exportReport.mutateAsync({ scanId: result.scan_id, format });
    downloadBlob(blob, result.scan_id, format);
  }

  return (
    <Card
      title={result.target_name}
      subtitle={result.input_path}
      action={
        <div style={{ display: "flex", gap: "var(--sp-2)" }}>
          <Button onClick={() => handleExport("html")}>Export HTML</Button>
          <Button onClick={() => handleExport("json")}>Export JSON</Button>
          <Button onClick={() => handleExport("sarif")}>Export SARIF</Button>
        </div>
      }
    >
      <div className={styles.resultHeader}>
        <ScoreGauge score={result.global_temporal_score} />
        <div style={{ display: "flex", flexDirection: "column", gap: "var(--sp-2)", alignItems: "flex-end" }}>
          <Badge tone={severityTone(result.severity)}>{result.severity}</Badge>
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "var(--fs-sm)",
              color: result.passed_threshold ? "var(--ok)" : "var(--sev-critical)",
            }}
          >
            {result.passed_threshold ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
            {result.passed_threshold ? "Passed threshold" : "Failed threshold"}
          </span>
        </div>
      </div>

      <div className={styles.resultMeta}>
        <span>{result.total_directives_scanned} directives scanned</span>
        <span>{result.total_issues_found} issues found</span>
        <span>{result.total_chains_detected} attack chains</span>
        {result.suppressed_count > 0 && <span>{result.suppressed_count} suppressed</span>}
        {result.detected_version && <span>Version {result.detected_version}</span>}
      </div>

      <FindingsTable
        rows={result.issues.map((finding) => ({ finding, service: result.target_name }))}
      />

      {result.chains.length > 0 && (
        <div style={{ marginTop: "var(--sp-5)" }}>
          <AttackChainsList chains={result.chains} findings={result.issues} />
        </div>
      )}
    </Card>
  );
}
