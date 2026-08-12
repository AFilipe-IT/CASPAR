import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { ReportList } from "@/components/reports/ReportList";
import { ReportPreviewModal } from "@/components/reports/ReportPreviewModal";
import { useDeleteScan, useScans } from "@/api/scans";
import { downloadBlob, useExportReport } from "@/api/reports";
import type { ScanListItem } from "@/api/types";

export function ReportsPage() {
  const { data: scans, isLoading } = useScans({ limit: 100 });
  const [previewing, setPreviewing] = useState<ScanListItem | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const exportReport = useExportReport();
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const deleteScan = useDeleteScan();

  async function handleDownload(scan: ScanListItem) {
    setDownloadingId(scan.id);
    try {
      const blob = await exportReport.mutateAsync({ scanId: scan.id, format: "html" });
      downloadBlob(blob, scan.id, "html");
    } finally {
      setDownloadingId(null);
    }
  }

  async function handleDelete(scan: ScanListItem) {
    setDeletingId(scan.id);
    setError(null);
    try {
      await deleteScan.mutateAsync(scan.id);
    } catch (e) {
      // Sem isto, uma falha ao apagar era silenciosa: a linha ficava lá e não
      // havia como distinguir "não deu" de "não carreguei bem no botão".
      setError(e instanceof Error ? e.message : "Could not delete the assessment.");
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Reports"
        description="Generate and export assessment reports on demand — HTML, SARIF, or JSON."
      />

      <Card
        title="Assessments"
        subtitle="Every persisted assessment can be exported as a report, or deleted from the database."
      >
        {error && (
          <p style={{ color: "var(--sev-critical)", fontSize: "var(--fs-sm)", marginBottom: "var(--sp-3)" }}>
            {error}
          </p>
        )}
        {isLoading ? <SkeletonBlock rows={6} /> : (
          <ReportList
            scans={scans ?? []}
            onPreview={setPreviewing}
            onDownload={handleDownload}
            onDelete={handleDelete}
            downloadingId={downloadingId}
            deletingId={deletingId}
          />
        )}
      </Card>

      {previewing && <ReportPreviewModal scan={previewing} onClose={() => setPreviewing(null)} />}
    </>
  );
}
