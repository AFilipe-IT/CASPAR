import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { ReportList } from "@/components/reports/ReportList";
import { ReportPreviewModal } from "@/components/reports/ReportPreviewModal";
import { useScans } from "@/api/scans";
import { downloadBlob, useExportReport } from "@/api/reports";
import type { ScanListItem } from "@/api/types";

export function ReportsPage() {
  const { data: scans, isLoading } = useScans({ limit: 100 });
  const [previewing, setPreviewing] = useState<ScanListItem | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const exportReport = useExportReport();

  async function handleDownload(scan: ScanListItem) {
    setDownloadingId(scan.id);
    try {
      const blob = await exportReport.mutateAsync({ scanId: scan.id, format: "html" });
      downloadBlob(blob, scan.id, "html");
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Reports"
        description="Generate and export assessment reports on demand — HTML, SARIF, or JSON."
      />

      <Card title="Assessments" subtitle="Every persisted assessment can be exported as a report.">
        {isLoading ? <SkeletonBlock rows={6} /> : (
          <ReportList
            scans={scans ?? []}
            onPreview={setPreviewing}
            onDownload={handleDownload}
            downloadingId={downloadingId}
          />
        )}
      </Card>

      {previewing && <ReportPreviewModal scan={previewing} onClose={() => setPreviewing(null)} />}
    </>
  );
}
