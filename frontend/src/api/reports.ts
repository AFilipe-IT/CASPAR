import { useMutation } from "@tanstack/react-query";
import type { DiffResult } from "./types";

export type ReportFormat = "html" | "dashboard" | "sarif" | "json";

interface ExportReportParams {
  scanId: string;
  format: ReportFormat;
  online?: boolean;
}

async function exportReport({ scanId, format, online = false }: ExportReportParams): Promise<Blob> {
  const res = await fetch(`/api/v1/scans/${scanId}/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ format, online }),
  });
  if (!res.ok) throw new Error(`Report export failed: ${res.statusText}`);
  return res.blob();
}

export function useExportReport() {
  return useMutation({ mutationFn: exportReport });
}

const EXTENSIONS: Record<ReportFormat, string> = {
  html: "html",
  dashboard: "html",
  sarif: "sarif.json",
  json: "json",
};

export function downloadBlob(blob: Blob, scanId: string, format: ReportFormat) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cvm-report-${scanId.slice(0, 8)}.${EXTENSIONS[format]}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function diffScans(oldId: string, newId: string): Promise<DiffResult> {
  const res = await fetch(`/api/v1/scans/${oldId}/diff/${newId}`, { method: "POST" });
  if (!res.ok) throw new Error(`Diff failed: ${res.statusText}`);
  return res.json();
}

export function useDiffScans() {
  return useMutation({
    mutationFn: ({ oldId, newId }: { oldId: string; newId: string }) => diffScans(oldId, newId),
  });
}
