import { useEffect, useState } from "react";
import { X } from "lucide-react";
import type { ScanListItem } from "@/api/types";
import styles from "./ReportPreviewModal.module.css";

interface ReportPreviewModalProps {
  scan: ScanListItem;
  onClose: () => void;
}

export function ReportPreviewModal({ scan, onClose }: ReportPreviewModalProps) {
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/v1/scans/${scan.id}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: "html" }),
    })
      .then((res) => {
        if (!res.ok) throw new Error(res.statusText);
        return res.text();
      })
      .then((text) => {
        if (!cancelled) setHtml(text);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [scan.id]);

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <header className={styles.header}>
          <span>
            {scan.target_name} · {scan.input_path}
          </span>
          <button className={styles.close} onClick={onClose} aria-label="Close preview">
            <X size={16} />
          </button>
        </header>
        <div className={styles.body}>
          {error && <p className={styles.error}>Failed to load report: {error}</p>}
          {!error && !html && <p className={styles.loading}>Generating report…</p>}
          {html && <iframe title="Report preview" className={styles.frame} srcDoc={html} />}
        </div>
      </div>
    </div>
  );
}
