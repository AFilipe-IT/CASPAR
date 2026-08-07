import { useRef, useState } from "react";
import { UploadCloud, FileText, Radio } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useTargets } from "@/api/targets";
import { useRunScan, useUploadScan } from "@/api/scans";
import type { ScanResponse } from "@/api/types";
import { usePreferences } from "@/context/PreferencesContext";
import styles from "@/pages/AssessmentPage.module.css";

type Mode = "upload" | "path" | "live";

interface RunAssessmentFormProps {
  onResult: (result: ScanResponse) => void;
}

export function RunAssessmentForm({ onResult }: RunAssessmentFormProps) {
  const [mode, setMode] = useState<Mode>("upload");
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [inputPath, setInputPath] = useState("");
  const [liveService, setLiveService] = useState("");
  // Seeded from Settings, then freely overridden for this run — a default,
  // not a lock.
  const { preferences } = usePreferences();
  const [profile, setProfile] = useState<"" | "production" | "internal" | "dev">(
    preferences.envProfile,
  );
  const [host, setHost] = useState("");
  const [threshold, setThreshold] = useState(preferences.threshold);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data: targets } = useTargets();
  const runScan = useRunScan();
  const uploadScan = useUploadScan();

  const busy = runScan.isPending || uploadScan.isPending;
  const error = runScan.error ?? uploadScan.error;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const thresholdNum = threshold ? Number(threshold) : undefined;

    if (mode === "upload") {
      if (!file) return;
      const result = await uploadScan.mutateAsync({
        file,
        env_profile: profile || undefined,
        host: host || undefined,
        threshold: thresholdNum,
      });
      onResult(result);
    } else if (mode === "path") {
      if (!inputPath) return;
      const result = await runScan.mutateAsync({
        input_path: inputPath,
        env_profile: profile || undefined,
        host: host || undefined,
        threshold: thresholdNum,
      });
      onResult(result);
    } else {
      if (!liveService) return;
      const result = await runScan.mutateAsync({
        input_path: liveService,
        live: true,
        env_profile: profile || undefined,
        host: host || undefined,
        threshold: thresholdNum,
      });
      onResult(result);
    }
  }

  const canSubmit =
    (mode === "upload" && !!file) ||
    (mode === "path" && inputPath.trim().length > 0) ||
    (mode === "live" && liveService.trim().length > 0);

  return (
    <form className={styles.form} onSubmit={handleSubmit}>
      <div className={styles.modeRow}>
        <button
          type="button"
          className={[styles.modeBtn, mode === "upload" ? styles.modeBtnActive : ""].join(" ")}
          onClick={() => setMode("upload")}
        >
          <UploadCloud size={15} /> Upload file
        </button>
        <button
          type="button"
          className={[styles.modeBtn, mode === "path" ? styles.modeBtnActive : ""].join(" ")}
          onClick={() => setMode("path")}
        >
          <FileText size={15} /> Server path
        </button>
        <button
          type="button"
          className={[styles.modeBtn, mode === "live" ? styles.modeBtnActive : ""].join(" ")}
          onClick={() => setMode("live")}
        >
          <Radio size={15} /> Live service
        </button>
      </div>

      {mode === "upload" && (
        <div className={styles.field}>
          <span className={styles.label}>Configuration file</span>
          <div
            className={[styles.dropzone, dragOver ? styles.dropzoneActive : ""].join(" ")}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const dropped = e.dataTransfer.files?.[0];
              if (dropped) setFile(dropped);
            }}
          >
            {file ? (
              <span className={styles.dropzoneFile}>
                <FileText size={16} /> {file.name}
              </span>
            ) : (
              <span>Drop a config file here, or click to browse</span>
            )}
            <input
              ref={fileInputRef}
              type="file"
              hidden
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
        </div>
      )}

      {mode === "path" && (
        <div className={styles.field}>
          <span className={styles.label}>Server-side path</span>
          <input
            className={styles.input}
            placeholder="/etc/nginx/nginx.conf or docker://httpd:2.4"
            value={inputPath}
            onChange={(e) => setInputPath(e.target.value)}
          />
        </div>
      )}

      {mode === "live" && (
        <div className={styles.field}>
          <span className={styles.label}>Installed service name</span>
          <input
            className={styles.input}
            placeholder="apache2"
            value={liveService}
            onChange={(e) => setLiveService(e.target.value)}
          />
        </div>
      )}

      <div className={styles.row2}>
        <div className={styles.field}>
          <span className={styles.label}>Environment profile</span>
          <select
            className={styles.select}
            value={profile}
            onChange={(e) => setProfile(e.target.value as typeof profile)}
          >
            <option value="">Default (production)</option>
            <option value="production">Production — Network exposure</option>
            <option value="internal">Internal — Adjacent exposure</option>
            <option value="dev">Dev — Local exposure</option>
          </select>
        </div>
        <div className={styles.field}>
          <span className={styles.label}>Host label (optional)</span>
          <input
            className={styles.input}
            placeholder="web01"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
      </div>

      <div className={styles.field}>
        <span className={styles.label}>CI threshold (optional)</span>
        <input
          className={styles.input}
          type="number"
          step="0.1"
          min="0"
          max="10"
          placeholder="e.g. 7.0 — flags pass/fail in the result"
          value={threshold}
          onChange={(e) => setThreshold(e.target.value)}
        />
      </div>

      {targets && targets.length === 0 && (
        <p className={styles.error}>
          No benchmarks installed yet — visit Knowledge Base or run `caspar build` first.
        </p>
      )}

      {error && <p className={styles.error}>{error.message}</p>}

      <Button type="submit" variant="primary" disabled={!canSubmit || busy}>
        {busy ? "Running assessment…" : "Run assessment"}
      </Button>
    </form>
  );
}
