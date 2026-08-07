import { useEffect, useRef } from "react";
import { CheckCircle2, Info, Loader2, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { useJob, useJobLogs } from "@/api/jobs";
import type { Job } from "@/api/types";
import styles from "./JobConsole.module.css";

const STATUS_TONE: Record<Job["status"], "accent" | "ok" | "Critical" | "neutral"> = {
  queued: "neutral",
  running: "accent",
  succeeded: "ok",
  failed: "Critical",
  cancelled: "neutral",
};

interface JobConsoleProps {
  jobId: string | undefined;
  /** Fired once when the job reaches a terminal state (to refresh other views). */
  onFinished?: (job: Job) => void;
  placeholder?: string;
}

export function JobConsole({ jobId, onFinished, placeholder }: JobConsoleProps) {
  const { data: job } = useJob(jobId);
  const { lines } = useJobLogs(jobId, job?.status);
  const consoleRef = useRef<HTMLDivElement>(null);
  const notifiedRef = useRef<string | null>(null);

  // Keep the newest line in view as the job streams.
  useEffect(() => {
    const el = consoleRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines.length]);

  // Fire onFinished exactly once per job, not on every poll after it ends.
  useEffect(() => {
    if (!job || notifiedRef.current === job.id) return;
    if (job.status === "succeeded" || job.status === "failed") {
      notifiedRef.current = job.id;
      onFinished?.(job);
    }
  }, [job, onFinished]);

  if (!jobId) {
    return (
      <div className={styles.console}>
        <span className={styles.placeholder}>
          {placeholder ?? "No job running. Output will stream here."}
        </span>
      </div>
    );
  }

  const running = job?.status === "queued" || job?.status === "running";

  return (
    <div className={styles.wrap}>
      <div className={styles.statusRow}>
        <span className={styles.statusLeft}>
          {running && <Loader2 size={15} className={styles.spin} />}
          {job?.status === "succeeded" && <CheckCircle2 size={15} color="var(--ok)" />}
          {job?.status === "failed" && <XCircle size={15} color="var(--sev-critical)" />}
          <code>{jobId.slice(0, 8)}</code>
          {lines.length > 0 && <>· {lines.length} lines</>}
        </span>
        {job && <Badge tone={STATUS_TONE[job.status]}>{job.status}</Badge>}
      </div>

      {running && <div className={styles.bar} aria-label="Job in progress" />}

      <div className={styles.console} ref={consoleRef} role="log" aria-live="polite">
        {lines.length === 0 ? (
          <span className={styles.placeholder}>Waiting for output…</span>
        ) : (
          lines.map((l) => (
            <span
              key={l.seq}
              className={l.line.startsWith("ERROR:") ? styles.lineError : styles.line}
            >
              {l.line || " "}
            </span>
          ))
        )}
      </div>

      {job?.error && <div className={styles.errorBox}>{job.error}</div>}

      <p className={styles.notice}>
        <Info size={13} style={{ flexShrink: 0, marginTop: 2 }} />
        <span>
          Jobs run in the server process. They survive a browser refresh, but not a
          server restart — <code>caspar serve --reload</code> kills running jobs, so
          avoid <code>--reload</code> while a build is in flight.
        </span>
      </p>
    </div>
  );
}
