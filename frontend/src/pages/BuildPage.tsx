import { useCallback, useState } from "react";
import { History, PlayCircle } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { JobConsole } from "@/components/jobs/JobConsole";
import { useInvalidateAfterJob, useJobs, useStartBuild } from "@/api/jobs";
import type { Job } from "@/api/types";
import styles from "./JobsShared.module.css";

const STATUS_TONE: Record<Job["status"], "accent" | "ok" | "Critical" | "neutral"> = {
  queued: "neutral",
  running: "accent",
  succeeded: "ok",
  failed: "Critical",
  cancelled: "neutral",
};

export function BuildPage() {
  const [benchmark, setBenchmark] = useState("");
  const [target, setTarget] = useState<"apache-httpd" | "nginx">("apache-httpd");
  const [model, setModel] = useState("qwen2.5:14b");
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [dryRun, setDryRun] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | undefined>();

  const startBuild = useStartBuild();
  const { data: jobs, isLoading, refetch } = useJobs("build");
  const invalidateAfterJob = useInvalidateAfterJob();

  const handleFinished = useCallback(() => {
    invalidateAfterJob();
    refetch();
  }, [invalidateAfterJob, refetch]);

  function handleStart() {
    startBuild.mutate(
      {
        benchmark,
        target,
        model,
        ollama_url: ollamaUrl,
        dry_run: dryRun,
      },
      { onSuccess: (res) => setActiveJobId(res.job_id) },
    );
  }

  return (
    <>
      <PageHeader
        title="Build"
        description="Populate the knowledge base from a benchmark using a local LLM — the same pipeline as `caspar build`."
      />

      <Card
        title="New build"
        subtitle="Runs server-side as a background job. Full LLM builds can take over an hour."
      >
        <div className={styles.form}>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="benchmark">
              Benchmark path
            </label>
            <input
              id="benchmark"
              className={styles.input}
              placeholder="plugins/apache_httpd/Benchmark.pdf"
              value={benchmark}
              onChange={(e) => setBenchmark(e.target.value)}
            />
            <span className={styles.hint}>
              A path on the server, as passed to <code>caspar build --benchmark</code>.
            </span>
          </div>

          <div className={styles.row2}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="target">
                Target
              </label>
              <select
                id="target"
                className={styles.select}
                value={target}
                onChange={(e) => setTarget(e.target.value as "apache-httpd" | "nginx")}
              >
                <option value="apache-httpd">apache-httpd</option>
                <option value="nginx">nginx</option>
              </select>
            </div>

            <div className={styles.field}>
              <label className={styles.label} htmlFor="model">
                LLM model
              </label>
              <input
                id="model"
                className={styles.input}
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
            </div>
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="ollama">
              Ollama URL
            </label>
            <input
              id="ollama"
              className={styles.input}
              value={ollamaUrl}
              onChange={(e) => setOllamaUrl(e.target.value)}
            />
          </div>

          <label className={styles.checkboxRow}>
            <input
              type="checkbox"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
            />
            Dry run — extract and score without writing to the database
          </label>

          {startBuild.isError && (
            <div className={styles.error}>{(startBuild.error as Error).message}</div>
          )}

          <div className={styles.actions}>
            <Button
              variant="primary"
              icon={<PlayCircle size={16} />}
              onClick={handleStart}
              disabled={!benchmark || startBuild.isPending}
            >
              {startBuild.isPending ? "Starting…" : "Start build"}
            </Button>
          </div>
        </div>
      </Card>

      <Card title="Build output" subtitle="Streams while the job runs.">
        <JobConsole
          jobId={activeJobId}
          onFinished={handleFinished}
          placeholder="Start a build to stream its output here."
        />
      </Card>

      <Card title="Build history" subtitle="Past builds on this server. Select one to view its log.">
        {isLoading ? (
          <SkeletonBlock rows={4} />
        ) : jobs && jobs.length > 0 ? (
          <div>
            {jobs.map((job) => (
              <div
                key={job.id}
                className={[
                  styles.jobRow,
                  job.id === activeJobId ? styles.jobRowActive : "",
                ].join(" ")}
                onClick={() => setActiveJobId(job.id)}
              >
                <span className={styles.jobMeta}>{job.id.slice(0, 8)}</span>
                <span style={{ flex: 1 }}>
                  {new Date(job.created_at).toLocaleString()}
                </span>
                <Badge tone={STATUS_TONE[job.status]}>{job.status}</Badge>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState icon={<History size={22} />} title="No builds run yet" />
        )}
      </Card>
    </>
  );
}
