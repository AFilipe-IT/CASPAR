import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { RunAssessmentForm } from "@/components/assessment/RunAssessmentForm";
import { ScanResultView } from "@/components/assessment/ScanResultView";
import { HistoryView } from "@/components/assessment/HistoryView";
import { CompareView } from "@/components/assessment/CompareView";
import { RemediateView } from "@/components/assessment/RemediateView";
import type { ScanResponse } from "@/api/types";
import styles from "./AssessmentPage.module.css";

type Tab = "run" | "history" | "compare" | "remediate";

export function AssessmentPage() {
  const [tab, setTab] = useState<Tab>("run");
  const [lastResult, setLastResult] = useState<ScanResponse | null>(null);

  return (
    <>
      <PageHeader
        title="Assessment"
        description="Run and manage configuration assessments — full parity with `caspar scan`."
      />

      <div className={styles.tabs}>
        <button
          className={[styles.tab, tab === "run" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("run")}
        >
          Run
        </button>
        <button
          className={[styles.tab, tab === "history" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("history")}
        >
          History
        </button>
        <button
          className={[styles.tab, tab === "compare" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("compare")}
        >
          Compare
        </button>
        <button
          className={[styles.tab, tab === "remediate" ? styles.tabActive : ""].join(" ")}
          onClick={() => setTab("remediate")}
        >
          Remediate
        </button>
      </div>

      {tab === "run" && (
        <>
          <RunAssessmentForm onResult={setLastResult} />
          {lastResult && (
            <div style={{ marginTop: "var(--sp-6)" }}>
              <ScanResultView result={lastResult} />
            </div>
          )}
        </>
      )}

      {tab === "history" && <HistoryView />}
      {tab === "compare" && <CompareView />}
      {tab === "remediate" && <RemediateView />}
    </>
  );
}
