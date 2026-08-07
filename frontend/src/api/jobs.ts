import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "./client";
import type { Job, JobLogLine, PluginsResponse } from "./types";

const POLL_MS = 2000;

function isTerminal(status: Job["status"] | undefined): boolean {
  return status === "succeeded" || status === "failed" || status === "cancelled";
}

export function useJobs(kind?: string) {
  return useQuery({
    queryKey: ["jobs", kind],
    queryFn: () => api.get<Job[]>(`/jobs${kind ? `?kind=${kind}` : ""}`),
  });
}

// Polls until the job reaches a terminal state, then stops — a finished job
// never changes again, so continuing to poll would be pure waste.
export function useJob(jobId: string | undefined) {
  return useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.get<Job>(`/jobs/${jobId}`),
    enabled: !!jobId,
    refetchInterval: (query) => (isTerminal(query.state.data?.status) ? false : POLL_MS),
  });
}

/**
 * Tails a job's log. Accumulates lines client-side and only ever asks the
 * server for `seq > last seen`, so an hour-long build doesn't re-ship its
 * whole log on every 2s poll.
 */
export function useJobLogs(jobId: string | undefined, jobStatus: Job["status"] | undefined) {
  const [lines, setLines] = useState<JobLogLine[]>([]);
  const afterRef = useRef(-1);

  // A new job means a fresh log — drop whatever the previous one accumulated.
  useEffect(() => {
    setLines([]);
    afterRef.current = -1;
  }, [jobId]);

  const query = useQuery({
    queryKey: ["job", jobId, "logs"],
    queryFn: async () => {
      const fresh = await api.get<JobLogLine[]>(
        `/jobs/${jobId}/logs?after=${afterRef.current}`,
      );
      if (fresh.length > 0) {
        afterRef.current = fresh[fresh.length - 1].seq;
        setLines((prev) => [...prev, ...fresh]);
      }
      return fresh;
    },
    enabled: !!jobId,
    // Keep polling one beat past terminal so the final lines always land.
    refetchInterval: isTerminal(jobStatus) ? false : POLL_MS,
  });

  return { lines, isLoading: query.isLoading };
}

export interface StartBuildParams {
  benchmark: string;
  target?: "apache-httpd" | "nginx";
  model?: string;
  ollama_url?: string;
  dry_run?: boolean;
}

export function useStartBuild() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: StartBuildParams) =>
      api.post<{ job_id: string }>("/builds", params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
}

export function usePlugins() {
  return useQuery({
    queryKey: ["plugins"],
    queryFn: () => api.get<PluginsResponse>("/plugins"),
  });
}

export interface InstallPluginParams {
  source: string;
  manual?: string;
  dry_run?: boolean;
  no_llm?: boolean;
  model?: string;
}

export function useInstallPlugin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: InstallPluginParams) =>
      api.post<{ job_id: string }>("/plugins/install", params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
}

// A finished install/build changes what the rest of the app can see.
export function useInvalidateAfterJob() {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["plugins"] });
    qc.invalidateQueries({ queryKey: ["targets"] });
    qc.invalidateQueries({ queryKey: ["knowledge"] });
  };
}
