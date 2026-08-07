import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { RunnerState, WatchDetail, WatchSession } from "./types";

// Watch is a live view: unlike a job, a session has no terminal state to stop
// polling on, so the cadence is constant while the page is open.
const POLL_MS = 3000;

export function useWatchSessions() {
  return useQuery({
    queryKey: ["watch"],
    queryFn: () => api.get<WatchSession[]>("/watch"),
    refetchInterval: POLL_MS,
  });
}

export function useWatchSession(sessionId: string | undefined) {
  return useQuery({
    queryKey: ["watch", sessionId],
    queryFn: () => api.get<WatchDetail>(`/watch/${sessionId}`),
    enabled: !!sessionId,
    refetchInterval: POLL_MS,
  });
}

export interface StartWatchParams {
  path: string;
  live?: boolean;
  interval?: number;
  env_profile?: "production" | "internal" | "dev";
  host?: string;
}

export function useStartWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: StartWatchParams) =>
      api.post<{ watch_session: string; path: string; interval: number }>(
        "/watch",
        params,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["watch"] }),
  });
}

/**
 * pause / resume / stop. These only work on sessions this server process
 * started — the API answers 409 for a CLI-started session, which the page
 * surfaces rather than swallowing.
 */
export function useWatchControl() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      sessionId,
      action,
    }: {
      sessionId: string;
      action: "pause" | "resume" | "stop";
    }) =>
      api.post<{ watch_session: string; runner_state: RunnerState | null }>(
        `/watch/${sessionId}/${action}`,
        {},
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["watch"] }),
  });
}
