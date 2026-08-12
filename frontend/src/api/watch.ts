import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { RunnerState, WatchDetail, WatchSession } from "./types";

// Watch is a live view: unlike a job, a session has no terminal state to stop
// polling on, so the cadence is constant while the page is open.
const POLL_MS = 3000;

// Nota, porque é um engano fácil: o `staleTime` global (10s) é maior que este
// intervalo, mas não o trava — o `refetchInterval` dispara à mesma. Foi
// medido, não deduzido. Não vale a pena pôr aqui `staleTime: 0` a pensar que
// desbloqueia o poll.
const LIVE = { refetchInterval: POLL_MS } as const;

export function useWatchSessions() {
  return useQuery({
    queryKey: ["watch"],
    queryFn: () => api.get<WatchSession[]>("/watch"),
    ...LIVE,
  });
}

export function useWatchSession(sessionId: string | undefined) {
  return useQuery({
    queryKey: ["watch", sessionId],
    queryFn: () => api.get<WatchDetail>(`/watch/${sessionId}`),
    enabled: !!sessionId,
    ...LIVE,
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
 * Apagar uma sessão parada e o seu histórico. A API responde 409 a uma sessão
 * ainda a correr — pará-la primeiro é deliberado, não uma limitação: apagar
 * debaixo do loop deixá-lo-ia a escrever eventos de um histórico que já não
 * existe.
 */
export function useDeleteWatchSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (sessionId: string) =>
      api.delete<{ watch_session: string; events_removed: number }>(
        `/watch/${sessionId}`,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["watch"] }),
  });
}

/** Limpar todas as sessões paradas de uma vez; as vivas ficam. */
export function useClearWatchSessions() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.delete<{ sessions_removed: number; kept_running: number }>("/watch"),
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
