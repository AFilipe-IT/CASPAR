import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { LiveService, TargetInfo } from "./types";

export function useTargets() {
  return useQuery({
    queryKey: ["targets"],
    queryFn: () => api.get<TargetInfo[]>("/targets"),
  });
}

/** Services available to `live` mode, with per-service detection.
 *  Feeds the Assessment and Watch pickers so a service name never has to be
 *  typed from memory — the resolver only accepts names from a fixed map. */
export function useLiveServices() {
  return useQuery({
    queryKey: ["targets", "live"],
    queryFn: () => api.get<LiveService[]>("/targets/live"),
  });
}
