import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { TargetInfo } from "./types";

export function useTargets() {
  return useQuery({
    queryKey: ["targets"],
    queryFn: () => api.get<TargetInfo[]>("/targets"),
  });
}
