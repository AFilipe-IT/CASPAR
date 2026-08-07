import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { AttackChain, Benchmark, Misconfiguration } from "./types";

export function useBenchmarks() {
  return useQuery({
    queryKey: ["knowledge", "benchmarks"],
    queryFn: () => api.get<Benchmark[]>("/knowledge/benchmarks"),
  });
}

export function useTargetRules(target: string | undefined, directive?: string) {
  return useQuery({
    queryKey: ["knowledge", "rules", target, directive],
    queryFn: () =>
      api.get<Misconfiguration[]>(
        `/knowledge/targets/${target}/rules${directive ? `?directive=${encodeURIComponent(directive)}` : ""}`,
      ),
    enabled: !!target,
  });
}

export function useRuleDetail(target: string | undefined, ruleId: string | undefined) {
  return useQuery({
    queryKey: ["knowledge", "rule", target, ruleId],
    queryFn: () => api.get<Misconfiguration>(`/knowledge/targets/${target}/rules/${ruleId}`),
    enabled: !!target && !!ruleId,
  });
}

export function useTargetChains(target: string | undefined) {
  return useQuery({
    queryKey: ["knowledge", "chains", target],
    queryFn: () => api.get<AttackChain[]>(`/knowledge/targets/${target}/chains`),
    enabled: !!target,
  });
}
