import { useQuery } from "@tanstack/react-query";
import { getAnalysisResults, getHealth, getModelInfo } from "./client";
import { getRecordedAnalysis } from "./recorded";
import { getCaptureContext, isRecordedSample } from "../lib/capture-session";

export function useBackendStatus() {
  return useQuery({ queryKey: ["backend-health"], queryFn: getHealth, retry: false, refetchInterval: 30_000 });
}

export function useModelStatus(enabled: boolean) {
  return useQuery({ queryKey: ["model-info"], queryFn: getModelInfo, enabled, retry: false, staleTime: 60_000 });
}

export function useCaptureResults(captureId: string, search: string) {
  const recorded = isRecordedSample(search);
  const context = getCaptureContext(captureId);
  return useQuery({
    queryKey: ["capture-results", captureId, recorded ? "recorded" : "live"],
    queryFn: () => recorded ? getRecordedAnalysis(captureId) : getAnalysisResults(captureId, context.captureToken),
    enabled: Boolean(captureId),
    retry: false,
  });
}
