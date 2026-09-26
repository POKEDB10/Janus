import { useQuery } from "@tanstack/react-query";
import { API_BASE_URL, getSamplePcaps } from "../api/client";
import type { SamplePcap } from "../types";

/**
 * Metadata for fixtures that are deliberately shipped with the frontend.
 * These samples are never used when a live testbed request fails.
 */
export interface RecordedSampleCapture {
  id: string;
  filename: string;
  title: string;
  category: string;
  rfcStatus: string;
  cipher: string;
  description: string;
}

export const recordedSampleCaptures: readonly RecordedSampleCapture[] = [
  {
    id: "wireshark_ikev2_aes_gcm",
    filename: "wireshark_ikev2_aes_gcm.pcap",
    title: "IKEv2 AES-GCM capture",
    category: "Recorded analysis",
    rfcStatus: "Recorded fixture",
    cipher: "AES-GCM",
    description: "A fixture-backed IKEv2 session with four classified ESP flows and a recorded compliance verdict.",
  },
];

export function recordedAnalysisPath(sample: RecordedSampleCapture): string {
  return `/analysis/${encodeURIComponent(sample.id)}?demo=1`;
}

export function sampleDownloadHref(sample: SamplePcap): string {
  const rawUrl = sample?.download_url || "";
  if (!rawUrl) return "#";
  if (rawUrl.startsWith("http://") || rawUrl.startsWith("https://")) {
    return rawUrl;
  }
  const base = API_BASE_URL || (typeof window !== "undefined" && window.location?.origin ? window.location.origin : "");
  if (!base) return rawUrl;
  try {
    return new URL(rawUrl, base).toString();
  } catch {
    return rawUrl;
  }
}

export function useTestbedSamples() {
  return useQuery({
    queryKey: ["testbed-samples"],
    queryFn: getSamplePcaps,
    retry: false,
    staleTime: 60_000,
  });
}
