/**
 * api/client.ts
 * Typed Axios API client for the Janus FastAPI backend.
 * Base URL is resolved from VITE_API_URL env var (Vite exposes import.meta.env).
 */
import axios, { type AxiosProgressEvent } from "axios";
import type {
  UploadResponse,
  AnalysisStatus,
  AnalysisResults,
  PaginatedFlows,
  FlowDetail,
  ComplianceReport,
  GenerateReportResponse,
  ReportStatus,
  ExplainerResponse,
  ReportNarrativeResponse,
} from "../types";

// ─── Axios Instance ───────────────────────────────────────────────────────────

const BASE_URL: string =
  // @ts-expect-error Vite injects import.meta.env at build time
  (import.meta.env?.VITE_API_URL as string | undefined) ?? "http://localhost:8000";

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
  timeout: 30_000,
});

apiClient.interceptors.response.use(
  (res) => res,
  (err: unknown) => {
    return Promise.reject(err);
  }
);

// ─── Typed API Functions ──────────────────────────────────────────────────────

/**
 * Upload a PCAP/PCAPng file for analysis.
 * @param file - The capture file chosen by the user.
 * @param onProgress - Optional upload progress callback (0-100).
 */
export async function uploadPcap(
  file: File,
  onProgress?: (percent: number) => void
): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);

  const { data } = await apiClient.post<UploadResponse>("/api/captures/upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress: (evt: AxiosProgressEvent) => {
      if (onProgress && evt.total) {
        onProgress(Math.round((evt.loaded / evt.total) * 100));
      }
    },
  });
  return data;
}

/**
 * Poll the analysis pipeline status for a given capture.
 */
export async function getAnalysisStatus(captureId: string): Promise<AnalysisStatus> {
  const { data } = await apiClient.get<AnalysisStatus>(
    `/api/analysis/${encodeURIComponent(captureId)}/status`
  );
  return data;
}

const complianceCache = new Map<string, ComplianceReport>();
const analysisCache = new Map<string, AnalysisResults>();

/**
 * Retrieve the full analysis results once the pipeline is DONE.
 */
export async function getAnalysisResults(captureId: string): Promise<AnalysisResults> {
  if (analysisCache.has(captureId)) {
    return analysisCache.get(captureId)!;
  }
  const { data } = await apiClient.get<AnalysisResults>(
    `/api/analysis/${encodeURIComponent(captureId)}/results`
  );
  analysisCache.set(captureId, data);
  return data;
}

/**
 * Fetch a paginated list of classified flows for a capture.
 */
export async function getFlows(
  captureId: string,
  page: number,
  pageSize: number
): Promise<PaginatedFlows> {
  const { data } = await apiClient.get<PaginatedFlows>(
    `/api/analysis/${encodeURIComponent(captureId)}/flows`,
    { params: { page, page_size: pageSize } }
  );
  return data;
}

/**
 * Fetch detailed information (including IAT/size samples) for a single flow.
 */
export async function getFlowDetail(
  captureId: string,
  flowId: string
): Promise<FlowDetail> {
  const { data } = await apiClient.get<FlowDetail>(
    `/api/analysis/${encodeURIComponent(captureId)}/flows/${encodeURIComponent(flowId)}`
  );
  return data;
}

/**
 * Fetch the compliance assessment report for a capture.
 */
export async function getCompliance(captureId: string): Promise<ComplianceReport> {
  if (complianceCache.has(captureId)) {
    return complianceCache.get(captureId)!;
  }
  const { data } = await apiClient.get<ComplianceReport>(
    `/api/compliance/${encodeURIComponent(captureId)}`
  );
  complianceCache.set(captureId, data);
  return data;
}

export const getComplianceReport = getCompliance;

/**
 * Run ad-hoc compliance scoring simulation.
 */
export async function runAdHocEvaluation(params: {
  esp_encryption: string;
  esp_auth?: string;
  dh_group?: number;
  pfs_enabled?: boolean;
  sa_lifetime_seconds?: number;
  rsa_key_bits?: number;
  ike_version?: string;
}): Promise<ComplianceReport> {
  const { data } = await apiClient.post<ComplianceReport>("/api/compliance/adhoc", params);
  return data;
}

/**
 * URL helpers for direct browser PDF download.
 */
export function getExecutiveReportUrl(captureId: string): string {
  return `${BASE_URL}/api/report/${encodeURIComponent(captureId)}/executive`;
}

export function getTechnicalReportUrl(captureId: string): string {
  return `${BASE_URL}/api/report/${encodeURIComponent(captureId)}/technical`;
}

/**
 * Trigger report generation (PDF) for a capture.
 */
export async function generateReport(captureId: string): Promise<GenerateReportResponse> {
  const { data } = await apiClient.post<GenerateReportResponse>(
    `/api/report/${encodeURIComponent(captureId)}/generate`
  );
  return data;
}

export async function getReportStatus(
  captureId: string,
  reportId: string
): Promise<ReportStatus> {
  const { data } = await apiClient.get<ReportStatus>(
    `/api/report/${encodeURIComponent(captureId)}/status/${encodeURIComponent(reportId)}`
  );
  return data;
}

// ─── SSE Progress Stream ──────────────────────────────────────────────────────

/**
 * Open a Server-Sent Events connection for live pipeline progress.
 * Returns the EventSource so the caller can close it on unmount.
 *
 * @param captureId - The session ID to monitor.
 * @param onProgress - Called on each progress event with {status, progress_pct, message}.
 * @param onDone     - Called when pipeline is complete.
 * @param onError    - Called on SSE error or pipeline failure.
 */
export function streamAnalysisProgress(
  captureId: string,
  onProgress: (data: { status: string; progress_pct: number; message: string }) => void,
  onDone: (data: { status: string; progress_pct: number; message: string; summary?: unknown }) => void,
  onError: (err: string) => void
): EventSource {
  const url = `${BASE_URL}/api/analysis/${encodeURIComponent(captureId)}/stream`;
  const sse = new EventSource(url);

  sse.addEventListener("progress", (e: MessageEvent) => {
    try { onProgress(JSON.parse(e.data)); } catch { /* ignore */ }
  });

  sse.addEventListener("done", (e: MessageEvent) => {
    try { onDone(JSON.parse(e.data)); } catch { /* ignore */ }
    sse.close();
  });

  sse.addEventListener("error", (e: MessageEvent) => {
    try { onError(JSON.parse((e as any).data)?.error ?? "SSE error"); } catch { /* ignore */ }
    sse.close();
  });

  sse.onerror = () => {
    onError("SSE connection failed");
    sse.close();
  };

  return sse;
}

// ─── Model Info ───────────────────────────────────────────────────────────────

/**
 * Fetch ML ensemble metadata from /api/model/info.
 * Returns architecture details, training stats, and feature count.
 */
export async function getModelInfo(): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get<Record<string, unknown>>("/api/model/info");
  return data;
}

// ─── CSV Export (client-side helper) ─────────────────────────────────────────

/**
 * Trigger a backend-generated CSV download of flow predictions.
 * Opens the download URL directly so the browser handles the file save dialog.
 */
export function triggerFlowsCsvDownload(captureId: string): void {
  const url = `${BASE_URL}/api/analysis/${encodeURIComponent(captureId)}/export/csv`;
  const a = document.createElement("a");
  a.href = url;
  a.download = `janus_flows_${captureId.slice(0, 8)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ─── Compliance-RAG Explainer API ───────────────────────────────────────────

/**
 * Request natural language explanation for an arbitrary compliance finding,
 * citing exact RFC/NIST clauses.
 */
export async function explainFinding(
  finding: Record<string, unknown>,
  topK: number = 3
): Promise<ExplainerResponse> {
  const { data } = await apiClient.post<ExplainerResponse>("/api/compliance/explain", {
    finding,
    top_k: topK,
  });
  return data;
}

/**
 * Request natural language explanation for a finding in a specific capture session.
 */
export async function explainSessionFinding(
  captureId: string,
  ruleId: string,
  topK: number = 3
): Promise<ExplainerResponse> {
  const { data } = await apiClient.post<ExplainerResponse>(
    `/api/compliance/${encodeURIComponent(captureId)}/explain-finding/${encodeURIComponent(ruleId)}?top_k=${topK}`
  );
  return data;
}

/**
 * Draft executive summary narrative and technical protocol commentary prose
 * around the deterministic compliance findings tables.
 */
export async function draftReportNarrative(
  captureId: string
): Promise<ReportNarrativeResponse> {
  const { data } = await apiClient.post<ReportNarrativeResponse>(
    `/api/report/${encodeURIComponent(captureId)}/draft-narrative`
  );
  return data;
}


