import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Cpu,
  Download,
  FileCheck2,
  Layers,
  Lock,
  Play,
  RefreshCw,
  ShieldCheck,
  Terminal,
  UploadCloud,
  X,
} from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import { analyzeSample, getAnalysisStatus, streamAnalysisProgress, uploadPcap } from "../api/client";
import ScoreGauge from "../components/ScoreGauge";
import { ErrorState, InlineNotice, LoadingState, PageHeader } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { saveCaptureContext } from "../lib/capture-session";
import { cn } from "../lib/cn";
import { formatBytes } from "../lib/format";
import { recordedAnalysisPath, recordedSampleCaptures, sampleDownloadHref, useTestbedSamples } from "../lib/sample-captures";
import type { AnalysisStatus } from "../types";

const statusText: Record<AnalysisStatus["status"], string> = {
  INIT: "Initializing",
  PARSING: "Protocol Parsing",
  CLASSIFYING: "Statistical Flow Classification",
  SCORING: "RFC Compliance Scoring",
  DONE: "Analysis Complete",
  ERROR: "Pipeline Failed",
  INDETERMINATE: "Not Assessable",
};

const PIPELINE_STAGES = [
  { key: "PARSING", label: "Protocol Parsing", desc: "tshark IKE & dpkt ESP extraction", icon: Layers },
  { key: "CLASSIFYING", label: "Flow Telemetry", desc: "FlowDeepNet 25D statistical analysis", icon: Cpu },
  { key: "SCORING", label: "Compliance Audit", desc: "RFC 8221, RFC 8247 & NIST SP 800-77", icon: Lock },
  { key: "DONE", label: "Finished", desc: "Interactive workspace & reports ready", icon: ShieldCheck },
];

function getStageIndex(status: AnalysisStatus["status"]): number {
  switch (status) {
    case "INIT":
    case "PARSING":
      return 0;
    case "CLASSIFYING":
      return 1;
    case "SCORING":
      return 2;
    case "DONE":
      return 3;
    default:
      return 0;
  }
}

type MonitoringMode = "idle" | "streaming" | "polling";

function mergeStreamStatus(
  captureId: string,
  current: AnalysisStatus | null,
  next: Partial<AnalysisStatus>,
): AnalysisStatus {
  const initial: AnalysisStatus = { capture_id: captureId, status: "INIT", progress_pct: 0, logs: [], error: null };
  return { ...initial, ...current, ...next, error: null };
}

export default function Upload() {
  const fileInput = useRef<HTMLInputElement>(null);
  const stream = useRef<EventSource | null>(null);
  const timer = useRef<number | null>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);
  const dragDepth = useRef(0);

  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [showAnalysisModal, setShowAnalysisModal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [monitoringMode, setMonitoringMode] = useState<MonitoringMode>("idle");
  const [connectionNote, setConnectionNote] = useState<string | null>(null);
  const [isDragActive, setIsDragActive] = useState(false);
  const [analyzingSampleId, setAnalyzingSampleId] = useState<string | null>(null);

  const location = useLocation();
  useEffect(() => {
    const preloaded = (location.state as { preloadedFile?: File } | null)?.preloadedFile;
    if (preloaded && !file) {
      chooseFile(preloaded);
    }
  }, [location.state]);

  const samples = useTestbedSamples();

  const clearMonitoring = useCallback(() => {
    stream.current?.close();
    stream.current = null;
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = null;
  }, []);

  const poll = useCallback(async (captureId: string, captureToken: string | undefined, delay: number, failures = 0) => {
    try {
      const next = await getAnalysisStatus(captureId, captureToken);
      setStatus(next);
      if (next.status === "ERROR") {
        setError(next.error ?? next.message ?? "The analysis pipeline reported an error.");
        setMonitoringMode("idle");
        return;
      }
      if (next.status === "DONE" || next.status === "INDETERMINATE") {
        setMonitoringMode("idle");
        return;
      }
      timer.current = window.setTimeout(() => void poll(captureId, captureToken, Math.min(delay * 1.5, 4_000)), delay);
    } catch (pollError) {
      if (failures >= 3) {
        setError(`Unable to retrieve pipeline status after four attempts: ${getApiErrorMessage(pollError)}`);
        setMonitoringMode("idle");
        return;
      }
      timer.current = window.setTimeout(() => void poll(captureId, captureToken, Math.min(delay * 2, 6_000), failures + 1), delay);
    }
  }, []);

  const monitor = useCallback((captureId: string, captureToken: string | undefined) => {
    clearMonitoring();
    setMonitoringMode("streaming");
    setConnectionNote(null);
    stream.current = streamAnalysisProgress(captureId, captureToken, {
      onProgress: (next) => {
        setStatus((current) => mergeStreamStatus(captureId, current, next));
      },
      onDone: (next) => {
        setStatus((current) => ({ ...mergeStreamStatus(captureId, current, next), status: "DONE", progress_pct: 100 }));
        setMonitoringMode("idle");
      },
      onFailure: (message) => {
        clearMonitoring();
        setMonitoringMode("polling");
        setConnectionNote(`Live stream disconnected (${message}). Switched to status polling.`);
        void poll(captureId, captureToken, 1_000);
      },
    });
  }, [clearMonitoring, poll]);

  useEffect(() => () => clearMonitoring(), [clearMonitoring]);

  // Auto-scroll terminal logs
  useEffect(() => {
    if (logsContainerRef.current) {
      logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
    }
  }, [status?.logs]);

  function chooseFile(next: File) {
    const isValid = /\.(pcap|pcapng|cap|dmp|dump|gz)$/i.test(next.name);
    if (!isValid) {
      setError(`Unsupported file extension for '${next.name}'. Please choose a .pcap, .pcapng, .cap, or .gz capture.`);
      return;
    }
    setFile(next);
    setError(null);
  }

  function dragEnter(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    dragDepth.current += 1;
    setIsDragActive(true);
  }

  function dragLeave(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setIsDragActive(false);
  }

  function dragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  }

  function drop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    dragDepth.current = 0;
    setIsDragActive(false);
    const next = event.dataTransfer.files.item(0);
    if (next) chooseFile(next);
  }

  async function submit() {
    if (!file) return;
    clearMonitoring();
    setUploading(true);
    setUploadProgress(0);
    setError(null);
    setStatus(null);
    setConnectionNote(null);
    setMonitoringMode("idle");
    try {
      const response = await uploadPcap(file, setUploadProgress);
      saveCaptureContext(response);
      setStatus({ capture_id: response.capture_id, status: "INIT", progress_pct: 5, message: "Capture accepted by server", logs: [] });
      setShowAnalysisModal(true);
      monitor(response.capture_id, response.capture_token ?? undefined);
    } catch (uploadError) {
      setError(getApiErrorMessage(uploadError));
    } finally {
      setUploading(false);
    }
  }

  async function handleAnalyzeSample(sampleId: string) {
    clearMonitoring();
    setAnalyzingSampleId(sampleId);
    setError(null);
    setStatus(null);
    setConnectionNote(null);
    try {
      const response = await analyzeSample(sampleId);
      saveCaptureContext(response);
      setStatus({ capture_id: response.capture_id, status: "INIT", progress_pct: 10, message: "Sample capture loaded. Launching pipeline...", logs: [] });
      setShowAnalysisModal(true);
      monitor(response.capture_id, response.capture_token ?? undefined);
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setAnalyzingSampleId(null);
    }
  }

  const isDone = status?.status === "DONE" || status?.status === "INDETERMINATE";
  const isError = status?.status === "ERROR";
  const currentStageIdx = status ? getStageIndex(status.status) : 0;
  const parsedScoreMatch = status?.message?.match(/(\d+(?:\.\d+)?)\/100\s*\((?:Grade\s*)?([A-F]|N\/A)/i);
  const parsedScore = parsedScoreMatch ? parseFloat(parsedScoreMatch[1]) : null;
  const parsedGrade = parsedScoreMatch ? parsedScoreMatch[2] : null;

  return (
    <div className="space-y-10 motion-enter max-w-4xl mx-auto">
      <PageHeader
        eyebrow="Capture Intake"
        title="Upload an IPsec capture."
        answer="Drop a packet capture to dissect observed IKE negotiation transforms, classify ESP flows with zero IP leakage, and audit RFC 8221/8247 compliance."
      />

      {/* Upload Zone Card */}
      <section className="border border-rule bg-surface p-6 sm:p-8 space-y-6">
        <div
          onDrop={drop}
          onDragEnter={dragEnter}
          onDragLeave={dragLeave}
          onDragOver={dragOver}
          onClick={() => fileInput.current?.click()}
          className={cn(
            "group relative grid min-h-56 place-items-center rounded-xl border-2 border-dashed p-8 text-center cursor-pointer transition-all duration-200",
            isDragActive
              ? "border-accent bg-accent/5 ring-4 ring-accent/20 scale-[1.01]"
              : file
              ? "border-accent/80 bg-sunken/40"
              : "border-rule/80 hover:border-accent hover:bg-sunken/30"
          )}
        >
          <input
            ref={fileInput}
            type="file"
            accept=".pcap,.pcapng,.cap,.dmp,.dump,.gz"
            className="sr-only"
            tabIndex={-1}
            aria-hidden="true"
            onChange={(event) => {
              const next = event.currentTarget.files?.item(0);
              if (next) chooseFile(next);
            }}
          />

          <div className="flex flex-col items-center space-y-3">
            <div className={cn(
              "grid size-14 place-items-center rounded-full border transition-all duration-200",
              file
                ? "border-accent bg-accent/10 text-accent"
                : "border-rule bg-sunken text-muted group-hover:border-accent group-hover:text-accent"
            )}>
              {file ? <FileCheck2 size={26} /> : <UploadCloud size={26} />}
            </div>

            <div className="space-y-1">
              <p className="font-semibold text-ink sm:text-base">
                {file ? file.name : isDragActive ? "Drop capture file here" : "Choose or drag a capture here"}
              </p>
              <p className="text-xs text-muted">
                {file
                  ? `${formatBytes(file.size)} · ready for autonomous analysis`
                  : "Supports standard PCAP, nanosecond PCAP, PCAPng, .cap, and gzip captures (up to 100 MB)"}
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => fileInput.current?.click()}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-rule px-4 text-xs font-semibold text-ink hover:border-accent transition-colors"
            >
              Browse device
            </button>
            {file && (
              <button
                type="button"
                onClick={() => { setFile(null); setError(null); }}
                className="inline-flex min-h-10 items-center gap-1 rounded-lg border border-transparent px-3 text-xs text-muted hover:text-ink transition-colors"
              >
                <X size={14} /> Clear
              </button>
            )}
          </div>

          <button
            type="button"
            onClick={() => void submit()}
            disabled={!file || uploading}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-accent px-6 text-sm font-semibold text-white shadow-sm hover:bg-accent-strong disabled:cursor-not-allowed disabled:bg-rule transition-all"
          >
            {uploading ? (
              <>
                <RefreshCw size={15} className="animate-spin" />
                <span>Uploading ({uploadProgress}%)</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>Analyze Capture</span>
              </>
            )}
          </button>
        </div>
      </section>

      {/* Error notification */}
      {error && (
        <ErrorState
          title="Upload or analysis failed"
          detail={error}
          onRetry={file ? () => void submit() : undefined}
        />
      )}

      {/* In-page compact status indicator when pop-up is dismissed */}
      {status && !showAnalysisModal && (
        <section className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-accent/40 bg-accent/5 p-4 sm:p-5 shadow-sm motion-enter">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "size-3 rounded-full shrink-0",
                isDone ? "bg-pass" : isError ? "bg-critical" : "bg-accent animate-pulse"
              )}
            />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-ink">
                  {statusText[status.status]}
                </span>
                <span className="font-mono text-xs text-muted">
                  ({Math.round(status.progress_pct)}%)
                </span>
              </div>
              <p className="text-xs text-muted mt-0.5 line-clamp-1">
                {status.message ?? "Running autonomous pipeline stages..."}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setShowAnalysisModal(true)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-accent-strong transition-all"
            >
              <span>View Analysis Details</span>
              <ArrowRight size={13} />
            </button>
          </div>
        </section>
      )}

      {/* Focused Pop-up Modal Window for Active/Completed Analysis */}
      {status && showAnalysisModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-md overflow-y-auto motion-fade"
          role="dialog"
          aria-modal="true"
          aria-labelledby="analysis-modal-title"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowAnalysisModal(false);
          }}
        >
          <div
            className="relative w-full max-w-3xl rounded-2xl border border-rule bg-surface p-6 sm:p-7 shadow-2xl space-y-6 motion-scale-in my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close button in top-right */}
            <button
              type="button"
              onClick={() => setShowAnalysisModal(false)}
              className="absolute top-5 right-5 p-1.5 rounded-lg text-muted hover:text-ink hover:bg-sunken transition-colors"
              aria-label="Close analysis popup"
            >
              <X size={18} />
            </button>

            {/* Top Bar: Progress & Stage Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-rule pb-5 pr-8">
              <div>
                <div className="flex items-center gap-2.5">
                  <div
                    className={cn(
                      "size-2.5 rounded-full",
                      isDone ? "bg-pass" : isError ? "bg-critical" : "bg-accent animate-pulse"
                    )}
                  />
                  <h2 id="analysis-modal-title" className="text-lg font-bold text-ink">
                    {statusText[status.status]}
                  </h2>
                  <span className="font-mono text-xs text-muted">
                    ({Math.round(status.progress_pct)}%)
                  </span>
                </div>
                <p className="mt-1 text-xs text-muted">
                  {status.message ?? "Running autonomous pipeline stages..."}
                </p>
              </div>

              {/* Overall Progress Bar */}
              <div className="w-full sm:w-56 space-y-1">
                <div className="h-2 w-full overflow-hidden rounded-full bg-sunken">
                  <div
                    className="h-full bg-accent transition-all duration-300"
                    style={{ width: `${Math.max(5, Math.min(100, status.progress_pct))}%` }}
                  />
                </div>
                <div className="flex justify-between font-mono text-[10px] text-muted">
                  <span>{monitoringMode === "streaming" ? "Live Stream" : "Status Polling"}</span>
                  <span>{Math.round(status.progress_pct)}%</span>
                </div>
              </div>
            </div>

            {/* 4-Stage Visual Stepper */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {PIPELINE_STAGES.map((stage, idx) => {
                const isPast = isDone || currentStageIdx > idx;
                const isCurrent = !isDone && currentStageIdx === idx;
                const Icon = stage.icon;

                return (
                  <div
                    key={stage.key}
                    className={cn(
                      "rounded-xl border p-3.5 transition-all text-left",
                      isCurrent
                        ? "border-accent bg-accent/5 ring-2 ring-accent/20"
                        : isPast
                        ? "border-pass/40 bg-pass/5 text-ink"
                        : "border-rule/60 bg-sunken/40 text-muted opacity-60"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-muted">Stage 0{idx + 1}</span>
                      {isPast ? (
                        <CheckCircle2 size={15} className="text-pass" />
                      ) : isCurrent ? (
                        <RefreshCw size={14} className="animate-spin text-accent" />
                      ) : (
                        <Icon size={14} />
                      )}
                    </div>
                    <p className="mt-2 text-xs font-bold text-ink">{stage.label}</p>
                    <p className="text-[11px] text-muted truncate">{stage.desc}</p>
                  </div>
                );
              })}
            </div>

            {/* When complete: Show the Verdict Score Gauge */}
            {isDone && parsedScore !== null && parsedGrade && (
              <div className="flex flex-col sm:flex-row items-center justify-between gap-5 border border-rule bg-sunken/40 p-4 sm:p-5 motion-enter">
                <div className="space-y-1.5 text-center sm:text-left">
                  <p className="font-mono text-xs font-semibold text-accent">
                    Audit Verdict
                  </p>
                  <h3 className="text-sm font-bold text-ink mt-1">RFC Compliance &amp; Dissection Evaluation</h3>
                  <p className="text-xs text-muted max-w-md leading-relaxed">
                    {status.message}
                  </p>
                </div>
                <div className="shrink-0">
                  <ScoreGauge
                    score={parsedScore}
                    grade={parsedGrade}
                    label="Evaluated Score"
                    size={140}
                  />
                </div>
              </div>
            )}

            {/* Live Terminal Log Stream */}
            <div className="rounded-xl border border-rule bg-canvas p-4 space-y-2">
              <div className="flex items-center justify-between border-b border-rule/60 pb-2 text-xs font-mono text-muted">
                <div className="flex items-center gap-2">
                  <Terminal size={14} className="text-accent" />
                  <span>Execution Dissection Log</span>
                </div>
                <span className="text-[10px] uppercase font-bold">
                  {isDone ? "COMPLETE" : isError ? "HALTED" : "DISSECTING"}
                </span>
              </div>

              <div
                ref={logsContainerRef}
                className="max-h-44 overflow-y-auto space-y-1.5 font-mono text-xs leading-relaxed"
              >
                {status.logs.length === 0 ? (
                  <div className="flex items-center gap-2 text-muted py-2">
                    <RefreshCw size={12} className="animate-spin text-accent" />
                    <span>Spawning worker pipeline and initializing packet dissector...</span>
                  </div>
                ) : (
                  status.logs.map((logLine, idx) => {
                    const isOk = logLine.includes("Complete") || logLine.includes("Succeeded") || logLine.includes("Validating");
                    const isInfo = logLine.includes("IKE") || logLine.includes("RFC") || logLine.includes("FlowDeepNet") || logLine.includes("SHAP");
                    const isErr = logLine.includes("Failed") || logLine.includes("Error") || logLine.includes("CRITICAL");

                    return (
                      <div key={idx} className="flex items-start gap-2">
                        <span className="text-muted select-none">&gt;</span>
                        <span className={cn(
                          isErr ? "text-critical font-medium" : isOk ? "text-pass" : isInfo ? "text-accent font-medium" : "text-ink"
                        )}>
                          {logLine}
                        </span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-rule">
              <button
                type="button"
                onClick={() => setShowAnalysisModal(false)}
                className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-rule bg-surface px-4 text-xs font-semibold text-muted hover:text-ink hover:border-accent transition-colors"
              >
                <span>Dismiss</span>
              </button>

              {isDone ? (
                <div className="flex flex-wrap items-center gap-3">
                  <Link
                    to={`/analysis/${encodeURIComponent(status.capture_id)}`}
                    className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-rule bg-surface px-4 text-xs font-semibold text-ink hover:border-accent transition-colors"
                  >
                    <Cpu size={15} />
                    View Flow Classification
                  </Link>

                  <Link
                    to={`/compliance/${encodeURIComponent(status.capture_id)}`}
                    className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-accent px-5 text-xs font-semibold text-white shadow-sm hover:bg-accent-strong transition-colors"
                  >
                    <ShieldCheck size={15} />
                    View Compliance Audit
                    <ArrowRight size={14} />
                  </Link>
                </div>
              ) : (
                <span className="text-xs font-mono text-muted flex items-center gap-2">
                  <RefreshCw size={12} className="animate-spin text-accent" />
                  Autonomous pipeline active...
                </span>
              )}
            </div>

            {connectionNote && <InlineNotice>{connectionNote}</InlineNotice>}
          </div>
        </div>
      )}

      {/* Live Testbed Captures Catalog with 1-Click Analyze */}
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-lg font-bold text-ink flex items-center gap-2">
              <FileCheck2 size={18} className="text-accent" />
              Verified Testbed Captures
            </h2>
            <p className="text-xs text-muted mt-0.5">
              Run live evaluations with real strongSwan captures or Wireshark testbed files in a single click.
            </p>
          </div>

          <a
            href="https://wiki.wireshark.org/SampleCaptures#ipsec"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-mono text-accent hover:underline inline-flex items-center gap-1"
          >
            Wireshark Samples Wiki &rarr;
          </a>
        </div>

        {samples.isPending && <LoadingState label="Loading sample captures..." />}
        {samples.isError && (
          <InlineNotice>Sample captures unavailable: {getApiErrorMessage(samples.error)}</InlineNotice>
        )}

        {samples.data && (
          <div className="grid gap-3 sm:grid-cols-2">
            {samples.data.map((sample, idx) => (
              <div
                key={sample.id}
                className={cn(
                  "flex flex-col justify-between border border-rule bg-surface p-4 space-y-3",
                  idx < 4 ? `stagger-${idx + 1}` : ""
                )}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-muted">
                      {sample.category}
                    </span>
                    <span className="font-mono text-[11px] text-muted">
                      {formatBytes(sample.size_bytes)}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-ink">{sample.title}</h3>
                  <p className="text-xs text-muted leading-relaxed line-clamp-2">{sample.description}</p>
                  <p className="font-mono text-[11px] text-ink/80 truncate">{sample.cipher}</p>
                </div>

                <div className="flex items-center justify-between gap-2 pt-2 border-t border-rule">
                  <a
                    href={sampleDownloadHref(sample)}
                    download={sample.filename}
                    className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-ink transition-colors"
                  >
                    <Download size={13} />
                    <span>Download</span>
                  </a>

                  <button
                    type="button"
                    disabled={analyzingSampleId === sample.id || uploading}
                    onClick={() => handleAnalyzeSample(sample.id)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50 transition-all cursor-pointer"
                  >
                    <Play size={12} />
                    <span>{analyzingSampleId === sample.id ? "Launching..." : "1-Click Analyze"}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Fixture-backed walkthrough demo shortcut */}
      <section className="border-t border-rule pt-6 space-y-3">
        <h3 className="text-xs font-medium text-muted">
          Recorded sample fixtures (offline evaluation):
        </h3>
        <div className="flex flex-wrap gap-2">
          {recordedSampleCaptures.map((sample) => (
            <Link
              key={sample.id}
              to={recordedAnalysisPath(sample)}
              className="inline-flex items-center gap-2 rounded border border-rule bg-sunken/40 px-3 py-1.5 text-xs font-mono text-ink hover:border-accent transition-colors"
            >
              <span>{sample.title}</span>
              <span className="text-[11px] text-muted">
                ({sample.cipher})
              </span>
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
