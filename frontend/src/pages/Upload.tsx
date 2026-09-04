/**
 * pages/Upload.tsx — PCAP / PCAPng Upload and Live Pipeline Monitor
 * Uses SSE (Server-Sent Events) for real-time progress with animated progress bar.
 * Gracefully falls back to exponential-backoff polling if SSE is unavailable.
 */
import React, { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Upload as UploadIcon,
  FileCheck,
  AlertCircle,
  ArrowRight,
  ShieldCheck,
  Cpu,
  Lock,
  Layers,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";
import { uploadPcap, getAnalysisStatus } from "../api/client";
import type { AnalysisStatus } from "../types";

// Vite exposes env vars through import.meta.env — declared in vite-env.d.ts
const API_BASE: string = (import.meta as any).env?.VITE_API_URL ?? "http://localhost:8000";



// ─── Progress stage config ────────────────────────────────────────────────────

const PIPELINE_STAGES = [
  { label: "Protocol Parsing",    desc: "tshark IKE & dpkt ESP extraction",         Icon: Layers,     key: "PARSING"     },
  { label: "AI Classification",   desc: "FlowDeepNet Ensemble + SHAP attribution",   Icon: Cpu,        key: "CLASSIFYING" },
  { label: "Compliance Scoring",  desc: "RFC 8221, RFC 8247 & NIST audit",           Icon: Lock,       key: "SCORING"     },
  { label: "Completed",           desc: "Reports & dashboard ready",                  Icon: ShieldCheck,key: "DONE"        },
];

const STATUS_TO_STAGE: Record<string, number> = {
  INIT: 0, PARSING: 0, CLASSIFYING: 1, SCORING: 2, DONE: 3,
};

// ─── Component ───────────────────────────────────────────────────────────────

export default function UploadPage() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sseRef = useRef<EventSource | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [captureId, setCaptureId] = useState<string | null>(null);
  const [pipelineStatus, setPipelineStatus] = useState<AnalysisStatus | null>(null);
  const [progressPct, setProgressPct] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [useSSE, setUseSSE] = useState(true);

  // ── SSE connection ──────────────────────────────────────────────────────────
  const connectSSE = useCallback((id: string) => {
    if (sseRef.current) {
      sseRef.current.close();
    }

    const sse = new EventSource(`${API_BASE}/api/analysis/${id}/stream`);
    sseRef.current = sse;

    sse.addEventListener("progress", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        setPipelineStatus((prev) => ({ ...(prev ?? {}), status: data.status } as AnalysisStatus));
        setProgressPct(data.progress_pct ?? 0);
        setProgressMsg(data.message ?? "");
      } catch { /* ignore malformed events */ }
    });

    sse.addEventListener("done", (_e: MessageEvent) => {
      setPipelineStatus({ capture_id: id, status: "DONE", progress_pct: 100, error: null } as AnalysisStatus);
      setProgressPct(100);
      setProgressMsg("Analysis complete — all results ready.");
      sse.close();
    });


    sse.addEventListener("error", (_e) => {
      sse.close();
      // SSE failed — fall back to polling
      setUseSSE(false);
      startPolling(id);
    });

    // Global SSE error (connection refused)
    sse.onerror = () => {
      sse.close();
      setUseSSE(false);
      startPolling(id);
    };
  }, []);

  // ── Exponential-backoff polling fallback ────────────────────────────────────
  const startPolling = useCallback((id: string, delay = 1500) => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);

    const poll = async () => {
      try {
        const statusResp = await getAnalysisStatus(id);
        setPipelineStatus(statusResp);
        setProgressPct(statusResp.progress_pct ?? 0);
        if (statusResp.status === "DONE" || statusResp.status === "ERROR") return;
        // Exponential backoff: 1.5s → 3s → 6s, capped at 6s
        const nextDelay = Math.min(delay * 1.5, 6000);
        pollTimerRef.current = setTimeout(() => startPolling(id, nextDelay), nextDelay);
      } catch {
        // Network error — retry with backoff
        const nextDelay = Math.min(delay * 2, 8000);
        pollTimerRef.current = setTimeout(() => startPolling(id, nextDelay), nextDelay);
      }
    };
    pollTimerRef.current = setTimeout(poll, delay);
  }, []);

  // ── Start monitoring when captureId arrives ─────────────────────────────────
  useEffect(() => {
    if (!captureId) return;
    if (useSSE) {
      connectSSE(captureId);
    } else {
      startPolling(captureId);
    }
    return () => {
      sseRef.current?.close();
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    };
  }, [captureId, useSSE, connectSSE, startPolling]);

  // ── File handling ───────────────────────────────────────────────────────────
  const handleFile = (file: File) => {
    const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (ext !== ".pcap" && ext !== ".pcapng") {
      setErrorMsg("Please upload a valid .pcap or .pcapng file.");
      return;
    }
    setErrorMsg(null);
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setErrorMsg(null);
    setProgressPct(0);
    setProgressMsg("Uploading file...");

    try {
      const res = await uploadPcap(selectedFile, (progress) => {
        setUploadProgress(progress);
        setProgressPct(progress * 0.12); // Upload = first ~12% of total
      });
      setCaptureId(res.capture_id);
      setIsUploading(false);
      setProgressPct(12);
      setProgressMsg("Upload complete — starting analysis pipeline...");
    } catch (err: any) {
      setIsUploading(false);
      setErrorMsg(err.response?.data?.detail || "Upload failed. Please try again.");
    }
  };

  const currentStageIdx = pipelineStatus ? (STATUS_TO_STAGE[pipelineStatus.status] ?? -1) : -1;
  const isDone = pipelineStatus?.status === "DONE";
  const isError = pipelineStatus?.status === "ERROR";

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Capture Upload &amp; Analysis
        </h1>
        <p className="text-gray-400 text-sm">
          Upload PCAP/PCAPng packet captures of IPsec IKE handshakes and ESP tunnels for autonomous
          compliance evaluation and AI side-channel classification.
        </p>
      </div>

      {/* Upload Box */}
      {!captureId ? (
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center cursor-pointer transition-all ${
              isDragging
                ? "border-blue-500 bg-blue-500/10"
                : "border-white/20 hover:border-blue-400/60 bg-slate-950/40 hover:bg-slate-950/70"
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files.length > 0) {
                  handleFile(e.target.files[0]);
                }
              }}
            />
            <div className="flex flex-col items-center space-y-3">
              <div className="w-14 h-14 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400 shadow-inner">
                <UploadIcon size={24} />
              </div>
              <div>
                <p className="text-base font-semibold text-white">
                  {selectedFile ? selectedFile.name : "Click to browse or drop PCAP file here"}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  Supports standard tcpdump, Wireshark, and strongSwan .pcap / .pcapng files up to 100 MB
                </p>
              </div>
              {selectedFile && (
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-500/20 text-blue-300 text-xs font-mono">
                  <FileCheck size={14} />
                  {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                </div>
              )}
            </div>
          </div>

          {errorMsg && (
            <div className="flex items-center gap-2 p-3.5 bg-red-900/30 border border-red-500/50 rounded-lg text-red-300 text-xs">
              <AlertCircle size={16} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Upload progress bar (shown while uploading) */}
          {isUploading && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-gray-400">
                <span>Uploading…</span>
                <span className="font-mono">{uploadProgress}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div
                  className="h-2 rounded-full bg-blue-500 transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <button
              onClick={() => {
                setSelectedFile(null);
                if (fileInputRef.current) fileInputRef.current.value = "";
              }}
              disabled={!selectedFile || isUploading}
              className="px-4 py-2 text-xs font-medium text-gray-400 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
            >
              Clear Selection
            </button>
            <button
              onClick={handleUpload}
              disabled={!selectedFile || isUploading}
              className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer"
            >
              {isUploading ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  Uploading ({uploadProgress}%)
                </>
              ) : (
                <>
                  Start Autonomous Analysis
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
        </div>
      ) : (
        /* Live Pipeline Progress View */
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-blue-400">Capture Session</span>
              <h2 className="text-xl font-bold text-white font-mono">{captureId}</h2>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${
                  isDone
                    ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                    : isError
                    ? "bg-red-500/20 text-red-300 border border-red-500/40"
                    : "bg-blue-500/20 text-blue-300 border border-blue-500/40 animate-pulse"
                }`}
              >
                {pipelineStatus?.status || "PROCESSING"}
              </span>
              {!useSSE && (
                <span className="text-[10px] text-gray-500 font-mono">polling</span>
              )}
            </div>
          </div>

          {/* Animated progress bar */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs text-gray-400">
              <span className="font-medium">{progressMsg || "Processing…"}</span>
              <span className="font-mono">{Math.round(progressPct)}%</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
              <div
                className={`h-2.5 rounded-full transition-all duration-500 ${
                  isDone ? "bg-emerald-500" : isError ? "bg-red-500" : "bg-blue-500"
                }`}
                style={{ width: `${Math.max(progressPct, isDone ? 100 : 0)}%` }}
              />
            </div>
          </div>

          {/* Stage stepper */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            {PIPELINE_STAGES.map((stage, idx) => {
              const isPassed = currentStageIdx > idx || isDone;
              const isCurrent = currentStageIdx === idx && !isDone;
              const Icon = stage.Icon;

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border transition-all duration-300 ${
                    isPassed
                      ? "bg-emerald-950/20 border-emerald-500/40"
                      : isCurrent
                      ? "bg-blue-950/40 border-blue-500 shadow-lg shadow-blue-500/10"
                      : "bg-slate-950/40 border-white/5 opacity-50"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold text-gray-400">0{idx + 1}</span>
                    {isPassed ? (
                      <CheckCircle2 size={18} className="text-emerald-400" />
                    ) : isCurrent ? (
                      <RefreshCw size={18} className="text-blue-400 animate-spin" />
                    ) : (
                      <Icon size={18} className="text-gray-500" />
                    )}
                  </div>
                  <h3 className="text-sm font-bold text-white mb-1">{stage.label}</h3>
                  <p className="text-xs text-gray-400">{stage.desc}</p>
                </div>
              );
            })}
          </div>

          {/* Error display */}
          {isError && pipelineStatus?.error && (
            <div className="flex items-center gap-2 p-3.5 bg-red-900/30 border border-red-500/50 rounded-lg text-red-300 text-xs">
              <AlertCircle size={16} className="shrink-0" />
              <span>{pipelineStatus.error}</span>
            </div>
          )}

          {/* Navigation once done */}
          {isDone && (
            <div className="pt-4 border-t border-white/10 flex flex-wrap gap-3 justify-end">
              <button
                onClick={() => navigate(`/analysis/${captureId}`)}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-semibold border border-white/10 cursor-pointer transition-colors"
              >
                <Cpu size={16} />
                View AI Flow Classification
              </button>
              <button
                onClick={() => navigate(`/compliance/${captureId}`)}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold shadow-lg shadow-blue-600/30 cursor-pointer transition-colors"
              >
                <ShieldCheck size={16} />
                View Compliance Audit
                <ArrowRight size={16} />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Pre-recorded demo scenarios shortcut */}
      <div className="bg-slate-900/60 border border-white/5 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-gray-300">Or inspect pre-generated testbed datasets:</h3>
        <div className="flex flex-wrap gap-2">
          {[
            { id: "scenario_01", label: "Scenario 01 (AES-256-GCM + DH19)", tag: "Modern A" },
            { id: "scenario_04", label: "Scenario 04 (3DES + MD5 + DH2)", tag: "Vulnerable F" },
            { id: "scenario_07", label: "Scenario 07 (RFC 9347 IP-TFS)", tag: "Obfuscated" },
          ].map((s) => (
            <button
              key={s.id}
              onClick={() => navigate(`/compliance/${s.id}`)}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-white/10 text-xs text-gray-300 font-mono transition-colors cursor-pointer"
            >
              <span>{s.label}</span>
              <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 text-[10px]">
                {s.tag}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
