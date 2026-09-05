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
  Terminal,
  Download,
  ExternalLink,
  Sparkles,
} from "lucide-react";
import { uploadPcap, getAnalysisStatus, getSamplePcaps } from "../api/client";
import type { AnalysisStatus, SamplePcap } from "../types";

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
  const logsEndRef = useRef<HTMLDivElement>(null);

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
  const [logs, setLogs] = useState<string[]>([]);
  const [sampleList, setSampleList] = useState<SamplePcap[]>([]);

  useEffect(() => {
    getSamplePcaps()
      .then((data) => setSampleList(data))
      .catch(() => {
        setSampleList([
          {
            id: "wireshark_ikev2_aes_gcm",
            filename: "wireshark_ikev2_aes_gcm.pcap",
            title: "Wireshark IPsec Ex 3 — Site-to-Site IKEv2 AES-GCM",
            category: "Compliant Production VPN",
            rfc_status: "RFC 8221 / 8247 Compliant (Grade A, 96/100)",
            cipher: "AES-256-GCM / SHA-384 / DH Group 19 (NIST P-256)",
            description: "Standard Wireshark public capture of strongSwan site-to-site IPsec tunnel with modern AEAD AES-GCM and Perfect Forward Secrecy.",
            download_url: "/api/samples/wireshark_ikev2_aes_gcm/download",
            external_url: "https://wiki.wireshark.org/SampleCaptures#example-3-site-to-site-ikev2-vpn-with-aes-256-gcm",
            size_bytes: 3356,
          },
          {
            id: "wireshark_ikev2_multi_suite",
            filename: "wireshark_ikev2_multi_suite.pcapng",
            title: "Wireshark IPsec Ex 2 — Multi-Suite IKEv2 (GCM, CTR, CBC)",
            category: "Multi-Cipher Benchmark",
            rfc_status: "RFC 8221 Comparative (Grade A & B)",
            cipher: "AES-GCM-16, AES-CTR, AES-CBC / Port 4500 NAT-T",
            description: "Official Wireshark capture of 3 consecutive IKEv2 tunnels demonstrating AES-GCM (modern), AES-CTR, and AES-CBC over UDP 4500.",
            download_url: "/api/samples/wireshark_ikev2_multi_suite/download",
            external_url: "https://wiki.wireshark.org/SampleCaptures#example-2-dissection-of-encrypted-and-udp-encapsulated-ikev2-and-esp-messages",
            size_bytes: 18476,
          },
          {
            id: "wireshark_esp_tunnel_mode",
            filename: "wireshark_esp_tunnel_mode.pcap",
            title: "Wireshark IPsec Ex 1 — Heavy ESP Tunnel Traffic",
            category: "High-Volume ESP Flow",
            rfc_status: "Standard ESP Tunnel Mode",
            cipher: "ESP Tunnel Mode / High Packet Density",
            description: "Official Wireshark Example 1 capture of sustained IPsec tunnel mode traffic with rich statistical packet length & IAT variance.",
            download_url: "/api/samples/wireshark_esp_tunnel_mode/download",
            external_url: "https://wiki.wireshark.org/SampleCaptures#example-1-esp-payload-decryption-and-authentication-checking-examples",
            size_bytes: 157639,
          },
          {
            id: "scenario_04_weak_3des",
            filename: "scenario_04_weak_3des.pcap",
            title: "Legacy Enterprise IPsec — Broken 3DES + MD5 + No PFS",
            category: "Vulnerable / Deprecated Suite",
            rfc_status: "RFC 8221 Critical Failure (Grade F, 25/100)",
            cipher: "3DES-CBC / MD5-HMAC / DH Group 2 (1024-bit MODP)",
            description: "Legacy Sweet32-vulnerable capture demonstrating CVE-2016-2183 64-bit block collision risks and Logjam-vulnerable DH group 2.",
            download_url: "/api/samples/scenario_04_weak_3des/download",
            external_url: "https://wiki.wireshark.org/SampleCaptures#ipsec",
            size_bytes: 41624,
          },
          {
            id: "scenario_01_hardened",
            filename: "scenario_01_hardened.pcap",
            title: "RFC 9347 IP-TFS Hardened Tunnel — Zero Metadata Leakage",
            category: "CNSA 2.0 / Post-Quantum Ready",
            rfc_status: "RFC 9347 & CNSA 2.0 Hardened (Grade A, 100/100)",
            cipher: "ChaCha20-Poly1305 / SHA-512 / DH Group 31 (Curve25519)",
            description: "Aggressive traffic-flow confidentiality with constant packet sizing and dummy burst injection defeating ML side-channel classifiers.",
            download_url: "/api/samples/scenario_01_hardened/download",
            external_url: "https://wiki.wireshark.org/SampleCaptures#ipsec",
            size_bytes: 41624,
          },
          {
            id: "wireshark_http_sample",
            filename: "wireshark_http_sample.pcap",
            title: "Wireshark Generic Traffic — HTTP Web Trace (Non-IPsec)",
            category: "External Standard Traffic",
            rfc_status: "Non-Encrypted Ingestion Test",
            cipher: "Cleartext HTTP / TCP Port 80",
            description: "Standard Wireshark public capture demonstrating how Janus handles arbitrary external PCAP files without crashing.",
            download_url: "/api/samples/wireshark_http_sample/download",
            external_url: "https://wiki.wireshark.org/SampleCaptures#hypertext-transfer-protocol-http",
            size_bytes: 25803,
          },
        ]);
      });
  }, []);

  useEffect(() => {
    if (logs.length > 0) {
      logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

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
        setPipelineStatus((prev) => ({ ...(prev ?? {}), status: data.status, logs: data.logs } as AnalysisStatus));
        setProgressPct(data.progress_pct ?? 0);
        setProgressMsg(data.message ?? "");
        if (data.logs && Array.isArray(data.logs)) {
          setLogs(data.logs);
        }
      } catch { /* ignore malformed events */ }
    });

    sse.addEventListener("done", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (data.logs && Array.isArray(data.logs)) {
          setLogs(data.logs);
        }
      } catch { /* ignore */ }
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
  const startPolling = useCallback((id: string, delay = 1000) => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);

    const poll = async () => {
      try {
        const statusResp = await getAnalysisStatus(id);
        setPipelineStatus(statusResp);
        setProgressPct(statusResp.progress_pct ?? 0);
        setProgressMsg(statusResp.message ?? "");
        if (statusResp.logs && Array.isArray(statusResp.logs)) {
          setLogs(statusResp.logs);
        }
        if (statusResp.status === "DONE" || statusResp.status === "ERROR") return;
        // Exponential backoff: 1s → 2s → 4s, capped at 4s
        const nextDelay = Math.min(delay * 1.5, 4000);
        pollTimerRef.current = setTimeout(() => startPolling(id, nextDelay), nextDelay);
      } catch {
        // Network error — retry with backoff
        const nextDelay = Math.min(delay * 2, 6000);
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

          {/* Live Pipeline Execution Terminal */}
          <div className="rounded-xl border border-slate-700/60 bg-[#070b14] overflow-hidden shadow-2xl">
            <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-white/5 text-xs">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                </div>
                <div className="flex items-center gap-1.5 font-mono text-gray-400 ml-2 font-medium">
                  <Terminal size={13} className="text-cyan-400" />
                  <span>janus-pipeline-worker // live execution stream</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`inline-block w-2 h-2 rounded-full ${isDone ? "bg-emerald-400" : isError ? "bg-red-400" : "bg-cyan-400 animate-ping"}`} />
                <span className="text-[11px] font-mono text-cyan-300 font-semibold">
                  {isDone ? "EXECUTION COMPLETE" : isError ? "EXECUTION HALTED" : "REALTIME DISSECTION"}
                </span>
              </div>
            </div>
            <div className="p-4 font-mono text-xs max-h-56 overflow-y-auto space-y-1.5 scrollbar-thin">
              {logs.length === 0 ? (
                <div className="text-gray-500 flex items-center gap-2">
                  <RefreshCw size={12} className="animate-spin text-blue-400" />
                  <span>Initializing dpkt packet stream and spawning worker thread...</span>
                </div>
              ) : (
                logs.map((logLine, idx) => {
                  const isSuccess = logLine.includes("OK") || logLine.includes("Complete") || logLine.includes("Saved");
                  const isHighlight = logLine.includes("RFC") || logLine.includes("Stage") || logLine.includes("SPI") || logLine.includes("FlowDeepNet");
                  return (
                    <div key={idx} className="leading-relaxed flex items-start gap-2">
                      <span className="text-gray-600 select-none font-bold">&gt;</span>
                      <span
                        className={
                          isSuccess
                            ? "text-emerald-400 font-medium"
                            : isHighlight
                            ? "text-cyan-300"
                            : "text-gray-300"
                        }
                      >
                        {logLine}
                      </span>
                    </div>
                  );
                })
              )}
              <div ref={logsEndRef} />
            </div>
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

      {/* Sample PCAP Download Section */}
      <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 sm:p-7 space-y-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="text-cyan-400" size={20} />
              <h2 className="text-base sm:text-lg font-bold text-white tracking-tight">
                Live Verification: Download &amp; Test Real PCAPs
              </h2>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Test the live autonomous pipeline with real Wireshark captures or testbed PCAPs, or download any sample from the internet to verify genuine execution.
            </p>
          </div>
          <a
            href="https://wiki.wireshark.org/SampleCaptures#ipsec"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/15 hover:bg-blue-600/25 text-blue-300 border border-blue-500/30 text-xs font-semibold shrink-0 transition-colors"
          >
            <span>Wireshark Sample Wiki</span>
            <ExternalLink size={13} />
          </a>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {sampleList.map((sample) => (
            <div
              key={sample.id}
              className="bg-slate-950/70 border border-white/5 hover:border-blue-500/30 rounded-xl p-4 flex flex-col justify-between space-y-3 transition-all group"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/25">
                    {sample.category}
                  </span>
                  <span className="text-[11px] font-mono text-gray-500">
                    {(sample.size_bytes / 1024).toFixed(1)} KB
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white group-hover:text-blue-300 transition-colors">
                  {sample.title}
                </h3>
                <p className="text-xs text-gray-400 leading-relaxed">
                  {sample.description}
                </p>
                <div className="flex flex-wrap gap-1.5 pt-1 text-[11px] font-mono">
                  <span className="text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/20">
                    {sample.cipher}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t border-white/5">
                <a
                  href={`${API_BASE}${sample.download_url}`}
                  download={sample.filename}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium border border-white/10 transition-colors cursor-pointer"
                >
                  <Download size={13} />
                  <span>Download .pcap</span>
                </a>
                <a
                  href={sample.external_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs text-gray-400 hover:text-white transition-colors"
                >
                  <span>Source info</span>
                  <ExternalLink size={12} />
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>

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
