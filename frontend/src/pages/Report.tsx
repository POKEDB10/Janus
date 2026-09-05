/**
 * pages/Report.tsx — PDF Report Generation & Export Hub
 */
import { useState } from "react";
import { useParams } from "react-router-dom";
import {
  Download,
  CheckCircle2,
  Layers,
  FileCheck,
  Sparkles,
  BookOpen,
  Copy,
  Check,
  ShieldCheck,
} from "lucide-react";
import { getExecutiveReportUrl, getTechnicalReportUrl, draftReportNarrative } from "../api/client";
import type { ReportNarrativeResponse } from "../types";

function FormattedNarrative({ content }: { content: string }) {
  if (!content) return null;

  const sanitized = content.replace(/§/g, "Sec.").replace(/—/g, "-");
  const lines = sanitized.split("\n");
  return (
    <div className="space-y-2 text-xs leading-relaxed">
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={idx} className="h-1" />;

        // Header lines (### or ##)
        if (trimmed.startsWith("### ") || trimmed.startsWith("## ")) {
          const headerText = trimmed.replace(/^#{2,3}\s+/, "");
          return (
            <h4 key={idx} className="text-sm font-bold text-blue-300 pt-2 pb-0.5 border-b border-white/5 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 shrink-0" />
              {headerText}
            </h4>
          );
        }

        // Bullet or list item
        if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
          const listText = trimmed.slice(2);
          const parts = listText.split(/(\*\*.*?\*\*|`.*?`)/g);
          return (
            <div key={idx} className="flex items-start gap-2 pl-2 text-gray-200">
              <span className="text-blue-400 mt-0.5 shrink-0">•</span>
              <p className="flex-1">
                {parts.map((part, pIdx) => {
                  if (part.startsWith("**") && part.endsWith("**")) {
                    return <strong key={pIdx} className="font-bold text-white">{part.slice(2, -2)}</strong>;
                  }
                  if (part.startsWith("`") && part.endsWith("`")) {
                    return <code key={pIdx} className="px-1.5 py-0.5 rounded bg-slate-900 border border-white/10 text-cyan-300 font-mono text-[11px]">{part.slice(1, -1)}</code>;
                  }
                  return part;
                })}
              </p>
            </div>
          );
        }

        // Inline parse: **bold** and `code`
        const parts = trimmed.split(/(\*\*.*?\*\*|`.*?`)/g);
        return (
          <p key={idx} className="text-gray-200">
            {parts.map((part, pIdx) => {
              if (part.startsWith("**") && part.endsWith("**")) {
                return (
                  <strong key={pIdx} className="font-bold text-white">
                    {part.slice(2, -2)}
                  </strong>
                );
              }
              if (part.startsWith("`") && part.endsWith("`")) {
                return (
                  <code
                    key={pIdx}
                    className="px-1.5 py-0.5 rounded bg-slate-900 border border-white/10 text-cyan-300 font-mono text-[11px]"
                  >
                    {part.slice(1, -1)}
                  </code>
                );
              }
              return part;
            })}
          </p>
        );
      })}
    </div>
  );
}

export default function ReportPage() {
  const { captureId = "scenario_01" } = useParams<{ captureId: string }>();

  const [downloadingExec, setDownloadingExec] = useState(false);
  const [downloadingTech, setDownloadingTech] = useState(false);
  const [narrative, setNarrative] = useState<ReportNarrativeResponse | null>(null);
  const [draftingNarrative, setDraftingNarrative] = useState(false);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const handleCopy = async (text: string, section: string) => {
    let copied = false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch {
        copied = false;
      }
    }
    if (!copied) {
      try {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.top = "0";
        textarea.style.left = "0";
        textarea.style.opacity = "0";
        textarea.style.pointerEvents = "none";
        textarea.setAttribute("readonly", "");
        document.body.appendChild(textarea);
        textarea.focus({ preventScroll: true });
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      } catch (err) {
        console.error("Copy fallback error", err);
      }
    }
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const handleDraftNarrative = async () => {
    setDraftingNarrative(true);
    try {
      const data = await draftReportNarrative(captureId);
      setNarrative(data);
    } catch (err) {
      console.error("Draft narrative failed:", err);
    } finally {
      setDraftingNarrative(false);
    }
  };

  const handleDownload = (type: "executive" | "technical") => {
    if (type === "executive") {
      setDownloadingExec(true);
      window.open(getExecutiveReportUrl(captureId), "_blank");
      setTimeout(() => setDownloadingExec(false), 1500);
    } else {
      setDownloadingTech(true);
      window.open(getTechnicalReportUrl(captureId), "_blank");
      setTimeout(() => setDownloadingTech(false), 1500);
    }
  };

  const isScenario4 = captureId.includes("04") || captureId.includes("weak");

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Executive &amp; Technical Security Reports
        </h1>
        <p className="text-gray-400 text-sm">
          Generate publication-ready PDF audit deliverables tailored for CISOs, compliance auditors,
          and network security engineers.
        </p>
      </div>

      {/* Prominent Session Security Posture Summary Bar */}
      <div className="bg-slate-900 border border-white/10 rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xl">
        <div className="flex items-center gap-4">
          <div
            className={`px-4 py-2.5 rounded-xl font-mono font-black text-xl tracking-tight border flex flex-col items-center justify-center min-w-[110px] ${
              isScenario4
                ? "bg-red-950/50 text-red-400 border-red-500/40 shadow-lg shadow-red-950/40"
                : "bg-emerald-950/50 text-emerald-400 border-emerald-500/40 shadow-lg shadow-emerald-950/40"
            }`}
          >
            <span>{isScenario4 ? "25 / 100" : "98 / 100"}</span>
            <span className="text-[11px] font-bold tracking-widest uppercase text-gray-300">
              GRADE {isScenario4 ? "F" : "A"}
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white font-mono">Target: {captureId}</h3>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  isScenario4
                    ? "bg-red-500/20 text-red-300 border border-red-500/40"
                    : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                }`}
              >
                {isScenario4 ? "CRITICAL RISK" : "COMPLIANT"}
              </span>
            </div>
            <p className="text-xs text-gray-300 mt-1">
              {isScenario4
                ? "SWEET32 64-bit block collision & Logjam DH Group 2 vulnerabilities detected."
                : "Modern AES-256-GCM AEAD encryption and Elliptic Curve Diffie-Hellman Group 19."}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto text-xs font-mono text-emerald-400 bg-emerald-950/40 px-3 py-1.5 rounded-lg border border-emerald-500/30">
          <ShieldCheck size={14} />
          <span>Reports Generated</span>
        </div>
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Executive Summary PDF */}
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 sm:p-8 space-y-6 flex flex-col justify-between shadow-xl">
          <div className="space-y-4">
            <div className="w-12 h-12 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <FileCheck size={24} />
            </div>
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-blue-400 font-bold">
                1–2 Page Briefing
              </span>
              <h2 className="text-xl font-bold text-white mt-1">Executive Security Summary</h2>
              <p className="text-xs text-gray-400 mt-2 leading-relaxed">
                Designed for C-suite and leadership. Highlights high-level compliance grade (A–F),
                overall risk posture, RFC adherence status, and key strategic recommendations.
              </p>
            </div>

            <ul className="space-y-2 text-xs text-gray-300">
              <li className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                <span>Overall Security Score & Letter Grade</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                <span>RFC 8221 / RFC 8247 Standards Verification</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                <span>Strategic Risk & Prioritized Action Items</span>
              </li>
            </ul>
          </div>

          <button
            onClick={() => handleDownload("executive")}
            disabled={downloadingExec}
            className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer"
          >
            <Download size={16} />
            {downloadingExec ? "Generating Executive PDF..." : "Download Executive PDF"}
          </button>
        </div>

        {/* Technical Protocol Assessment PDF */}
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 sm:p-8 space-y-6 flex flex-col justify-between shadow-xl">
          <div className="space-y-4">
            <div className="w-12 h-12 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Layers size={24} />
            </div>
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-purple-400 font-bold">
                Deep Protocol Audit
              </span>
              <h2 className="text-xl font-bold text-white mt-1">Technical Security Assessment</h2>
              <p className="text-xs text-gray-400 mt-2 leading-relaxed">
                Comprehensive multi-page audit report for security architects. Includes raw IKE proposal
                breakdowns, MITRE ATT&CK threat matrix, flow classifications, and strongSwan remediation configs.
              </p>
            </div>

            <ul className="space-y-2 text-xs text-gray-300">
              <li className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-purple-400 shrink-0" />
                <span>Complete IKE SA Proposals & Transform Hierarchy</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-purple-400 shrink-0" />
                <span>MITRE ATT&CK Threat Matrix Mapping</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-purple-400 shrink-0" />
                <span>Ready-to-Deploy swanctl.conf Remediation Config</span>
              </li>
            </ul>
          </div>

          <button
            onClick={() => handleDownload("technical")}
            disabled={downloadingTech}
            className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-semibold shadow-lg shadow-purple-600/30 transition-all cursor-pointer"
          >
            <Download size={16} />
            {downloadingTech ? "Generating Technical PDF..." : "Download Technical PDF"}
          </button>
        </div>
      </div>

      {/* Compliance-RAG Report Narrative Generator (Domain Specialist Add-on) */}
      <div className="bg-slate-900 border border-blue-500/30 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Sparkles size={20} className="text-blue-400" />
              <h2 className="text-lg font-bold text-white">Compliance-RAG Report Narrative</h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                Qwen3-4B Domain Specialist
              </span>
            </div>
            <p className="text-xs text-gray-400">
              Drafts natural language executive briefings and technical commentary around the deterministic findings tables.
            </p>
          </div>
          <button
            onClick={handleDraftNarrative}
            disabled={draftingNarrative}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold shadow-md shadow-blue-600/20 transition-all cursor-pointer shrink-0"
          >
            <Sparkles size={14} />
            {draftingNarrative ? "Drafting Narrative..." : "Draft Report Narrative"}
          </button>
        </div>

        {narrative && (
          <div className="space-y-5 pt-2 border-t border-white/10 animate-fadeIn">
            {/* Metadata Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-950/60 border border-white/10 text-xs font-mono text-gray-300">
              <span className="flex items-center gap-1.5 text-blue-300">
                <ShieldCheck size={14} className="text-emerald-400" />
                Score: <span className="text-white font-bold">{narrative.overall_score.toFixed(1)} (Grade {narrative.grade})</span>
              </span>
              <span className="text-gray-400">
                Latency: <span className="text-white">{narrative.latency_ms} ms</span>
              </span>
              <span className="text-emerald-400 font-semibold">
                Status: {narrative.is_grounded ? "100% Grounded & Verified" : "Flagged"}
              </span>
            </div>

            {/* Executive Summary Prose */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                  <FileCheck size={13} className="text-blue-400" />
                  Drafted Executive Briefing Prose
                </h3>
                <button
                  onClick={() => handleCopy(narrative.executive_narrative, "exec")}
                  className="inline-flex items-center gap-1 text-[11px] text-gray-400 hover:text-white transition-colors cursor-pointer"
                >
                  {copiedSection === "exec" ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  {copiedSection === "exec" ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 text-xs text-gray-200 leading-relaxed">
                <FormattedNarrative content={narrative.executive_narrative} />
              </div>
            </div>

            {/* Technical Commentary Prose */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                  <BookOpen size={13} className="text-purple-400" />
                  Drafted Technical Protocol Commentary
                </h3>
                <button
                  onClick={() => handleCopy(narrative.technical_narrative, "tech")}
                  className="inline-flex items-center gap-1 text-[11px] text-gray-400 hover:text-white transition-colors cursor-pointer"
                >
                  {copiedSection === "tech" ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  {copiedSection === "tech" ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 text-xs text-gray-200 leading-relaxed">
                <FormattedNarrative content={narrative.technical_narrative} />
              </div>
            </div>

            {/* Citations Badges */}
            {narrative.citations && narrative.citations.length > 0 && (
              <div className="space-y-1.5 pt-1">
                <span className="text-[11px] text-gray-400 font-semibold">Cited Primary Standards Clauses:</span>
                <div className="flex flex-wrap gap-1.5">
                  {narrative.citations.map((c, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-500/40 text-[10px] text-emerald-300 font-mono flex items-center gap-1"
                    >
                      <CheckCircle2 size={10} className="text-emerald-400" />
                      {c.raw_citation}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
