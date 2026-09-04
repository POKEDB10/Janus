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

export default function ReportPage() {
  const { captureId = "scenario_01" } = useParams<{ captureId: string }>();

  const [downloadingExec, setDownloadingExec] = useState(false);
  const [downloadingTech, setDownloadingTech] = useState(false);
  const [narrative, setNarrative] = useState<ReportNarrativeResponse | null>(null);
  const [draftingNarrative, setDraftingNarrative] = useState(false);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const handleCopy = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
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

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Executive & Technical Security Reports
        </h1>
        <p className="text-gray-400 text-sm">
          Generate publication-ready PDF audit deliverables tailored for CISOs, compliance auditors,
          and network security engineers.
        </p>
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
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 text-xs text-gray-200 leading-relaxed whitespace-pre-line">
                {narrative.executive_narrative}
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
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 text-xs text-gray-200 leading-relaxed whitespace-pre-line">
                {narrative.technical_narrative}
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
