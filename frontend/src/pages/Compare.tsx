/**
 * pages/Compare.tsx — Side-by-side scenario comparison
 * Shows two compliance scenarios in split panels with diff table highlighting.
 */
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { GitCompare, ArrowRight, Shield, AlertTriangle, CheckCircle2 } from "lucide-react";
import { getComplianceReport } from "../api/client";
import type { ComplianceReport } from "../types";
import ScoreGauge from "../components/ScoreGauge";
import RiskBadge from "../components/RiskBadge";
import type { RiskLevel } from "../types";

const AVAILABLE_SCENARIOS = [
  { id: "scenario_01", label: "Scenario 01 — Modern AES-256-GCM + DH19", grade: "A" },
  { id: "scenario_04", label: "Scenario 04 — Legacy 3DES + MD5 + DH2",   grade: "F" },
  { id: "scenario_07", label: "Scenario 07 — RFC 9347 IP-TFS Obfuscated", grade: "A" },
];

// ─── Skeleton loader for loading state ───────────────────────────────────────

function PanelSkeleton() {
  return (
    <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-4 animate-pulse">
      <div className="h-4 bg-slate-700 rounded w-3/4" />
      <div className="flex justify-center py-6">
        <div className="w-40 h-40 rounded-full bg-slate-800" />
      </div>
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-10 bg-slate-800 rounded-xl" />
      ))}
    </div>
  );
}

// ─── Score color helper ───────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

// ─── Param diff row ───────────────────────────────────────────────────────────

interface DiffRowProps {
  label: string;
  left: string | number | boolean;
  right: string | number | boolean;
}

function DiffRow({ label, left, right }: DiffRowProps) {
  const different = String(left) !== String(right);
  return (
    <tr className={`text-xs border-b border-white/5 ${different ? "bg-red-950/10" : ""}`}>
      <td className="py-2.5 px-3 text-gray-400 font-mono">{label}</td>
      <td className={`py-2.5 px-3 font-mono font-semibold ${different ? "text-red-300" : "text-white"}`}>
        {String(left)}
      </td>
      <td className={`py-2.5 px-3 font-mono font-semibold ${different ? "text-red-300" : "text-white"}`}>
        {String(right)}
      </td>
      <td className="py-2.5 px-3">
        {different ? (
          <span className="flex items-center gap-1 text-amber-400 text-[10px] font-semibold">
            <AlertTriangle size={11} />
            DIFFER
          </span>
        ) : (
          <span className="flex items-center gap-1 text-emerald-500 text-[10px] font-semibold">
            <CheckCircle2 size={11} />
            SAME
          </span>
        )}
      </td>
    </tr>
  );
}

// ─── Single scenario panel ────────────────────────────────────────────────────

function ScenarioPanel({
  report,
  label,
}: {
  report: ComplianceReport;
  label: string;
}) {
  const navigate = useNavigate();

  return (
    <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-5 shadow-xl flex flex-col">
      {/* Score gauge + summary */}
      <div className="text-center space-y-2">
        <h2 className="text-sm font-bold text-white">{label}</h2>
        <ScoreGauge score={report.overall_score} grade={report.grade} size={160} />
        <p
          className={`text-sm font-bold font-mono ${scoreColor(report.overall_score)}`}
        >
          {report.overall_score}/100 — Grade {report.grade}
        </p>
        <p className="text-xs text-gray-400 px-2">{report.summary}</p>
      </div>

      {/* Parameters */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        {[
          { label: "ESP Cipher", value: report.evaluated_parameters?.esp_encryption || "—" },
          { label: "Auth",       value: report.evaluated_parameters?.esp_auth || "—" },
          { label: "DH Group",   value: `Group ${report.evaluated_parameters?.dh_group || "—"}` },
          { label: "PFS",        value: report.evaluated_parameters?.pfs_enabled ? "Enabled" : "Disabled" },
        ].map((p) => (
          <div
            key={p.label}
            className="bg-slate-950/60 p-2.5 rounded-lg border border-white/5 space-y-0.5"
          >
            <span className="text-gray-500 font-mono block">{p.label}</span>
            <span className="text-white font-semibold font-mono block">{p.value}</span>
          </div>
        ))}
      </div>

      {/* Findings */}
      <div className="flex-1 space-y-2">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          {report.findings.length > 0 ? `${report.findings.length} Finding(s)` : "No Findings"}
        </h3>
        {report.findings.length === 0 ? (
          <div className="flex items-center gap-2 text-emerald-400 text-xs">
            <CheckCircle2 size={14} />
            All RFC parameters compliant.
          </div>
        ) : (
          <div className="space-y-1.5">
            {report.findings.map((f, i) => (
              <div
                key={i}
                className="flex items-center justify-between p-2 bg-slate-950/60 rounded-lg border border-white/5"
              >
                <span className="text-gray-300 font-mono text-[11px]">{f.rule_id}</span>
                <RiskBadge
                  level={(f.severity || f.risk_level || "MEDIUM") as RiskLevel}
                  size="sm"
                />
              </div>
            ))}
          </div>
        )}
      </div>

      <button
        onClick={() => navigate(`/compliance/${report.capture_id}`)}
        className="inline-flex items-center justify-center gap-1.5 w-full py-2 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 text-xs font-semibold cursor-pointer transition-colors"
      >
        Full Audit <ArrowRight size={13} />
      </button>
    </div>
  );
}

// ─── Main Compare page ────────────────────────────────────────────────────────

export default function Compare() {
  const [leftId, setLeftId] = useState("scenario_01");
  const [rightId, setRightId] = useState("scenario_04");
  const [leftReport, setLeftReport] = useState<ComplianceReport | null>(null);
  const [rightReport, setRightReport] = useState<ComplianceReport | null>(null);
  const [loadingLeft, setLoadingLeft] = useState(false);
  const [loadingRight, setLoadingRight] = useState(false);

  async function loadReport(
    id: string,
    setReport: React.Dispatch<React.SetStateAction<ComplianceReport | null>>,
    setLoading: React.Dispatch<React.SetStateAction<boolean>>,
  ) {
    setLoading(true);
    setReport(null);
    try {
      const data = await getComplianceReport(id);
      setReport(data);
    } catch {
      // Fallback for demo
      const isScenario4 = id.includes("04") || id.includes("weak");
      const fallback: ComplianceReport = {
        capture_id: id,
        overall_score: isScenario4 ? 25.0 : 96.0,
        grade: isScenario4 ? "F" : "A",
        summary: isScenario4
          ? "CRITICAL: Deprecated 3DES cipher and weak DH Group 2."
          : "COMPLIANT: AES-GCM AEAD + DH Group 19.",
        evaluated_parameters: {
          esp_encryption: isScenario4 ? "ENCR_3DES" : "ENCR_AES_GCM_16",
          esp_auth: isScenario4 ? "AUTH_HMAC_MD5_96" : "AUTH_NONE",
          dh_group: isScenario4 ? 2 : 19,
          pfs_enabled: !isScenario4,
          sa_lifetime_seconds: isScenario4 ? 86400 : 3600,
        },
        findings: isScenario4
          ? [
              { rule_id: "RFC8221-ENCR_3DES", parameter: "ESP Encryption", severity: "HIGH",
                description: "SWEET32 vulnerability.", recommendation: "Use AES-GCM-16.",
                references: ["RFC 8221 §5", "CVE-2016-2183"] },
              { rule_id: "RFC8247-DH_GROUP_2", parameter: "DH Group", severity: "CRITICAL",
                description: "Logjam attack surface.", recommendation: "Use DH Group 19.",
                references: ["RFC 8247 §2.4"] },
            ]
          : [],
        remediation_config: "",
        threat_matrix: [],
        generated_at: new Date().toISOString(),
      };
      setReport(fallback);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadReport(leftId, setLeftReport, setLoadingLeft); }, [leftId]);
  useEffect(() => { loadReport(rightId, setRightReport, setLoadingRight); }, [rightId]);

  const leftLabel = AVAILABLE_SCENARIOS.find((s) => s.id === leftId)?.label || leftId;
  const rightLabel = AVAILABLE_SCENARIOS.find((s) => s.id === rightId)?.label || rightId;

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Side-by-Side Scenario Comparison
            </h1>
            <GitCompare className="text-purple-400" size={24} />
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Select two compliance profiles to compare their cryptographic parameters, scores, and findings.
          </p>
        </div>
      </div>

      {/* Scenario Selectors */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4 space-y-2">
          <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
            <Shield size={14} className="text-blue-400" />
            Left Panel — Scenario A
          </label>
          <select
            value={leftId}
            onChange={(e) => setLeftId(e.target.value)}
            className="w-full bg-slate-950 border border-white/10 rounded-lg p-2 text-white text-sm font-mono focus:border-blue-500 focus:outline-none cursor-pointer"
          >
            {AVAILABLE_SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>{s.label}</option>
            ))}
          </select>
        </div>

        <div className="bg-slate-900 border border-white/10 rounded-xl p-4 space-y-2">
          <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
            <Shield size={14} className="text-purple-400" />
            Right Panel — Scenario B
          </label>
          <select
            value={rightId}
            onChange={(e) => setRightId(e.target.value)}
            className="w-full bg-slate-950 border border-white/10 rounded-lg p-2 text-white text-sm font-mono focus:border-blue-500 focus:outline-none cursor-pointer"
          >
            {AVAILABLE_SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>{s.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Split Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {loadingLeft ? <PanelSkeleton /> : leftReport ? (
          <ScenarioPanel report={leftReport} label={leftLabel} />
        ) : null}
        {loadingRight ? <PanelSkeleton /> : rightReport ? (
          <ScenarioPanel report={rightReport} label={rightLabel} />
        ) : null}
      </div>

      {/* Parameter Diff Table */}
      {leftReport && rightReport && (
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-4 shadow-xl">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <GitCompare size={16} className="text-purple-400" />
            Parameter Diff Table
            <span className="text-xs font-normal text-gray-400 ml-1">
              — rows highlighted in red differ between the two profiles
            </span>
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/10 text-gray-400 font-mono">
                  <th className="py-2.5 px-3 text-left">Parameter</th>
                  <th className="py-2.5 px-3 text-left">Scenario A</th>
                  <th className="py-2.5 px-3 text-left">Scenario B</th>
                  <th className="py-2.5 px-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody>
                <DiffRow
                  label="Overall Score"
                  left={`${leftReport.overall_score}/100 (${leftReport.grade})`}
                  right={`${rightReport.overall_score}/100 (${rightReport.grade})`}
                />
                <DiffRow
                  label="ESP Cipher"
                  left={leftReport.evaluated_parameters?.esp_encryption || "—"}
                  right={rightReport.evaluated_parameters?.esp_encryption || "—"}
                />
                <DiffRow
                  label="ESP Auth"
                  left={leftReport.evaluated_parameters?.esp_auth || "—"}
                  right={rightReport.evaluated_parameters?.esp_auth || "—"}
                />
                <DiffRow
                  label="DH Group"
                  left={`Group ${leftReport.evaluated_parameters?.dh_group || "—"}`}
                  right={`Group ${rightReport.evaluated_parameters?.dh_group || "—"}`}
                />
                <DiffRow
                  label="PFS"
                  left={leftReport.evaluated_parameters?.pfs_enabled ? "Enabled" : "Disabled"}
                  right={rightReport.evaluated_parameters?.pfs_enabled ? "Enabled" : "Disabled"}
                />
                <DiffRow
                  label="SA Lifetime"
                  left={`${(leftReport.evaluated_parameters?.sa_lifetime_seconds || 0) / 3600}h`}
                  right={`${(rightReport.evaluated_parameters?.sa_lifetime_seconds || 0) / 3600}h`}
                />
                <DiffRow
                  label="# Findings"
                  left={leftReport.findings.length}
                  right={rightReport.findings.length}
                />
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
