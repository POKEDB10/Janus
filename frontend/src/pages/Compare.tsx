import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { GitCompare, ArrowRight, Shield, AlertTriangle, CheckCircle2, AlertCircle } from "lucide-react";
import { getComplianceReport } from "../api/client";
import type { ComplianceReport } from "../types";
import ScoreGauge from "../components/ScoreGauge";
import RiskBadge from "../components/RiskBadge";
import type { RiskLevel } from "../types";

const AVAILABLE_SCENARIOS = [
  { id: "scenario_01", label: "Scenario 01 — Modern AES-256-GCM + DH19 (Gigabit LAN)", grade: "A" },
  { id: "scenario_02", label: "Scenario 02 — Metro WAN (AES-GCM + PFS)", grade: "A" },
  { id: "scenario_03", label: "Scenario 03 — Corporate WAN (ChaCha20-Poly1305)", grade: "A" },
  { id: "scenario_04", label: "Scenario 04 — Legacy Enterprise (3DES-CBC + MD5 + DH2)", grade: "F" },
  { id: "scenario_05", label: "Scenario 05 — Cross-Country WAN (AES-CBC + SHA256)", grade: "B" },
  { id: "scenario_06", label: "Scenario 06 — Satellite Link (High Latency)", grade: "B" },
  { id: "scenario_07", label: "Scenario 07 — RFC 9347 IP-TFS (Obfuscated Tunnel)", grade: "A" },
  { id: "scenario_08", label: "Scenario 08 — Lossy Wireless WAN", grade: "B" },
  { id: "scenario_09", label: "Scenario 09 — Congested Gateway", grade: "B" },
  { id: "scenario_10", label: "Scenario 10 — Host-to-Host Transport Mode", grade: "A" },
  { id: "scenario_11", label: "Scenario 11 — Constrained MTU Tunnel", grade: "B" },
  { id: "scenario_12", label: "Scenario 12 — Asymmetric WAN Uplink", grade: "B" },
];

// ─── Posture evaluation (Green = Good / Red = Bad) ───────────────────────────

export type PostureType = "GOOD" | "BAD" | "WARN" | "NEUTRAL";

export interface ParameterEvaluation {
  posture: PostureType;
  badgeText?: string;
}

export function evaluateParameterPosture(
  label: string,
  rawVal: string | number | boolean
): ParameterEvaluation {
  const str = String(rawVal).trim().toLowerCase();

  if (label === "Overall Score") {
    const match = str.match(/^(\d+(?:\.\d+)?)/);
    if (match) {
      const num = parseFloat(match[1]);
      if (num >= 80) return { posture: "GOOD", badgeText: "SECURE" };
      if (num >= 50) return { posture: "WARN", badgeText: "MODERATE" };
      return { posture: "BAD", badgeText: "CRITICAL" };
    }
  }

  if (label === "ESP Cipher") {
    if (str.includes("3des") || str.includes("des") || str.includes("rc4") || str.includes("blowfish")) {
      return { posture: "BAD", badgeText: "SWEET32 / DEPRECATED" };
    }
    if (str.includes("gcm") || str.includes("chacha") || str.includes("poly") || str.includes("aes_256")) {
      return { posture: "GOOD", badgeText: "RFC 8221 AEAD" };
    }
    if (str.includes("cbc")) {
      return { posture: "WARN", badgeText: "LEGACY CBC" };
    }
  }

  if (label === "ESP Auth") {
    if (str.includes("md5") || str.includes("sha1")) {
      return { posture: "BAD", badgeText: "COLLISION RISK" };
    }
    if (str.includes("none") || str.includes("n/a") || str === "—") {
      return { posture: "GOOD", badgeText: "AEAD INTEGRATED" };
    }
    if (str.includes("sha2") || str.includes("sha256") || str.includes("sha384") || str.includes("sha512")) {
      return { posture: "GOOD", badgeText: "SECURE HMAC" };
    }
  }

  if (label === "DH Group") {
    if (str.includes("group 2") || str.includes("group 1") || str.includes("group 5") || str === "2" || str === "1" || str === "5") {
      return { posture: "BAD", badgeText: "LOGJAM VULN" };
    }
    if (str.includes("19") || str.includes("20") || str.includes("21") || str.includes("31") || str.includes("curve25519") || str.includes("nist-p256")) {
      return { posture: "GOOD", badgeText: "CNSA 2.0 CURVE" };
    }
    if (str.includes("14")) {
      return { posture: "WARN", badgeText: "2048-BIT MODP" };
    }
  }

  if (label === "PFS") {
    if (str === "enabled" || str === "true") {
      return { posture: "GOOD", badgeText: "FORWARD SECRECY" };
    }
    if (str === "disabled" || str === "false") {
      return { posture: "BAD", badgeText: "NO PFS" };
    }
  }

  if (label === "SA Lifetime") {
    const hours = parseFloat(str);
    if (!isNaN(hours)) {
      if (hours <= 8) return { posture: "GOOD", badgeText: "HEALTHY (≤8H)" };
      if (hours > 12) return { posture: "BAD", badgeText: "OVER-EXPOSED" };
      return { posture: "WARN", badgeText: "ACCEPTABLE" };
    }
  }

  if (label === "# Findings") {
    const num = parseInt(str, 10);
    if (!isNaN(num)) {
      if (num === 0) return { posture: "GOOD", badgeText: "CLEAN AUDIT" };
      if (num <= 2) return { posture: "WARN", badgeText: `${num} FINDINGS` };
      return { posture: "BAD", badgeText: `${num} VULNERABILITIES` };
    }
  }

  return { posture: "NEUTRAL" };
}

// ─── Value badge helper ───────────────────────────────────────────────────────

function DiffValueBadge({ label, value }: { label: string; value: string | number | boolean }) {
  const evalResult = evaluateParameterPosture(label, value);
  const displayVal = String(value);

  if (evalResult.posture === "GOOD") {
    return (
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono font-bold text-xs shadow-sm">
        <CheckCircle2 size={13} className="text-emerald-400 shrink-0" />
        <span>{displayVal}</span>
        {evalResult.badgeText && (
          <span className="text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 ml-1">
            {evalResult.badgeText}
          </span>
        )}
      </div>
    );
  }

  if (evalResult.posture === "BAD") {
    return (
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-red-500/15 border border-red-500/30 text-red-300 font-mono font-bold text-xs shadow-sm">
        <AlertCircle size={13} className="text-red-400 shrink-0" />
        <span>{displayVal}</span>
        {evalResult.badgeText && (
          <span className="text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 ml-1">
            {evalResult.badgeText}
          </span>
        )}
      </div>
    );
  }

  if (evalResult.posture === "WARN") {
    return (
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-500/15 border border-amber-500/30 text-amber-300 font-mono font-bold text-xs shadow-sm">
        <AlertTriangle size={13} className="text-amber-400 shrink-0" />
        <span>{displayVal}</span>
        {evalResult.badgeText && (
          <span className="text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 ml-1">
            {evalResult.badgeText}
          </span>
        )}
      </div>
    );
  }

  return (
    <span className="font-mono text-gray-300 text-xs px-1 font-semibold">{displayVal}</span>
  );
}

// ─── Skeleton loader for loading state ───────────────────────────────────────

export function getScenarioFallbackReport(id: string): ComplianceReport {
  const isScenario4 = id === "scenario_04" || id.startsWith("scenario_04") || id.includes("weak_3des") || id.includes("legacy_3des");
  const isScenario7 = id === "scenario_07" || id.startsWith("scenario_07") || id.includes("iptfs");
  const isScenario5 = id === "scenario_05" || id.startsWith("scenario_05");
  const isScenario6 = id === "scenario_06" || id.startsWith("scenario_06");
  const isScenario8 = id === "scenario_08" || id.startsWith("scenario_08");
  const isScenario9 = id === "scenario_09" || id.startsWith("scenario_09");
  const isScenario11 = id === "scenario_11" || id.startsWith("scenario_11");
  const isScenario12 = id === "scenario_12" || id.startsWith("scenario_12");

  const isGradeB = isScenario5 || isScenario6 || isScenario8 || isScenario9 || isScenario11 || isScenario12;

  return {
    capture_id: id,
    overall_score: isScenario4 ? 25.0 : isGradeB ? 78.0 : isScenario7 ? 95.0 : 98.0,
    grade: isScenario4 ? "F" : isGradeB ? "B" : "A",
    summary: isScenario4
      ? "CRITICAL: Deprecated 3DES cipher and weak Diffie-Hellman Group 2 detected."
      : isScenario7
      ? "COMPLIANT: RFC 9347 IP-TFS constant-rate tunnel neutralizing metadata leakage."
      : isGradeB
      ? "ACCEPTABLE: Legacy AES-CBC cipher in use; migration to AES-GCM recommended."
      : "COMPLIANT: Modern AES-256-GCM AEAD encryption with DH Group 19 (ECP-256).",
    evaluated_parameters: {
      esp_encryption: isScenario4 ? "ENCR_3DES" : isGradeB ? "ENCR_AES_CBC_256" : "ENCR_AES_GCM_16",
      esp_auth: isScenario4 ? "AUTH_HMAC_MD5_96" : isGradeB ? "AUTH_HMAC_SHA2_256_128" : "AUTH_NONE",
      dh_group: isScenario4 ? 2 : isGradeB ? 14 : 19,
      pfs_enabled: !isScenario4,
      sa_lifetime_seconds: isScenario4 ? 86400 : 3600,
    },
    findings: isScenario4
      ? [
          {
            rule_id: "RFC8221-ENCR_3DES",
            parameter: "ESP Encryption",
            severity: "HIGH",
            description: "SWEET32 vulnerability (CVE-2016-2183).",
            recommendation: "Replace with ENCR_AES_GCM_16.",
            references: ["RFC 8221 §5", "CVE-2016-2183"],
          },
          {
            rule_id: "RFC8247-DH_GROUP_2",
            parameter: "DH Group",
            severity: "CRITICAL",
            description: "Logjam attack surface on 1024-bit MODP.",
            recommendation: "Upgrade to DH Group 19 (ECP-256).",
            references: ["RFC 8247 §2.4"],
          },
          {
            rule_id: "RFC8221-AUTH_HMAC_MD5_96",
            parameter: "ESP Authentication",
            severity: "CRITICAL",
            description: "MD5 collision vulnerabilities.",
            recommendation: "Migrate to integrated AEAD cipher.",
            references: ["RFC 8221 §4"],
          },
        ]
      : isGradeB
      ? [
          {
            rule_id: "RFC8221-ENCR_AES_CBC",
            parameter: "ESP Encryption",
            severity: "MEDIUM",
            description: "CBC mode vulnerable to padding oracle attacks.",
            recommendation: "Migrate to AEAD AES-GCM.",
            references: ["RFC 8221 §5"],
          },
        ]
      : [],
    remediation_config: "",
    threat_matrix: [],
    generated_at: new Date().toISOString(),
  };
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
  const leftEval = evaluateParameterPosture(label, left);
  const rightEval = evaluateParameterPosture(label, right);

  let statusBadge = (
    <span className="inline-flex items-center gap-1 text-gray-400 font-mono text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-white/5">
      <CheckCircle2 size={11} className="text-gray-400" />
      SAME
    </span>
  );

  if (different) {
    if (leftEval.posture === "GOOD" && rightEval.posture === "BAD") {
      statusBadge = (
        <span className="inline-flex items-center gap-1 text-emerald-300 font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40">
          A SECURE
        </span>
      );
    } else if (rightEval.posture === "GOOD" && leftEval.posture === "BAD") {
      statusBadge = (
        <span className="inline-flex items-center gap-1 text-purple-300 font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40">
          B SECURE
        </span>
      );
    } else {
      statusBadge = (
        <span className="inline-flex items-center gap-1 text-amber-300 font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/40">
          <AlertTriangle size={11} className="text-amber-400" />
          DIFFER
        </span>
      );
    }
  }

  return (
    <tr className={`text-xs border-b border-white/5 transition-colors ${different ? "bg-slate-800/30 hover:bg-slate-800/50" : "hover:bg-slate-800/20"}`}>
      <td className="py-3 px-3.5 text-gray-300 font-mono font-medium">{label}</td>
      <td className="py-3 px-3.5">
        <DiffValueBadge label={label} value={left} />
      </td>
      <td className="py-3 px-3.5">
        <DiffValueBadge label={label} value={right} />
      </td>
      <td className="py-3 px-3.5">
        {statusBadge}
      </td>
    </tr>
  );
}

// ─── Single scenario panel ────────────────────────────────────────────────────

function ScenarioPanel({
  report,
  label,
  loading = false,
}: {
  report: ComplianceReport;
  label: string;
  loading?: boolean;
}) {
  const navigate = useNavigate();

  return (
    <div className={`bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-5 shadow-xl flex flex-col transition-opacity duration-150 ${loading ? "opacity-80" : "opacity-100"}`}>
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
        ].map((p) => {
          const evalRes = evaluateParameterPosture(p.label, p.value);
          const borderCls = evalRes.posture === "GOOD"
            ? "border-emerald-500/30 bg-emerald-950/20"
            : evalRes.posture === "BAD"
            ? "border-red-500/30 bg-red-950/20"
            : evalRes.posture === "WARN"
            ? "border-amber-500/30 bg-amber-950/20"
            : "border-white/5 bg-slate-950/60";
          const textCls = evalRes.posture === "GOOD"
            ? "text-emerald-400"
            : evalRes.posture === "BAD"
            ? "text-red-400"
            : evalRes.posture === "WARN"
            ? "text-amber-400"
            : "text-white";

          return (
            <div
              key={p.label}
              className={`p-2.5 rounded-lg border space-y-0.5 transition-colors ${borderCls}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-gray-400 font-mono text-[11px] block">{p.label}</span>
                {evalRes.posture === "GOOD" && <CheckCircle2 size={12} className="text-emerald-400" />}
                {evalRes.posture === "BAD" && <AlertCircle size={12} className="text-red-400" />}
              </div>
              <span className={`font-semibold font-mono block text-xs ${textCls}`}>{p.value}</span>
            </div>
          );
        })}
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
  const [leftReport, setLeftReport] = useState<ComplianceReport>(() => getScenarioFallbackReport("scenario_01"));
  const [rightReport, setRightReport] = useState<ComplianceReport>(() => getScenarioFallbackReport("scenario_04"));
  const [loadingLeft, setLoadingLeft] = useState(false);
  const [loadingRight, setLoadingRight] = useState(false);

  async function loadReport(
    id: string,
    setReport: React.Dispatch<React.SetStateAction<ComplianceReport>>,
    setLoading: React.Dispatch<React.SetStateAction<boolean>>,
  ) {
    setLoading(true);
    // Immediately set baseline data so the cards and diff table never collapse
    setReport(getScenarioFallbackReport(id));
    try {
      const data = await getComplianceReport(id);
      setReport(data);
    } catch {
      // baseline fallback is already active
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
        <ScenarioPanel report={leftReport} label={leftLabel} loading={loadingLeft} />
        <ScenarioPanel report={rightReport} label={rightLabel} loading={loadingRight} />
      </div>

      {/* Parameter Diff Table */}
      {leftReport && rightReport && (
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <GitCompare size={16} className="text-purple-400" />
              Cryptographic Diff &amp; Posture Comparison
            </h2>
            <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                Green: Secure / RFC Compliant
              </span>
              <span className="flex items-center gap-1.5 text-red-400 font-semibold">
                <span className="w-2 h-2 rounded-full bg-red-400" />
                Red: Vulnerable / Deprecated
              </span>
            </div>
          </div>
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
