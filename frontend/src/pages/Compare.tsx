import { useState, useEffect } from "react";
import { GitCompare, Shield, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import { getComplianceReport } from "../api/client";
import ScoreGauge from "../components/ScoreGauge";
import RiskBadge from "../components/RiskBadge";
import type { ComplianceReport } from "../types";

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
      return { posture: "BAD", badgeText: "SWEET32 / BROKEN" };
    }
    if (str.includes("gcm") || str.includes("chacha") || str.includes("poly") || str.includes("aes_256")) {
      return { posture: "GOOD", badgeText: "RFC 8221 AEAD" };
    }
    if (str.includes("cbc")) {
      return { posture: "WARN", badgeText: "LEGACY CBC" };
    }
  }

  if (label === "Integrity Auth") {
    if (str.includes("md5") || str.includes("sha1") || str.includes("96")) {
      return { posture: "BAD", badgeText: "DEPRECATED HASH" };
    }
    if (str.includes("none") || str.includes("aead") || str.includes("sha2") || str.includes("256")) {
      return { posture: "GOOD", badgeText: "APPROVED" };
    }
  }

  if (label === "Diffie-Hellman Group") {
    const num = parseInt(str.replace(/\D/g, ""), 10);
    if (!isNaN(num)) {
      if (num === 1 || num === 2) return { posture: "BAD", badgeText: "LOGJAM VULNERABLE" };
      if (num === 5) return { posture: "WARN", badgeText: "DEPRECATED (1536b)" };
      if (num >= 14) return { posture: "GOOD", badgeText: "ADEQUATE MARGIN" };
    }
  }

  if (label === "Forward Secrecy (PFS)") {
    if (str === "true" || str === "yes" || str === "enabled") {
      return { posture: "GOOD", badgeText: "PFS ACTIVE" };
    }
    return { posture: "BAD", badgeText: "NO PFS" };
  }

  if (label === "SA Lifetime") {
    const num = parseInt(str.replace(/\D/g, ""), 10);
    if (!isNaN(num) && num > 14400) {
      return { posture: "WARN", badgeText: "EXCEEDS NIST 4H" };
    }
    return { posture: "GOOD", badgeText: "NIST COMPLIANT" };
  }

  return { posture: "NEUTRAL" };
}

export function getScenarioFallbackReport(id: string): ComplianceReport {
  const isScenario4 = id === "scenario_04" || id.startsWith("scenario_04") || id.includes("weak_3des");
  const isScenario7 = id === "scenario_07" || id.startsWith("scenario_07") || id.includes("iptfs");
  const isGradeB = ["scenario_05", "scenario_06", "scenario_08", "scenario_09", "scenario_11", "scenario_12"].some((s) => id.startsWith(s));

  return {
    capture_id: id,
    overall_score: isScenario4 ? 25.0 : isGradeB ? 78.0 : isScenario7 ? 95.0 : 96.0,
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
            description: "SWEET32 vulnerability (CVE-2016-2183) — 64-bit block cipher collision risks.",
            recommendation: "Replace with ENCR_AES_GCM_16.",
            references: ["RFC 8221 §5", "CVE-2016-2183"],
          },
          {
            rule_id: "RFC8247-DH_GROUP_2",
            parameter: "Diffie-Hellman Group",
            severity: "HIGH",
            description: "1024-bit MODP group vulnerable to nation-state Logjam precomputation.",
            recommendation: "Upgrade to DH Group 19 (ECP-256) or Group 14 (MODP-2048).",
            references: ["RFC 8247 §2.4", "CVE-2015-4000"],
          },
        ]
      : [],
  };
}

function PostureValue({ label, value }: { label: string; value: string | number | boolean }) {
  const { posture, badgeText } = evaluateParameterPosture(label, value);
  const displayVal = typeof value === "boolean" ? (value ? "Enabled" : "Disabled") : String(value);

  const badgeClass =
    posture === "GOOD"
      ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
      : posture === "BAD"
      ? "bg-red-500/15 text-red-400 border border-red-500/30"
      : posture === "WARN"
      ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
      : "bg-sunken text-muted";

  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-xs font-semibold text-ink">{displayVal}</span>
      {badgeText && (
        <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase ${badgeClass}`}>
          {badgeText}
        </span>
      )}
    </div>
  );
}

function ScenarioPanel({ report, label }: { report: ComplianceReport; label: string }) {
  const critical = report.findings?.filter((f) => f.severity.toUpperCase() === "CRITICAL").length ?? 0;
  const high = report.findings?.filter((f) => f.severity.toUpperCase() === "HIGH").length ?? 0;

  return (
    <div className="flex flex-col justify-between rounded-2xl border border-rule bg-surface p-6 shadow-sm space-y-5 interactive-card">
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-rule pb-3">
          <h3 className="text-sm font-bold text-ink truncate">{label}</h3>
          <RiskBadge level={critical > 0 ? "CRITICAL" : high > 0 ? "HIGH" : "LOW"} size="sm" />
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-around gap-4 py-2">
          <ScoreGauge score={report.overall_score ?? 0} grade={report.grade} label="Security Score" size={165} />
          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between gap-4">
              <span className="text-muted">Grade:</span>
              <span className="font-bold text-ink">{report.grade}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-muted">Critical:</span>
              <span className="font-bold text-critical">{critical}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-muted">High:</span>
              <span className="font-bold text-high">{high}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-muted">Total Findings:</span>
              <span className="font-bold text-ink">{report.findings?.length ?? 0}</span>
            </div>
          </div>
        </div>

        <p className="text-xs text-muted leading-relaxed line-clamp-2">{report.summary}</p>
      </div>

      <div className="border-t border-rule pt-3 text-right">
        <Link
          to={`/compliance/${report.capture_id}?demo=1`}
          className="inline-flex items-center gap-1 text-xs font-semibold text-accent hover:underline"
        >
          View Full Audit <ArrowRight size={12} />
        </Link>
      </div>
    </div>
  );
}

export default function Compare() {
  const [leftId, setLeftId] = useState("scenario_01");
  const [rightId, setRightId] = useState("scenario_04");
  const [leftReport, setLeftReport] = useState<ComplianceReport>(() => getScenarioFallbackReport("scenario_01"));
  const [rightReport, setRightReport] = useState<ComplianceReport>(() => getScenarioFallbackReport("scenario_04"));

  async function loadReport(id: string, setter: React.Dispatch<React.SetStateAction<ComplianceReport>>) {
    setter(getScenarioFallbackReport(id));
    // If it's a dynamic user capture, attempt to fetch live results
    if (!AVAILABLE_SCENARIOS.some((s) => s.id === id)) {
      try {
        const data = await getComplianceReport(id);
        setter(data);
      } catch {
        // Fallback is already loaded
      }
    }
  }

  useEffect(() => { loadReport(leftId, setLeftReport); }, [leftId]);
  useEffect(() => { loadReport(rightId, setRightReport); }, [rightId]);

  const leftLabel = AVAILABLE_SCENARIOS.find((s) => s.id === leftId)?.label || leftId;
  const rightLabel = AVAILABLE_SCENARIOS.find((s) => s.id === rightId)?.label || rightId;

  const leftParams = leftReport.evaluated_parameters || {};
  const rightParams = rightReport.evaluated_parameters || {};

  const diffRows: Array<{ label: string; left: string | number | boolean; right: string | number | boolean }> = [
    { label: "Overall Score", left: `${leftReport.overall_score ?? 0} / 100 (${leftReport.grade})`, right: `${rightReport.overall_score ?? 0} / 100 (${rightReport.grade})` },
    { label: "ESP Cipher", left: String(leftParams.esp_encryption ?? "—"), right: String(rightParams.esp_encryption ?? "—") },
    { label: "Integrity Auth", left: String(leftParams.esp_auth ?? "None (AEAD)"), right: String(rightParams.esp_auth ?? "None (AEAD)") },
    { label: "Diffie-Hellman Group", left: leftParams.dh_group ? `Group ${leftParams.dh_group}` : "—", right: rightParams.dh_group ? `Group ${rightParams.dh_group}` : "—" },
    { label: "Forward Secrecy (PFS)", left: Boolean(leftParams.pfs_enabled), right: Boolean(rightParams.pfs_enabled) },
    { label: "SA Lifetime", left: leftParams.sa_lifetime_seconds ? `${leftParams.sa_lifetime_seconds}s` : "—", right: rightParams.sa_lifetime_seconds ? `${rightParams.sa_lifetime_seconds}s` : "—" },
  ];

  return (
    <div className="space-y-8 motion-enter max-w-5xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink flex items-center gap-2">
            <GitCompare className="text-accent" size={24} />
            Side-by-Side Scenario Comparison
          </h1>
          <p className="text-xs sm:text-sm text-muted mt-1">
            Compare cryptographic parameters, RFC compliance scores, and vulnerabilities between any two profiles.
          </p>
        </div>
      </div>

      {/* Selectors */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="rounded-xl border border-rule bg-surface p-4 space-y-2">
          <label className="text-xs font-semibold text-muted uppercase tracking-wider flex items-center gap-2">
            <Shield size={14} className="text-accent" />
            Left Scenario (Profile A)
          </label>
          <select
            value={leftId}
            onChange={(e) => setLeftId(e.target.value)}
            className="w-full rounded-lg border border-rule bg-sunken p-2.5 text-xs font-mono text-ink focus:border-accent focus:outline-none cursor-pointer"
          >
            {AVAILABLE_SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>{s.label}</option>
            ))}
          </select>
        </div>

        <div className="rounded-xl border border-rule bg-surface p-4 space-y-2">
          <label className="text-xs font-semibold text-muted uppercase tracking-wider flex items-center gap-2">
            <Shield size={14} className="text-purple-400" />
            Right Scenario (Profile B)
          </label>
          <select
            value={rightId}
            onChange={(e) => setRightId(e.target.value)}
            className="w-full rounded-lg border border-rule bg-sunken p-2.5 text-xs font-mono text-ink focus:border-accent focus:outline-none cursor-pointer"
          >
            {AVAILABLE_SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>{s.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Side-by-side Score Panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <ScenarioPanel report={leftReport} label={leftLabel} />
        <ScenarioPanel report={rightReport} label={rightLabel} />
      </div>

      {/* Parameter Diff Table */}
      <div className="rounded-2xl border border-rule bg-surface p-6 space-y-4 shadow-sm">
        <div className="flex items-center gap-2 border-b border-rule pb-3">
          <GitCompare size={18} className="text-accent" />
          <h2 className="text-base font-bold text-ink">Cryptographic Parameter Diff &amp; Posture Matrix</h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-rule font-mono text-muted">
                <th className="py-2.5 px-3">Parameter</th>
                <th className="py-2.5 px-3">{leftLabel.split("—")[0]}</th>
                <th className="py-2.5 px-3">{rightLabel.split("—")[0]}</th>
              </tr>
            </thead>
            <tbody>
              {diffRows.map((row) => (
                <tr key={row.label} className="border-b border-rule/60 hover:bg-sunken/40 transition-colors">
                  <td className="py-3 px-3 font-semibold text-ink w-48">{row.label}</td>
                  <td className="py-3 px-3"><PostureValue label={row.label} value={row.left} /></td>
                  <td className="py-3 px-3"><PostureValue label={row.label} value={row.right} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
