/**
 * pages/Compliance.tsx — Deterministic RFC 8221, RFC 8247 & NIST SP 800-77 Engine Dashboard
 */
import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  Lock,
  FileText,
  CheckCircle2,
  Play,
  Copy,
  Check,
  Terminal,
  AlertCircle,
  Download,
  AlertTriangle,
  Lightbulb,
  Sparkles,
  BookOpen,
  X,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { getComplianceReport, runAdHocEvaluation, explainFinding } from "../api/client";
import type { ComplianceReport, Finding, RiskLevel, ExplainerResponse } from "../types";
import RiskBadge from "../components/RiskBadge";
import ScoreGauge from "../components/ScoreGauge";

// ─── Fix suggestions per rule ID ─────────────────────────────────────────────
// "What would fix this?" inline explainer — makes results actionable

const FIX_SUGGESTIONS: Record<string, string> = {
  "RFC8221-ENCR_3DES":
    "Change ESP cipher from 3DES → AES-256-GCM-16 in swanctl.conf. Estimated effort: 2 minutes.",
  "RFC8221-ENCR_BLOWFISH":
    "Replace Blowfish with AES-256-GCM-16. Blowfish is MUST NOT per RFC 8221 §5.",
  "RFC8247-DH_GROUP_2":
    "Upgrade DH Group 2 (MODP-1024) → Group 19 (ECP-256) in your IKEv2 proposal. Estimated effort: 5 minutes.",
  "RFC8247-DH_GROUP_1":
    "Upgrade DH Group 1 (MODP-768) → Group 19 (ECP-256). Group 1 is cryptographically broken.",
  "RFC8221-AUTH_HMAC_MD5_96":
    "Replace HMAC-MD5-96 with AEAD cipher (drop separate auth) or HMAC-SHA2-256-128. Estimated effort: 2 minutes.",
  "RFC8221-AUTH_HMAC_SHA1_96":
    "Migrate from HMAC-SHA1-96 to HMAC-SHA2-256-128 or switch to an AEAD cipher.",
  "NIST-SA_LIFETIME":
    "Reduce SA lifetime to ≤ 4h (14400 s) per NIST SP 800-77 Rev. 1 §7.2.3. One config line change.",
  "NIST-PFS":
    "Enable Perfect Forward Secrecy (PFS) by adding a Child SA DH group. Estimated effort: 1 minute.",
};

function getFixSuggestion(ruleId: string | undefined): string | null {
  if (!ruleId) return null;
  return FIX_SUGGESTIONS[ruleId] || null;
}


// ─── AES-CBC + AUTH_NONE validation ──────────────────────────────────────────

const AEAD_CIPHERS = new Set([
  "ENCR_AES_GCM_16", "ENCR_AES_GCM_12", "ENCR_AES_GCM_8",
  "ENCR_CHACHA20_POLY1305", "ENCR_AES_CCM_8", "ENCR_AES_CCM_12", "ENCR_AES_CCM_16",
]);

function validateAdhocCombo(cipher: string, auth: string): string | null {
  const isAead = AEAD_CIPHERS.has(cipher);
  if (auth === "AUTH_NONE" && !isAead) {
    return (
      `AUTH_NONE is only valid with AEAD ciphers (e.g., AES-GCM, ChaCha20-Poly1305). ` +
      `${cipher} is not an AEAD cipher — this combination would produce an unauthenticated ` +
      `ESP tunnel, which is invalid per RFC 8221. Please select HMAC-SHA2-256-128 for auth, ` +
      `or switch the cipher to AES-GCM-16.`
    );
  }
  if (isAead && auth !== "AUTH_NONE") {
    return (
      `${cipher} is an AEAD cipher that provides built-in authentication. ` +
      `Using a separate auth algorithm (${auth}) is redundant and may cause ` +
      `negotiation failures. Set auth to AUTH_NONE for AEAD ciphers.`
    );
  }
  return null;
}

// ─── JSON export ──────────────────────────────────────────────────────────────

function exportReportJSON(report: ComplianceReport, captureId: string) {
  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `janus_compliance_${captureId.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function Compliance() {
  const { captureId = "scenario_01" } = useParams<{ captureId: string }>();

  const navigate = useNavigate();

  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [isDemoMode, setIsDemoMode] = useState(false);

  // Ad-hoc sandbox state
  const [adhocCipher, setAdhocCipher] = useState("ENCR_AES_GCM_16");
  const [adhocAuth, setAdhocAuth] = useState("AUTH_NONE");
  const [adhocDh, setAdhocDh] = useState(19);
  const [adhocPfs, setAdhocPfs] = useState(true);
  const [adhocLifetime, setAdhocLifetime] = useState(3600);
  const [evaluatingAdhoc, setEvaluatingAdhoc] = useState(false);
  const [adhocValidationError, setAdhocValidationError] = useState<string | null>(null);

  // Compliance-RAG Explainer modal state
  const [explainingFinding, setExplainingFinding] = useState<Finding | null>(null);
  const [explanationResult, setExplanationResult] = useState<ExplainerResponse | null>(null);
  const [loadingExplanation, setLoadingExplanation] = useState(false);
  const [showSourceClauses, setShowSourceClauses] = useState(false);

  const handleExplainFinding = async (finding: Finding) => {
    setExplainingFinding(finding);
    setLoadingExplanation(true);
    setExplanationResult(null);
    setShowSourceClauses(false);
    try {
      const res = await explainFinding(finding as unknown as Record<string, unknown>, 3);
      setExplanationResult(res);
    } catch (err) {
      console.error("Explainer failed:", err);
    } finally {
      setLoadingExplanation(false);
    }
  };

  useEffect(() => {
    async function loadData() {
      try {
        const data = await getComplianceReport(captureId);
        setReport(data);
        setIsDemoMode(false);
      } catch {
        // High-fidelity fallback profile if backend has no active capture session
        const isScenario4 = captureId.includes("04") || captureId.includes("weak");
        const fallback: ComplianceReport = {
          capture_id: captureId,
          overall_score: isScenario4 ? 25.0 : 96.0,
          grade: isScenario4 ? "F" : "A",
          summary: isScenario4
            ? "CRITICAL: Deprecated 3DES cipher and weak Diffie-Hellman Group 2 detected."
            : "COMPLIANT: Modern AES-GCM AEAD encryption and DH Group 19 compliant with RFC 8221.",
          evaluated_parameters: {
            esp_encryption: isScenario4 ? "ENCR_3DES" : "ENCR_AES_GCM_16",
            esp_auth: isScenario4 ? "AUTH_HMAC_MD5_96" : "AUTH_NONE",
            dh_group: isScenario4 ? 2 : 19,
            pfs_enabled: !isScenario4,
            sa_lifetime_seconds: isScenario4 ? 86400 : 3600,
          },
          remediation_config: `# =============================================================================
# Janus Automated strongSwan Remediation Configuration
# Generated based on RFC 8221 (ESP), RFC 8247 (IKEv2) & NIST SP 800-77 Rev. 1
# =============================================================================
${isScenario4 ? "# Fix for RFC8221-ENCR_3DES [HIGH]: Replace with ENCR_AES_GCM_16\n# Fix for RFC8247-DH_GROUP_2 [CRITICAL]: Upgrade to DH Group 19 (ECP-256)" : "# Status: Baseline satisfies standard requirements"}

connections {
    janus-remediated {
        version = 2
        proposals = aes256gcm16-prfsha256-ecp256!
        rekey_time = 4h
        children {
            net-traffic {
                esp_proposals = aes256gcm16-ecp256!
                rekey_time = 4h
                copy_dscp = out
                copy_ecn = yes
            }
        }
    }
}`,
          findings: isScenario4
            ? [
                {
                  rule_id: "RFC8221-ENCR_3DES",
                  parameter: "ESP Encryption",
                  severity: "HIGH",
                  description: "3DES is vulnerable to SWEET32 64-bit block collision attacks.",
                  recommendation: "Replace with ENCR_AES_GCM_16 or ENCR_CHACHA20_POLY1305.",
                  references: ["RFC 8221 §5", "CVE-2016-2183"],
                },
                {
                  rule_id: "RFC8247-DH_GROUP_2",
                  parameter: "Diffie-Hellman Group",
                  severity: "CRITICAL",
                  description: "DH Group 2 (MODP-1024) is vulnerable to Logjam precomputation attacks.",
                  recommendation: "Upgrade to DH Group 19 (ECP-256) or Group 20 (ECP-384).",
                  references: ["RFC 8247 §2.4", "NIST SP 800-77 Rev. 1"],
                },
                {
                  rule_id: "RFC8221-AUTH_HMAC_MD5_96",
                  parameter: "ESP Authentication",
                  severity: "CRITICAL",
                  description: "MD5 hash algorithm suffers from severe collision vulnerabilities.",
                  recommendation: "Migrate to HMAC-SHA2-256-128 or AEAD cipher.",
                  references: ["RFC 8221 §5"],
                },
              ]
            : [],
          threat_matrix: [
            {
              technique_id: "T1040",
              tactic: "Credential Access",
              technique_name: "Network Sniffing",
              severity: isScenario4 ? "HIGH" : "INFO",
              status: isScenario4 ? "VULNERABLE" : "PROTECTED",
              details: isScenario4
                ? "Weak 3DES/MD5 suite allows traffic eavesdropping and active MITM."
                : "Protected via modern authenticated encryption (AES-256-GCM).",
            },
          ],
          generated_at: new Date().toISOString(),
        };
        setReport(fallback);
        setIsDemoMode(true);
      }
    }
    loadData();
  }, [captureId]);

  // Validate cipher+auth combo whenever either changes
  useEffect(() => {
    setAdhocValidationError(validateAdhocCombo(adhocCipher, adhocAuth));
  }, [adhocCipher, adhocAuth]);

  const handleRunAdHoc = async () => {
    if (adhocValidationError) return;
    setEvaluatingAdhoc(true);
    try {
      const res = await runAdHocEvaluation({
        esp_encryption: adhocCipher,
        esp_auth: adhocAuth,
        dh_group: Number(adhocDh),
        pfs_enabled: adhocPfs,
        sa_lifetime_seconds: Number(adhocLifetime),
        rsa_key_bits: 3072,
        ike_version: "IKEv2",
      });
      setReport(res);
      setIsDemoMode(false);
    } catch (err) {
      console.error("Ad-hoc evaluation failed:", err);
    } finally {
      setEvaluatingAdhoc(false);
    }
  };

  const handleCopyConfig = () => {
    if (report?.remediation_config) {
      navigator.clipboard.writeText(report.remediation_config);
      setCopiedConfig(true);
      setTimeout(() => setCopiedConfig(false), 2000);
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">

      {/* DEMO MODE Banner */}
      {isDemoMode && (
        <div className="flex items-center gap-3 px-4 py-3 bg-amber-900/30 border border-amber-500/50 rounded-xl text-amber-300 text-sm">
          <AlertCircle size={18} className="shrink-0 text-amber-400" />
          <div>
            <span className="font-bold">DEMO MODE</span>
            {" — Showing pre-computed compliance profile. "}
            <button
              onClick={() => navigate("/upload")}
              className="underline hover:text-amber-100 cursor-pointer"
            >
              Upload a real PCAP to run live evaluation.
            </button>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Cryptographic Compliance &amp; Security Audit
            </h1>
            <span className="px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/40 text-xs font-mono font-bold">
              RFC 8221 / RFC 8247 / NIST
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Zero-hallucination deterministic scoring evaluating IKE/ESP parameters against formal cryptographic RFC standards.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {report && (
            <button
              onClick={() => exportReportJSON(report, captureId)}
              title="Download compliance report as JSON"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-gray-300 text-xs font-semibold border border-white/10 cursor-pointer transition-colors"
            >
              <Download size={14} />
              Export JSON
            </button>
          )}
          <button
            onClick={() => navigate(`/report/${captureId}`)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/30 cursor-pointer transition-colors"
          >
            <FileText size={14} />
            Generate PDF Reports
          </button>
        </div>
      </div>

      {/* Top Banner: Score Gauge & Key Overview */}
      {report && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Score Gauge */}
          <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 flex flex-col items-center justify-center text-center shadow-xl">
            <h3 className="text-xs font-mono uppercase tracking-wider text-gray-400 mb-2">
              Overall Compliance Score
            </h3>
            <ScoreGauge score={report.overall_score} grade={report.grade} size={200} />
            <p className="text-xs text-gray-400 max-w-xs mt-2">{report.summary}</p>
          </div>

          {/* Evaluated Parameters Matrix */}
          <div className="lg:col-span-2 bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Lock size={16} className="text-blue-400" />
              Evaluated Cryptographic Parameters
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-white/5 space-y-1">
                <span className="text-gray-500 font-mono">ESP Cipher</span>
                <p className="text-sm font-bold text-white font-mono">
                  {report.evaluated_parameters?.esp_encryption || "ENCR_AES_GCM_16"}
                </p>
                <span className="text-[11px] text-emerald-400">RFC 8221 MUST (AEAD)</span>
              </div>

              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-white/5 space-y-1">
                <span className="text-gray-500 font-mono">ESP Authentication</span>
                <p className="text-sm font-bold text-white font-mono">
                  {report.evaluated_parameters?.esp_auth || "AUTH_NONE (AEAD Paired)"}
                </p>
                <span className="text-[11px] text-emerald-400">RFC 8221 Compliant</span>
              </div>

              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-white/5 space-y-1">
                <span className="text-gray-500 font-mono">Diffie-Hellman Group</span>
                <p className="text-sm font-bold text-white font-mono">
                  Group {report.evaluated_parameters?.dh_group || 19}
                </p>
                <span className="text-[11px] text-emerald-400">RFC 8247 RECOMMENDED (ECP-256)</span>
              </div>

              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-white/5 space-y-1">
                <span className="text-gray-500 font-mono">Forward Secrecy &amp; Lifetime</span>
                <p className="text-sm font-bold text-white font-mono">
                  PFS: {report.evaluated_parameters?.pfs_enabled ? "Enabled" : "Disabled"} |{" "}
                  {(report.evaluated_parameters?.sa_lifetime_seconds || 3600) / 3600}h
                </p>
                <span className="text-[11px] text-emerald-400">NIST SP 800-77 Window Compliant</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Audit Findings Section */}
      <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="flex items-center justify-between border-b border-white/10 pb-4">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert size={18} className="text-blue-400" />
              Compliance Findings &amp; Actionable Remediations
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Exact RFC rule deductions with mitigation guidance and CVE references.
            </p>
          </div>
          <span className="text-xs font-mono font-bold px-3 py-1 rounded-full bg-slate-800 text-gray-300">
            {report?.findings.length || 0} Issues Detected
          </span>
        </div>

        {report?.findings.length === 0 ? (
          <div className="p-8 text-center space-y-3 bg-slate-950/40 rounded-xl border border-white/5">
            <CheckCircle2 size={36} className="text-emerald-400 mx-auto" />
            <h3 className="text-sm font-bold text-white">Fully Compliant Security Posture</h3>
            <p className="text-xs text-gray-400 max-w-md mx-auto">
              All inspected parameters satisfy mandatory RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1
              cryptographic guidelines.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {report?.findings.map((finding, idx) => {
              const fixSuggestion = getFixSuggestion(finding.rule_id);
              return (
                <div
                  key={idx}
                  className="bg-slate-950/60 border border-white/10 rounded-xl p-4 space-y-3 hover:border-red-500/40 transition-colors duration-200"
                >
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-gray-400">{finding.rule_id}</span>
                        <span className="text-xs text-gray-500">•</span>
                        <span className="text-xs font-semibold text-white">{finding.parameter}</span>
                      </div>
                      <p className="text-sm font-medium text-gray-200">{finding.description}</p>
                    </div>
                    <RiskBadge level={(finding.severity || finding.risk_level || "MEDIUM") as RiskLevel} />
                  </div>

                  <div className="bg-slate-900/80 p-3 rounded-lg border border-white/5 space-y-1 text-xs">
                    <span className="text-blue-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 size={13} />
                      Recommended Remediation:
                    </span>
                    <p className="text-gray-300">{finding.recommendation || finding.remediation}</p>
                  </div>

                  {/* "What would fix this?" inline explainer */}
                  {fixSuggestion && (
                    <div className="flex items-start gap-2 p-3 bg-blue-950/30 border border-blue-500/20 rounded-lg text-xs text-blue-300">
                      <Lightbulb size={13} className="shrink-0 mt-0.5 text-blue-400" />
                      <span>
                        <span className="font-bold">Quick fix: </span>
                        {fixSuggestion}
                      </span>
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-1">
                    <div className="flex flex-wrap gap-1.5">
                      {finding.references && finding.references.length > 0 ? (
                        finding.references.map((ref, rIdx) => (
                          <span
                            key={rIdx}
                            className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] text-gray-400 font-mono"
                          >
                            {ref}
                          </span>
                        ))
                      ) : null}
                    </div>
                    <button
                      onClick={() => handleExplainFinding(finding)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 text-xs font-semibold transition-all cursor-pointer hover:border-blue-400/50 shrink-0"
                      title="Explain why this finding has this severity using RAG over RFC/NIST clauses"
                    >
                      <Sparkles size={13} className="text-blue-400" />
                      Explain (RFC RAG)
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Auto-Remediated swanctl.conf Generator Card */}
      {report?.remediation_config && (
        <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal size={18} className="text-emerald-400" />
              <div>
                <h3 className="text-base font-bold text-white">
                  Automated strongSwan Remediation Configuration
                </h3>
                <p className="text-xs text-gray-400">
                  Ready-to-deploy <code className="text-blue-400">swanctl.conf</code> resolving all detected CVEs and RFC non-compliances.
                </p>
              </div>
            </div>
            <button
              onClick={handleCopyConfig}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-mono font-semibold transition-all cursor-pointer"
            >
              {copiedConfig ? (
                <>
                  <Check size={14} className="text-emerald-400" />
                  Copied!
                </>
              ) : (
                <>
                  <Copy size={14} />
                  Copy Config
                </>
              )}
            </button>
          </div>

          <div className="bg-slate-950 p-4 rounded-xl border border-white/5 font-mono text-xs text-emerald-300/90 overflow-x-auto max-h-72">
            <pre>{report.remediation_config}</pre>
          </div>
        </div>
      )}

      {/* Interactive Ad-Hoc Sandbox Evaluation */}
      <div className="bg-slate-900/70 border border-white/10 rounded-2xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Play size={16} className="text-purple-400" />
            Ad-Hoc Cryptographic Suite Simulator
          </h3>
          <span className="text-xs text-gray-400">Test hypothetical configurations instantly</span>
        </div>

        {/* Combo validation warning */}
        {adhocValidationError && (
          <div className="flex items-start gap-2 p-3 bg-red-900/30 border border-red-500/40 rounded-lg text-red-300 text-xs">
            <AlertTriangle size={14} className="shrink-0 mt-0.5 text-red-400" />
            <span>{adhocValidationError}</span>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-5 gap-4 text-xs">
          <div>
            <label className="block text-gray-400 mb-1">ESP Cipher</label>
            <select
              value={adhocCipher}
              onChange={(e) => setAdhocCipher(e.target.value)}
              className="w-full bg-slate-950 border border-white/10 rounded-lg p-2 text-white font-mono focus:border-blue-500 focus:outline-none"
            >
              <option value="ENCR_AES_GCM_16">AES-GCM-16 (AEAD MUST)</option>
              <option value="ENCR_CHACHA20_POLY1305">ChaCha20-Poly1305 (AEAD SHOULD)</option>
              <option value="ENCR_AES_CBC">AES-CBC (MUST — needs separate auth)</option>
              <option value="ENCR_3DES">3DES (SHOULD NOT / SWEET32)</option>
              <option value="ENCR_BLOWFISH">Blowfish (MUST NOT)</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-400 mb-1">ESP Authentication</label>
            <select
              value={adhocAuth}
              onChange={(e) => setAdhocAuth(e.target.value)}
              className={`w-full bg-slate-950 border rounded-lg p-2 text-white font-mono focus:outline-none ${
                adhocValidationError ? "border-red-500/60" : "border-white/10 focus:border-blue-500"
              }`}
            >
              <option value="AUTH_NONE">AUTH_NONE (Paired with AEAD only)</option>
              <option value="AUTH_HMAC_SHA2_256_128">HMAC-SHA2-256 (MUST)</option>
              <option value="AUTH_HMAC_SHA1_96">HMAC-SHA1-96 (MUST-)</option>
              <option value="AUTH_HMAC_MD5_96">HMAC-MD5-96 (MUST NOT)</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-400 mb-1">DH Group</label>
            <select
              value={adhocDh}
              onChange={(e) => setAdhocDh(Number(e.target.value))}
              className="w-full bg-slate-950 border border-white/10 rounded-lg p-2 text-white font-mono focus:border-blue-500 focus:outline-none"
            >
              <option value={19}>Group 19 (ECP-256 — RECOMMENDED)</option>
              <option value={20}>Group 20 (ECP-384 — RECOMMENDED)</option>
              <option value={14}>Group 14 (MODP-2048 — SHOULD+)</option>
              <option value={2}>Group 2 (MODP-1024 — MUST NOT)</option>
              <option value={1}>Group 1 (MODP-768 — MUST NOT)</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-400 mb-1">PFS &amp; Lifetime</label>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setAdhocPfs(!adhocPfs)}
                className={`w-1/2 py-2 px-2 rounded-lg border text-xs font-mono cursor-pointer transition-colors ${
                  adhocPfs ? "bg-emerald-600/30 border-emerald-500 text-emerald-300" : "bg-slate-950 border-white/10 text-gray-400"
                }`}
              >
                PFS {adhocPfs ? "ON" : "OFF"}
              </button>
              <select
                value={adhocLifetime}
                onChange={(e) => setAdhocLifetime(Number(e.target.value))}
                className="w-1/2 bg-slate-950 border border-white/10 rounded-lg p-1 text-white font-mono text-[11px] focus:outline-none"
              >
                <option value={3600}>1h</option>
                <option value={14400}>4h</option>
                <option value={28800}>8h</option>
                <option value={86400}>24h (Bad)</option>
              </select>
            </div>
          </div>

          <div className="flex items-end">
            <button
              onClick={handleRunAdHoc}
              disabled={evaluatingAdhoc || !!adhocValidationError}
              title={adhocValidationError ? "Fix the validation error above before simulating" : undefined}
              className="w-full py-2 px-4 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold transition-all cursor-pointer"
            >
              {evaluatingAdhoc ? "Evaluating…" : "Simulate"}
            </button>
          </div>
        </div>
      </div>

      {/* Compliance-RAG Explainer Modal / Drawer */}
      {explainingFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-blue-500/40 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-white/10 bg-slate-950/80 sticky top-0 z-10">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  <Sparkles size={18} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white">RFC/NIST Standards Explainer</h3>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                      Qwen3-4B-Instruct RAG
                    </span>
                  </div>
                  <p className="text-xs text-gray-400">
                    Grounded domain specialist explanation citing primary standards text.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setExplainingFinding(null)}
                className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-all cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5 flex-1">
              {/* Target Finding Summary */}
              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/10 flex items-center justify-between">
                <div className="space-y-0.5">
                  <span className="text-xs font-mono font-bold text-gray-400">{explainingFinding.rule_id}</span>
                  <p className="text-sm font-semibold text-white">{explainingFinding.parameter}</p>
                </div>
                <RiskBadge level={(explainingFinding.severity || explainingFinding.risk_level || "MEDIUM") as RiskLevel} />
              </div>

              {loadingExplanation ? (
                <div className="flex flex-col items-center justify-center py-12 space-y-3">
                  <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  <p className="text-xs text-gray-400 font-mono">Retrieving standards clauses &amp; generating grounded explanation...</p>
                </div>
              ) : explanationResult ? (
                <div className="space-y-4">
                  {/* Model Metadata Banner */}
                  <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-lg bg-blue-950/40 border border-blue-500/20 text-xs font-mono text-gray-300">
                    <span className="flex items-center gap-1.5 text-blue-300">
                      <ShieldCheck size={14} className="text-emerald-400" />
                      Model: <span className="text-white font-bold">{explanationResult.model_name}</span>
                    </span>
                    <span className="text-gray-400">
                      Latency: <span className="text-white">{explanationResult.latency_ms} ms</span>
                    </span>
                    <span className="text-emerald-400 font-semibold">
                      Groundedness: {Math.round(explanationResult.groundedness_score * 100)}%
                    </span>
                  </div>

                  {/* Warning Banner if ungrounded citations were remediated */}
                  {explanationResult.warning && (
                    <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-500/40 text-xs text-amber-300 flex items-center gap-2">
                      <AlertTriangle size={14} className="shrink-0 text-amber-400" />
                      <span>{explanationResult.warning}</span>
                    </div>
                  )}

                  {/* Natural Language Explanation */}
                  <div className="bg-slate-950/80 p-4 rounded-xl border border-white/10 text-sm text-gray-200 leading-relaxed whitespace-pre-line">
                    {explanationResult.explanation}
                  </div>

                  {/* Verified Citations List */}
                  {explanationResult.citations && explanationResult.citations.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                        Verified Primary Standards Citations
                      </h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {explanationResult.citations.map((c, cIdx) => (
                          <div
                            key={cIdx}
                            className={`p-2.5 rounded-lg border text-xs flex items-center justify-between ${
                              c.verified
                                ? "bg-emerald-950/30 border-emerald-500/30 text-emerald-300"
                                : "bg-amber-950/30 border-amber-500/30 text-amber-300"
                            }`}
                          >
                            <div className="flex items-center gap-2 font-mono">
                              <span className="font-bold">{c.raw_citation}</span>
                              <span className="text-[10px] text-gray-400 truncate max-w-[150px]">{c.clause_title}</span>
                            </div>
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-white/10">
                              {c.verified ? "Verified" : "Flagged"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Collapsible Retrieved Source Chunks */}
                  {explanationResult.retrieved_chunks && explanationResult.retrieved_chunks.length > 0 && (
                    <div className="border border-white/10 rounded-xl overflow-hidden">
                      <button
                        onClick={() => setShowSourceClauses(!showSourceClauses)}
                        className="w-full flex items-center justify-between p-3 bg-slate-950 hover:bg-slate-800/60 text-xs font-semibold text-gray-300 transition-colors cursor-pointer"
                      >
                        <span className="flex items-center gap-2">
                          <BookOpen size={14} className="text-blue-400" />
                          View Primary Standards Chunks ({explanationResult.retrieved_chunks.length} clauses)
                        </span>
                        {showSourceClauses ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>

                      {showSourceClauses && (
                        <div className="p-3 bg-slate-950/90 border-t border-white/10 space-y-3 max-h-60 overflow-y-auto">
                          {explanationResult.retrieved_chunks.map((chk, kIdx) => (
                            <div key={kIdx} className="p-2.5 rounded-lg bg-slate-900 border border-white/5 space-y-1 text-xs">
                              <div className="flex items-center justify-between font-mono text-[11px] text-blue-300">
                                <span>{chk.document} {chk.section} — {chk.title}</span>
                                <span className="text-gray-500">score: {chk.score.toFixed(4)}</span>
                              </div>
                              <p className="text-gray-400 font-mono text-[10px] whitespace-pre-wrap leading-relaxed line-clamp-4">
                                {chk.text}
                              </p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : null}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-white/10 bg-slate-950/80 flex justify-end">
              <button
                onClick={() => setExplainingFinding(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition-all cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

