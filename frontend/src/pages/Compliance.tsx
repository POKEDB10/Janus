import { useLocation, useParams } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { getApiErrorMessage } from "../lib/api-error";
import { ErrorState, InlineNotice, LoadingState, PageHeader } from "../components/ui/Primitives";
import ScoreGauge from "../components/ScoreGauge";
import RiskBadge from "../components/RiskBadge";
import { DetectedParametersPanel } from "./compliance/DetectedParametersPanel";
import { FindingsPanel } from "./compliance/FindingsPanel";
import { RemediationConfigPanel } from "./compliance/RemediationConfigPanel";
import { ParameterSandbox } from "./compliance/ParameterSandbox";
import { ThreatMatrix } from "./compliance/ThreatMatrix";
import { useExplainerDrawer } from "./compliance/ExplainerDrawer";
import { JsonExport } from "./compliance/JsonExport";

export default function Compliance() {
  const { captureId = "" } = useParams();
  const { search } = useLocation();
  const results = useCaptureResults(captureId, search);
  const explainer = useExplainerDrawer();

  if (results.isPending) {
    return <LoadingState label="Loading configuration audit…" />;
  }

  if (results.isError) {
    return (
      <ErrorState
        title="Configuration audit is unavailable"
        detail={getApiErrorMessage(results.error)}
        onRetry={() => void results.refetch()}
      />
    );
  }

  const compliance = results.data?.compliance;
  if (!compliance) {
    return (
      <div className="space-y-8">
        <PageHeader eyebrow="Configuration audit" title="No audit returned." answer="The analysis result did not include a configuration audit." />
        <InlineNotice>Not returned by the API</InlineNotice>
      </div>
    );
  }

  const findings = compliance.findings ?? [];
  const critical = findings.filter((finding) => finding.severity?.toUpperCase() === "CRITICAL").length;
  const high = findings.filter((finding) => finding.severity?.toUpperCase() === "HIGH").length;
  const indeterminate = compliance.overall_score === null;
  const answer = indeterminate
    ? compliance.indeterminate_reason ?? "Not assessable: no IKE handshake in this capture."
    : `Grade ${compliance.grade}. ${critical} critical, ${high} high findings identified.`;

  return (
    <div className="space-y-8 motion-enter">
      <PageHeader
        eyebrow="Configuration verdict"
        title={indeterminate ? "Not assessable." : `RFC Security Grade: ${compliance.grade}`}
        answer={answer}
        actions={<JsonExport captureId={captureId} compliance={compliance} />}
      />

      {/* Hero Score Gauge Banner */}
      {!indeterminate && compliance.overall_score !== null && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6 rounded-2xl border border-rule bg-surface p-6 sm:p-8 shadow-sm">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-rule/80 bg-sunken/60 px-3 py-1 font-mono text-xs text-muted">
              <span>RFC 8221 (ESP) · RFC 8247 (IKEv2) · NIST SP 800-77 Rev. 1</span>
            </div>

            <h2 className="text-xl sm:text-2xl font-bold text-ink">
              Compliance Posture: {compliance.overall_score >= 80 ? "Fully Compliant" : compliance.overall_score >= 50 ? "Sub-optimal / Legacy" : "Severe Security Vulnerabilities"}
            </h2>

            <p className="text-xs sm:text-sm text-muted max-w-xl leading-relaxed">
              {compliance.summary ?? answer}
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <RiskBadge level={critical > 0 ? "CRITICAL" : high > 0 ? "HIGH" : "LOW"} size="md" />
              <span className="font-mono text-xs text-muted">
                {findings.length} findings · {compliance.threat_matrix?.length ?? 0} ATT&amp;CK techniques
              </span>
            </div>
          </div>

          <div className="shrink-0">
            <ScoreGauge
              score={compliance.overall_score}
              grade={compliance.grade}
              label="Audit Score"
              size={170}
            />
          </div>
        </div>
      )}

      {/* Indeterminate State Diagnostic Banner */}
      {indeterminate && (
        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-6 sm:p-8 space-y-4 shadow-sm">
          <div className="inline-flex items-center gap-2 rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 font-mono text-xs font-semibold text-amber-600 dark:text-amber-400">
            <span>ESP Mid-Stream Session · IKE Key Exchange Absent</span>
          </div>

          <h2 className="text-xl sm:text-2xl font-bold text-ink">
            Compliance Posture: Indeterminate
          </h2>

          <p className="text-xs sm:text-sm text-muted max-w-2xl leading-relaxed">
            {compliance.indeterminate_reason ?? "This capture contains active ESP tunnel payload packets, but does not include the initial IKE SA negotiation handshake (UDP 500/4500). Because encryption transforms, integrity algorithms, and DH key-exchange groups are established during the IKE handshake, cryptographic compliance cannot be verified automatically from packet headers alone."}
          </p>

          <div className="pt-2">
            <a
              href="#parameter-sandbox"
              className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-accent-strong transition-colors"
            >
              Test Hypothetical Suite in Sandbox &darr;
            </a>
          </div>
        </div>
      )}

      {/* 1. Detected Cryptographic Parameters Panel (Top Section, with compact PQC) */}
      <DetectedParametersPanel compliance={compliance} />

      {/* 2. Findings Breakdown (only rendered if findings exist or if capture is indeterminate) */}
      {compliance.findings.length > 0 ? (
        <FindingsPanel findings={compliance.findings} onExplain={explainer.open} />
      ) : indeterminate ? (
        <div className="rounded-xl border border-rule bg-surface p-5 text-sm space-y-2">
          <p className="font-semibold text-ink">No Assertable Vulnerabilities (Pre-Handshake Capture)</p>
          <p className="text-muted leading-relaxed">
            Cryptographic algorithms and key lengths are established exclusively inside the IKE handshake. Because this capture began mid-stream, zero vulnerabilities can be asserted deterministically from encrypted packet headers.
          </p>
          <p className="text-xs text-muted">
            To evaluate hypothetical suites (e.g. 3DES, AES-CBC, AES-GCM) or your target strongSwan policy, use the <strong>Parameter Sandbox</strong> below.
          </p>
        </div>
      ) : null}

      {/* 3. MITRE ATT&CK Threat Matrix (Default: Table, with RAG explanation) */}
      <ThreatMatrix items={compliance.threat_matrix ?? []} onExplain={explainer.open} />

      {/* 4. Recommended strongSwan Remediation Policy (Full-width box placed before sandbox, with explain rationale) */}
      <RemediationConfigPanel compliance={compliance} />

      {/* 5. Interactive Parameter Sandbox (Simulate suite with 1h traffic and RAG explain) */}
      <ParameterSandbox onExplain={explainer.open} />

      {/* RAG Explainer Drawer */}
      {explainer.drawer}
    </div>
  );
}
