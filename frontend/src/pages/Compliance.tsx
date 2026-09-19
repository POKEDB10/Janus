import { useLocation, useParams } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { getApiErrorMessage } from "../lib/api-error";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section, SeverityBadge } from "../components/ui/Primitives";
import { RemediationPanel } from "./compliance/RemediationPanel";

export default function Compliance() {
  const { captureId = "" } = useParams();
  const { search } = useLocation();
  const results = useCaptureResults(captureId, search);

  if (results.isPending) {
    return <LoadingState label="Loading configuration audit…" />;
  }

  if (results.isError) {
    return <ErrorState title="Configuration audit is unavailable" detail={getApiErrorMessage(results.error)} onRetry={() => void results.refetch()} />;
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

  const critical = compliance.findings.filter((finding) => finding.severity.toUpperCase() === "CRITICAL").length;
  const high = compliance.findings.filter((finding) => finding.severity.toUpperCase() === "HIGH").length;
  const indeterminate = compliance.overall_score === null || compliance.grade === "N/A";
  const answer = indeterminate
    ? compliance.indeterminate_reason ?? "Not assessable: no IKE handshake in this capture."
    : `Grade ${compliance.grade}. ${critical} critical, ${high} high findings.${compliance.remediation_config ? " A remediation config is available." : ""}`;

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Configuration verdict"
        title={indeterminate ? "Not assessable." : `Grade ${compliance.grade}.`}
        answer={answer}
      />

      {indeterminate ? (
        <InlineNotice>{compliance.indeterminate_reason ?? "Not assessable: no IKE handshake in this capture."}</InlineNotice>
      ) : null}

      <RemediationPanel compliance={compliance} />

      {compliance.findings.length === 0 ? <InlineNotice>No findings returned by the API.</InlineNotice> : (
        <Section title="Findings" detail="Reported directly by the completed analysis.">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] border-collapse text-left text-sm">
              <thead className="border-b border-rule font-mono text-xs text-muted">
                <tr><th className="px-2 py-2 font-medium">Severity</th><th className="px-2 py-2 font-medium">Rule</th><th className="px-2 py-2 font-medium">Parameter</th><th className="px-2 py-2 font-medium">Finding</th></tr>
              </thead>
              <tbody>
                {compliance.findings.map((finding) => (
                  <tr key={`${finding.rule_id}-${finding.parameter}`} className="border-b border-rule/70 align-top">
                    <td className="px-2 py-3"><SeverityBadge level={finding.severity} /></td>
                    <td className="px-2 py-3 font-mono text-xs text-ink">{finding.rule_id}</td>
                    <td className="px-2 py-3 font-mono text-xs text-ink">{finding.parameter}</td>
                    <td className="px-2 py-3 text-muted">{finding.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {compliance.pqc_status ? (
        <Section title="Post-quantum readiness">
          <p className="text-sm text-ink">{compliance.pqc_status}</p>
          {compliance.pqc_advisory ? <p className="mt-1 text-sm text-muted">{compliance.pqc_advisory}</p> : null}
        </Section>
      ) : null}
    </div>
  );
}
