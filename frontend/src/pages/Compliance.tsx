import { useLocation, useParams } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { getApiErrorMessage } from "../lib/api-error";
import { ErrorState, InlineNotice, LoadingState, PageHeader } from "../components/ui/Primitives";
import { FindingsPanel } from "./compliance/FindingsPanel";
import { PqcPanel } from "./compliance/PqcPanel";
import { RemediationPanel } from "./compliance/RemediationPanel";
import { ParameterSandbox } from "./compliance/ParameterSandbox";
import { ThreatMatrix } from "./compliance/ThreatMatrix";

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

      {compliance.findings.length ? <FindingsPanel findings={compliance.findings} /> : <InlineNotice>No findings returned by the API.</InlineNotice>}
      <PqcPanel compliance={compliance} />
      <ThreatMatrix items={compliance.threat_matrix ?? []} />
      <ParameterSandbox />
    </div>
  );
}
