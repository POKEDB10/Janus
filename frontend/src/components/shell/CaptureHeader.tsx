import { NavLink, useLocation } from "react-router-dom";
import { useCaptureResults } from "../../api/queries";
import { getCaptureContext, isRecordedSample } from "../../lib/capture-session";
import { getFlowDisposition } from "../../types";
import { LoadingState, SampleStamp } from "../ui/Primitives";
import { VerdictPair } from "../ui/VerdictPair";

const workspaceTabs = [
  { segment: "analysis", label: "Flows" },
  { segment: "compliance", label: "Compliance" },
  { segment: "report", label: "Report" },
];

export function CaptureHeader({ captureId }: { captureId: string }) {
  const { search } = useLocation();
  const recorded = isRecordedSample(search);
  const context = getCaptureContext(captureId);
  const results = useCaptureResults(captureId, search);

  if (results.isPending) return <><>{recorded && <SampleStamp />}</><div className="border-b border-rule bg-surface"><div className="mx-auto max-w-content px-4 sm:px-6"><LoadingState label="Loading capture verdicts…" /></div></div></>;
  if (results.isError) {
    if (recorded) {
      return <><SampleStamp /><div className="border-b border-rule bg-surface"><div className="mx-auto max-w-content px-4 py-4 sm:px-6"><p className="font-mono text-xs text-muted">Capture {captureId}</p><p className="mt-1 text-sm text-muted">Recorded sample requested, but no recorded fixture is installed.</p></div></div></>;
    }
    return null;
  }

  const data = results.data;
  if (!data) return null;
  const compliance = data.compliance;
  const critical = compliance?.findings.filter((finding) => finding.severity.toUpperCase() === "CRITICAL").length ?? 0;
  const high = compliance?.findings.filter((finding) => finding.severity.toUpperCase() === "HIGH").length ?? 0;
  const abstained = data.flows.filter((flow) => {
    const disposition = getFlowDisposition(flow);
    return disposition === "ABSTAINED" || disposition === "LOW_CONFIDENCE";
  }).length;
  const obfuscated = data.flows.filter((flow) => getFlowDisposition(flow) === "OBFUSCATED").length;
  const trafficMix = Object.values(data.traffic_distribution ?? {}).filter((count) => count > 0).length;
  const reason = compliance?.overall_score === null
    ? compliance.indeterminate_reason ?? data.reason ?? "Not assessable: no IKE handshake in this capture."
    : undefined;

  const isCleartext = compliance?.evaluated_parameters?.esp_encryption?.toString().toLowerCase().includes("cleartext") ||
    compliance?.findings?.some((f) => f.rule_id?.includes("CLEARTEXT") || f.parameter?.toLowerCase().includes("cleartext")) ||
    (data.flows.length > 0 && !data.ike_sessions.length && compliance?.overall_score === 0.0);

  return (
    <>{recorded && <SampleStamp />}<div className="bg-surface">
      <div className="mx-auto max-w-content px-4 py-4 sm:px-6">
        <div className="mb-4 flex flex-wrap items-baseline gap-x-4 gap-y-1">
          <p className="font-medium text-ink">{data.filename ?? context.filename ?? "Capture"}</p>
          <p className="font-mono text-xs text-muted">{captureId}</p>
        </div>
        <VerdictPair
          configuration={{ score: compliance?.overall_score ?? null, grade: compliance?.grade ?? "—", reason, critical, high }}
          traffic={{ flows: data.total_flows, mix: trafficMix, abstained, obfuscated, trafficType: isCleartext ? "Cleartext IP" : "ESP" }}
        />
        <nav className="mt-3 flex gap-4" aria-label="Capture workspace">
          {workspaceTabs.map((tab) => (
            <NavLink
              key={tab.segment}
              to={`/${tab.segment}/${encodeURIComponent(captureId)}${search}`}
              className={({ isActive }) =>
                `border-b-2 px-1 pb-2 text-sm font-medium transition-all duration-200 cursor-pointer ${
                  isActive
                    ? "border-accent text-ink font-semibold"
                    : "border-transparent text-muted hover:border-rule hover:text-ink"
                }`
              }
            >
              {tab.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </div></>
  );
}
