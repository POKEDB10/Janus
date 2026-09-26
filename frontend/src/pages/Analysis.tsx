import { useLocation, useParams } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { getFlowDisposition, type FlowResult } from "../types";
import { FlowDrawer } from "./analysis/FlowDrawer";
import { FlowTable } from "./analysis/FlowTable";
import { TrafficCharts } from "./analysis/TrafficCharts";

export default function Analysis() {
  const { captureId = "" } = useParams();
  const { search } = useLocation();
  const results = useCaptureResults(captureId, search);
  const [selectedFlow, setSelectedFlow] = useState<FlowResult | null>(null);

  if (results.isPending) return <LoadingState label="Loading traffic classification…" />;
  if (results.isError) return <ErrorState title="Traffic classification is unavailable" detail={getApiErrorMessage(results.error)} onRetry={() => void results.refetch()} />;

  const data = results.data;
  if (!data) return null;
  const flows = data.flows ?? [];
  const abstained = flows.filter((flow) => getFlowDisposition(flow) === "ABSTAINED" || getFlowDisposition(flow) === "LOW_CONFIDENCE").length;
  const shaped = flows.filter((flow) => getFlowDisposition(flow) === "OBFUSCATED").length;

  return (
    <div className="space-y-6 motion-enter">
      {/* Operational context bar — differentiated from marketing hero */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-rule text-xs text-muted">
        <div className="flex items-center gap-3">
          <span className="font-semibold text-ink font-mono">{data.total_flows ?? flows.length} flows analyzed</span>
          <span className="text-rule">/</span>
          <span>{abstained} abstained</span>
          <span className="text-rule">/</span>
          <span>{shaped} traffic shaping detected</span>
        </div>
        <p className="text-[11px] font-mono text-muted">
          Statistical side-channel classification (zero IP/port feature bias)
        </p>
      </div>

      {flows.length === 0 ? (
        <EmptyState title="No flows returned" detail="The analysis result did not include ESP flow classifications." />
      ) : (
        <>
          <TrafficCharts distribution={data.traffic_distribution} flows={flows} />
          <Section title="Flow Telemetry &amp; Classification" detail="Extracted packet distributions, calibrated predictions, and SHAP attribution.">
            <FlowTable captureId={captureId} flows={flows} onInspect={setSelectedFlow} />
          </Section>
          <FlowDrawer flow={selectedFlow} onClose={() => setSelectedFlow(null)} />
        </>
      )}
    </div>
  );
}
