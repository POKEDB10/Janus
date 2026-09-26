import { useLocation, useParams } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
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
    <div className="space-y-8 motion-enter">
      <PageHeader
        eyebrow="Traffic classification"
        title={`${data.total_flows ?? flows.length} ESP flows analyzed.`}
        answer={`${abstained} abstained, ${shaped} with traffic shaping detected. Review the classifier decision for each flow below.`}
      />
      {flows.length === 0 ? (
        <EmptyState title="No flows returned" detail="The analysis result did not include ESP flow classifications." />
      ) : (
        <>
          <TrafficCharts distribution={data.traffic_distribution} flows={flows} />
          <Section title="Flows" detail="Results returned by the statistical ESP classifier.">
            <FlowTable captureId={captureId} flows={flows} onInspect={setSelectedFlow} />
          </Section>
          <FlowDrawer flow={selectedFlow} onClose={() => setSelectedFlow(null)} />
        </>
      )}
    </div>
  );
}
