import { useLocation, useParams } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { DataTable } from "../components/ui/DataTable";
import { EmptyState, ErrorState, LoadingState, PageHeader, Section, SeverityBadge } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { getFlowDisposition, getFlowLabel, type FlowResult } from "../types";

function dispositionText(flow: FlowResult) {
  const disposition = getFlowDisposition(flow);
  if (disposition === "ABSTAINED") return "Abstained: traffic differs from training data";
  if (disposition === "OBFUSCATED") return "Traffic shaping detected";
  if (disposition === "LOW_CONFIDENCE") return "Abstained: low classifier confidence";
  return "Classified";
}

export default function Analysis() {
  const { captureId = "" } = useParams();
  const { search } = useLocation();
  const results = useCaptureResults(captureId, search);

  if (results.isPending) return <LoadingState label="Loading traffic classification…" />;
  if (results.isError) return <ErrorState title="Traffic classification is unavailable" detail={getApiErrorMessage(results.error)} onRetry={() => void results.refetch()} />;

  const data = results.data;
  if (!data) return null;
  const abstained = data.flows.filter((flow) => getFlowDisposition(flow) === "ABSTAINED" || getFlowDisposition(flow) === "LOW_CONFIDENCE").length;
  const shaped = data.flows.filter((flow) => getFlowDisposition(flow) === "OBFUSCATED").length;

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Traffic classification"
        title={`${data.total_flows} ESP flows analyzed.`}
        answer={`${abstained} abstained, ${shaped} with traffic shaping detected. Review the classifier decision for each flow below.`}
      />
      {data.flows.length === 0 ? <EmptyState title="No flows returned" detail="The analysis result did not include ESP flow classifications." /> : (
        <Section title="Flows" detail="Results returned by the statistical ESP classifier.">
          <DataTable
            caption="Classified ESP flows"
            rows={data.flows}
            getRowKey={(flow) => flow.flow_id}
            columns={[
              { id: "type", label: "Traffic type", render: (flow) => <span>{getFlowLabel(flow)}</span> },
              { id: "confidence", label: "Confidence", className: "font-mono", render: (flow) => flow.classification?.confidence === undefined ? "—" : `${(flow.classification.confidence * 100).toFixed(0)}%` },
              { id: "spi", label: "SPI", className: "font-mono", render: (flow) => flow.spi || "—" },
              { id: "packets", label: "Packets", className: "font-mono", render: (flow) => flow.packet_count.toLocaleString() },
              { id: "state", label: "State", render: (flow) => <span className="text-muted">{dispositionText(flow)}</span> },
              { id: "risk", label: "Risk", render: (flow) => <SeverityBadge level={flow.risk_level ?? "INFO"} /> },
            ]}
          />
        </Section>
      )}
    </div>
  );
}
