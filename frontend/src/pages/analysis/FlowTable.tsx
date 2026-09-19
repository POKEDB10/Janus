import { useMemo, useState } from "react";
import { Download, ChevronLeft, ChevronRight } from "lucide-react";
import { DataTable } from "../../components/ui/DataTable";
import { formatPercent } from "../../lib/format";
import { getFlowDisposition, getFlowLabel, type FlowResult } from "../../types";

type SortColumn = "type" | "confidence" | "spi" | "duration" | "packets" | "shaping" | "state";

function dispositionText(flow: FlowResult): string {
  const disposition = getFlowDisposition(flow);
  if (disposition === "ABSTAINED") return "Abstained: traffic differs from training data";
  if (disposition === "OBFUSCATED") return "Traffic shaping detected";
  if (disposition === "LOW_CONFIDENCE") return "Abstained: low classifier confidence";
  return "Classified";
}

function flowValue(flow: FlowResult, column: SortColumn): string | number {
  if (column === "type") return getFlowLabel(flow);
  if (column === "confidence") return flow.classification?.calibrated_confidence ?? flow.classification?.confidence ?? -1;
  if (column === "spi") return flow.spi ?? "";
  if (column === "duration") return flow.duration_s ?? -1;
  if (column === "packets") return flow.packet_count ?? -1;
  if (column === "shaping") return getFlowDisposition(flow) === "OBFUSCATED" ? 1 : 0;
  return dispositionText(flow);
}

function csvCell(value: string | number | undefined): string { return `"${String(value ?? "").replace(/"/g, '""')}"`; }

function downloadCsv(captureId: string, flows: FlowResult[]) {
  const header = ["flow_id", "traffic_type", "confidence", "spi", "duration_s", "packets", "traffic_shaping", "state", "top_model_guess"];
  const rows = flows.map((flow) => [flow.flow_id, getFlowLabel(flow), flow.classification?.calibrated_confidence ?? flow.classification?.confidence, flow.spi, flow.duration_s, flow.packet_count, getFlowDisposition(flow) === "OBFUSCATED" ? "Detected" : "Not detected", dispositionText(flow), flow.classification?.obfuscation_details?.raw_prediction]);
  const data = [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([data], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `janus-${captureId.replace(/[^a-z0-9._-]/gi, "-") || "flows"}-flows.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

export function FlowTable({ captureId, flows, onInspect }: { captureId: string; flows: FlowResult[]; onInspect: (flow: FlowResult) => void }) {
  const [sortColumn, setSortColumn] = useState<SortColumn>("confidence");
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const sortedFlows = useMemo(() => flows.slice().sort((left, right) => {
    const a = flowValue(left, sortColumn);
    const b = flowValue(right, sortColumn);
    const compared = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b));
    return direction === "asc" ? compared : -compared;
  }), [direction, flows, sortColumn]);
  const pageCount = Math.max(1, Math.ceil(sortedFlows.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visibleFlows = sortedFlows.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const changeSort = (columnId: string) => {
    const column = columnId as SortColumn;
    if (column === sortColumn) setDirection((current) => current === "asc" ? "desc" : "asc");
    else { setSortColumn(column); setDirection("asc"); }
    setPage(0);
  };

  return <div>
    <div className="mb-3 flex flex-wrap items-center justify-between gap-3"><p className="text-xs text-muted">{flows.length.toLocaleString()} returned flow{flows.length === 1 ? "" : "s"}</p><button type="button" onClick={() => downloadCsv(captureId, flows)} className="inline-flex items-center gap-2 text-sm font-medium text-accent hover:text-accent-strong"><Download aria-hidden="true" className="size-4" />Export CSV</button></div>
    <DataTable
      caption="Classified ESP flows"
      rows={visibleFlows}
      getRowKey={(flow) => flow.flow_id}
      sort={{ columnId: sortColumn, direction, onChange: changeSort }}
      columns={[
        { id: "type", label: "Traffic type", sortable: true, render: (flow) => <span>{getFlowLabel(flow)}</span> },
        { id: "confidence", label: "Calibrated confidence", sortable: true, className: "font-mono", render: (flow) => formatPercent(flow.classification?.calibrated_confidence ?? flow.classification?.confidence) },
        { id: "spi", label: "SPI", sortable: true, className: "font-mono", render: (flow) => flow.spi || "—" },
        { id: "duration", label: "Duration", sortable: true, className: "font-mono", render: (flow) => flow.duration_s === undefined ? "—" : `${flow.duration_s.toFixed(2)} s` },
        { id: "packets", label: "Packets", sortable: true, className: "font-mono", render: (flow) => flow.packet_count.toLocaleString() },
        { id: "shaping", label: "Traffic shaping", sortable: true, render: (flow) => <span className="text-muted">{getFlowDisposition(flow) === "OBFUSCATED" ? "Detected" : "Not detected"}</span> },
        { id: "state", label: "State", sortable: true, render: (flow) => <span className="text-muted">{dispositionText(flow)}</span> },
        { id: "detail", label: "", render: (flow) => <button type="button" onClick={() => onInspect(flow)} className="text-sm font-medium text-accent underline underline-offset-4">Inspect</button> },
      ]}
    />
    {pageCount > 1 ? <nav className="mt-4 flex items-center justify-end gap-3" aria-label="Flow pages"><p className="font-mono text-xs text-muted">{currentPage + 1} / {pageCount}</p><button type="button" onClick={() => setPage((value) => Math.max(0, value - 1))} disabled={currentPage === 0} aria-label="Previous page" className="p-1 text-muted hover:text-ink disabled:opacity-40"><ChevronLeft aria-hidden="true" className="size-4" /></button><button type="button" onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))} disabled={currentPage === pageCount - 1} aria-label="Next page" className="p-1 text-muted hover:text-ink disabled:opacity-40"><ChevronRight aria-hidden="true" className="size-4" /></button></nav> : null}
  </div>;
}
