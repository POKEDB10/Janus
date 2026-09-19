import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Drawer } from "../../components/ui/Drawer";
import { InlineNotice, SeverityBadge } from "../../components/ui/Primitives";
import { formatPercent } from "../../lib/format";
import { getFlowDisposition, getFlowLabel, getPacketTrace, type FlowResult } from "../../types";

function FlowTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name?: string; value?: number }>; label?: string | number }) {
  if (!active || !payload?.length) return null;
  return <div className="border border-rule bg-surface px-3 py-2 text-xs shadow-menu"><p className="font-mono text-muted">Sample {label}</p>{payload.map((entry) => <p key={entry.name} className="mt-1 text-ink">{entry.name}: <span className="font-mono">{entry.value ?? "—"}</span></p>)}</div>;
}

function dispositionText(flow: FlowResult): string {
  const disposition = getFlowDisposition(flow);
  if (disposition === "ABSTAINED") return "Abstained: traffic differs from training data";
  if (disposition === "OBFUSCATED") return "Traffic shaping detected";
  if (disposition === "LOW_CONFIDENCE") return "Abstained: low classifier confidence";
  return "Classified";
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 font-mono text-sm text-ink">{value}</dd></div>;
}

export function FlowDrawer({ flow, onClose }: { flow: FlowResult | null; onClose: () => void }) {
  const trace = flow ? getPacketTrace(flow) : null;
  const shap = flow?.classification?.shap;
  const contributions = shap?.contributions?.map((item) => ({ name: item.feature_name, value: Number(item.shap_value.toFixed(3)) }))
    ?? Object.entries(shap?.shap_values ?? {}).map(([name, value]) => ({ name, value: Number(value.toFixed(3)) }));
  const traceData = trace ? Array.from({ length: Math.max(trace.normalized_length.length, trace.log_iat.length) }, (_, index) => ({ sample: index + 1, length: trace.normalized_length[index], timing: trace.log_iat[index] })) : [];
  const confidence = flow?.classification?.calibrated_confidence ?? flow?.classification?.confidence;
  const rawPrediction = flow?.classification?.obfuscation_details?.raw_prediction;

  return (
    <Drawer open={Boolean(flow)} title={flow ? `Flow ${flow.flow_id}` : "Flow detail"} onClose={onClose}>
      {flow ? <div className="space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-rule pb-5">
          <div><p className="text-base font-semibold text-ink">{getFlowLabel(flow)}</p><p className="mt-1 text-sm text-muted">{dispositionText(flow)}</p>{rawPrediction && getFlowDisposition(flow) !== "VERIFIED" ? <p className="mt-1 text-xs text-muted">Top model guess: <span className="font-mono text-ink">{rawPrediction}</span></p> : null}</div>
          <SeverityBadge level={flow.risk_level ?? "INFO"} />
        </div>
        <dl className="grid grid-cols-2 gap-x-5 gap-y-4"><Detail label="SPI" value={flow.spi || "—"} /><Detail label="Calibrated confidence" value={formatPercent(confidence)} />{flow.classification?.raw_confidence !== undefined ? <Detail label="Raw confidence" value={formatPercent(flow.classification.raw_confidence)} /> : null}<Detail label="Duration" value={flow.duration_s === undefined ? "—" : `${flow.duration_s.toFixed(2)} s`} /><Detail label="Packets" value={flow.packet_count.toLocaleString()} /><Detail label="Traffic shaping" value={getFlowDisposition(flow) === "OBFUSCATED" ? "Detected" : "Not detected"} /><Detail label="Protocol" value={flow.protocol ?? "—"} /></dl>
        {contributions.length ? <section aria-labelledby="shap-heading"><h3 id="shap-heading" className="text-sm font-semibold text-ink">SHAP contribution</h3><p className="mt-1 text-xs text-muted">Returned local feature contributions.</p><div className="mt-3 h-64"><ResponsiveContainer width="100%" height="100%"><BarChart data={contributions} layout="vertical" margin={{ top: 0, right: 8, left: 64, bottom: 0 }}><CartesianGrid stroke="rgb(var(--color-rule))" horizontal={false} /><XAxis type="number" tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={false} tickLine={false} /><YAxis dataKey="name" type="category" width={64} tick={{ fill: "rgb(var(--color-muted))", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip content={<FlowTooltip />} cursor={{ fill: "rgb(var(--color-sunken))" }} /><Bar dataKey="value" name="Contribution" fill="rgb(var(--color-accent))" isAnimationActive={false} /></BarChart></ResponsiveContainer></div></section> : <InlineNotice>SHAP contributions not returned by the API.</InlineNotice>}
        {traceData.length ? <section aria-labelledby="trace-heading"><h3 id="trace-heading" className="text-sm font-semibold text-ink">Normalized packet trace</h3><p className="mt-1 text-xs text-muted">Returned normalized length and timing signals.</p><div className="mt-3 h-56"><ResponsiveContainer width="100%" height="100%"><LineChart data={traceData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}><CartesianGrid stroke="rgb(var(--color-rule))" vertical={false} /><XAxis dataKey="sample" tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={{ stroke: "rgb(var(--color-rule))" }} tickLine={false} /><YAxis tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={false} tickLine={false} /><Tooltip content={<FlowTooltip />} /><Line type="linear" dataKey="length" name="Length signal" stroke="rgb(var(--color-accent))" strokeWidth={1.5} dot={false} isAnimationActive={false} /><Line type="linear" dataKey="timing" name="Timing signal" stroke="rgb(var(--color-low))" strokeWidth={1.5} dot={false} isAnimationActive={false} /></LineChart></ResponsiveContainer></div></section> : <InlineNotice>Normalized packet trace not returned by the API.</InlineNotice>}
      </div> : null}
    </Drawer>
  );
}
