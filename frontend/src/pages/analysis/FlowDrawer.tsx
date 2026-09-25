import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { Drawer } from "../../components/ui/Drawer";
import { InlineNotice } from "../../components/ui/Primitives";
import RiskBadge from "../../components/RiskBadge";
import SHAPChart from "../../components/SHAPChart";
import { formatPercent } from "../../lib/format";
import { getFlowDisposition, getFlowLabel, getPacketTrace, type FlowResult } from "../../types";

function FlowTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name?: string; value?: number }>; label?: string | number }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="border border-rule bg-surface p-2 text-xs shadow-md rounded">
      <p className="font-mono text-muted">Sample {label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="mt-1 text-ink">
          {entry.name}: <span className="font-mono font-bold">{entry.value ?? "—"}</span>
        </p>
      ))}
    </div>
  );
}

function dispositionText(flow: FlowResult): string {
  const disposition = getFlowDisposition(flow);
  if (disposition === "ABSTAINED") return "Abstained: traffic differs from training data (OOD)";
  if (disposition === "OBFUSCATED") return "Traffic shaping detected (RFC 9347 IP-TFS)";
  if (disposition === "LOW_CONFIDENCE") return "Abstained: low classifier confidence";
  return "Verified Classification";
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-rule/60 bg-sunken/40 p-2.5">
      <dt className="text-[11px] font-mono uppercase text-muted">{label}</dt>
      <dd className="mt-0.5 font-mono text-xs font-semibold text-ink truncate">{value}</dd>
    </div>
  );
}

export function FlowDrawer({ flow, onClose }: { flow: FlowResult | null; onClose: () => void }) {
  const trace = flow ? getPacketTrace(flow) : null;
  const shap = flow?.classification?.shap;
  const traceData = trace
    ? Array.from(
        { length: Math.max(trace.normalized_length.length, trace.log_iat.length) },
        (_, index) => ({
          sample: index + 1,
          length: trace.normalized_length[index],
          timing: trace.log_iat[index],
        })
      )
    : [];

  const confidence = flow?.classification?.calibrated_confidence ?? flow?.classification?.confidence;
  const rawPrediction = flow?.classification?.obfuscation_details?.raw_prediction;

  return (
    <Drawer open={Boolean(flow)} title={flow ? `Flow Inspection: ${flow.flow_id}` : "Flow detail"} onClose={onClose}>
      {flow ? (
        <div className="space-y-6">
          {/* Header */}
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-rule pb-4">
            <div>
              <p className="text-base font-bold text-ink">{getFlowLabel(flow)}</p>
              <p className="mt-0.5 text-xs text-muted">{dispositionText(flow)}</p>
              {rawPrediction && getFlowDisposition(flow) !== "VERIFIED" ? (
                <p className="mt-1 text-xs text-muted">
                  Underlying prediction: <span className="font-mono text-ink font-semibold">{rawPrediction}</span>
                </p>
              ) : null}
            </div>
            <RiskBadge level={flow.risk_level ?? "INFO"} size="sm" />
          </div>

          {/* Details Grid */}
          <dl className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            <Detail label="SPI" value={flow.spi || "—"} />
            <Detail label="Calibrated Conf." value={formatPercent(confidence)} />
            <Detail label="Duration" value={flow.duration_s === undefined ? "—" : `${flow.duration_s.toFixed(2)} s`} />
            <Detail label="Packets" value={flow.packet_count.toLocaleString()} />
            <Detail label="Traffic Shaping" value={getFlowDisposition(flow) === "OBFUSCATED" ? "Detected" : "None"} />
            <Detail label="Protocol" value={flow.protocol ?? "ESP (50)"} />
          </dl>

          {/* Deep SHAP Attribution Chart */}
          <section className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-muted">
                SHAP Local Feature Attribution
              </h3>
              {shap?.base_value !== undefined && (
                <span className="font-mono text-[10px] text-muted">
                  Base value: {shap.base_value.toFixed(3)}
                </span>
              )}
            </div>

            {shap?.shap_values ? (
              <div className="rounded-xl border border-rule bg-canvas p-3">
                <SHAPChart
                  shap_values={shap.shap_values}
                  base_value={shap.base_value}
                  topN={8}
                />
              </div>
            ) : (
              <InlineNotice>SHAP feature weights not returned for this flow.</InlineNotice>
            )}
          </section>

          {/* Normalized Packet Trace */}
          {traceData.length ? (
            <section className="space-y-2">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-muted">
                Normalized Packet Trace (Length &amp; Timing)
              </h3>
              <div className="rounded-xl border border-rule bg-surface p-3 h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={traceData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <CartesianGrid stroke="rgba(128,128,128,0.15)" vertical={false} />
                    <XAxis dataKey="sample" tick={{ fill: "currentColor", fontSize: 10 }} className="text-muted" axisLine={{ stroke: "rgba(128,128,128,0.2)" }} tickLine={false} />
                    <YAxis tick={{ fill: "currentColor", fontSize: 10 }} className="text-muted" axisLine={false} tickLine={false} />
                    <Tooltip content={<FlowTooltip />} cursor={{ stroke: "rgba(255, 255, 255, 0.2)", strokeDasharray: "3 3" }} />
                    <Line type="monotone" dataKey="length" name="Normalized Length" stroke="#3b82f6" strokeWidth={1.5} dot={false} isAnimationActive={false} />
                    <Line type="monotone" dataKey="timing" name="Log Inter-Arrival" stroke="#10b981" strokeWidth={1.5} dot={false} isAnimationActive={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </section>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}
