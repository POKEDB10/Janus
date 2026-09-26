/**
 * components/SHAPChart.tsx
 * Diverging bar chart visualising SHAP feature contributions.
 *
 * Positive values (push towards predicted class) → red/coral bars.
 * Negative values (push away from predicted class) → blue/sky bars.
 * Features are sorted by absolute SHAP value descending.
 *
 * Design decisions:
 * - Bars start at x=0 (simple diverging chart — no waterfall/cumulative-from-base).
 * - base_value is shown ONCE in the FlowDrawer header stat area (not here).
 * - Static end-of-bar labels render the value without requiring hover.
 * - Tooltip is custom: constrained width, never clips below the visible area.
 */
import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  Cell,
  ResponsiveContainer,
  LabelList,
} from "recharts";

interface SHAPChartProps {
  shap_values: Record<string, number>;
  base_value?: number;
  /** Max number of features to display (default 8) */
  topN?: number;
}

interface ShapEntry {
  feature: string;
  label: string;
  value: number;
  displayValue: string;
}

const POSITIVE_COLOR = "#ef4444"; // vibrant red — pushes toward prediction
const NEGATIVE_COLOR = "#0ea5e9"; // vibrant cyan/sky — pushes away

const FEATURE_PRETTY_NAMES: Record<string, string> = {
  iat_mean: "IAT Mean (s)",
  pkt_len_iqr: "Packet Len IQR (bytes)",  // was (B) — spelled out for clarity
  burst_len_mean: "Burst Len Mean",
  burst_len_max: "Burst Len Max",
  pkt_len_mean: "Packet Len Mean (bytes)",
  byte_rate_bps: "Byte Rate (bps)",
  forward_byte_ratio: "Fwd Byte Ratio",
  forward_packet_ratio: "Fwd Packet Ratio",
  pkt_len_var: "Packet Len Variance",
  iat_cv: "IAT Coeff. Var",
  iat_max: "IAT Max (s)",
  burst_count: "Burst Count",
  iat_var: "IAT Variance",
  burst_bytes_mean: "Burst Bytes Mean",
  pkt_len_std: "Packet Len Std",
  iat_min: "IAT Min (s)",
};

function formatFeatureName(raw: string): string {
  if (FEATURE_PRETTY_NAMES[raw]) return FEATURE_PRETTY_NAMES[raw];
  return raw
    .replace(/_/g, " ")
    .replace(/\b\w/g, (l) => l.toUpperCase());
}

/** Format a SHAP value as a signed string with consistent 2 decimal places. */
function fmtShap(v: number): string {
  return (v >= 0 ? "+" : "") + v.toFixed(2);
}

/** Custom tooltip that constrains width and wraps text so it never clips. */
const CustomTooltip = ({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload: ShapEntry }>;
}) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  const isPositive = d.value >= 0;

  return (
    <div
      style={{
        backgroundColor: "rgba(15, 23, 42, 0.97)",
        border: "1px solid rgba(255,255,255,0.15)",
        borderRadius: 6,
        padding: "8px 10px",
        fontSize: 11,
        maxWidth: 200,
        whiteSpace: "normal",
        wordBreak: "break-word",
        lineHeight: 1.5,
        pointerEvents: "none",
        zIndex: 9999,
        color: "#fff",
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 4, color: isPositive ? "#ef4444" : "#0ea5e9" }}>
        {d.displayValue}
      </div>
      <div style={{ color: "rgba(255,255,255,0.7)" }}>
        {d.label}
      </div>
      <div style={{ color: "rgba(255,255,255,0.55)", marginTop: 2, fontSize: 10 }}>
        {isPositive ? "Increases classification likelihood" : "Decreases classification likelihood"}
      </div>
    </div>
  );
};

export const SHAPChart: React.FC<SHAPChartProps> = ({
  shap_values,
  topN = 8,
}) => {
  if (!shap_values || Object.keys(shap_values).length === 0) {
    return (
      <div className="p-4 text-center text-xs text-muted font-mono">
        No SHAP attribution values available for this flow.
      </div>
    );
  }

  // Sort features by |shap_value| descending, take topN
  const entries: ShapEntry[] = Object.entries(shap_values)
    .map(([feature, value]) => {
      const v = typeof value === "number" ? value : parseFloat(String(value)) || 0;
      return {
        feature,
        label: formatFeatureName(feature),
        value: v,
        displayValue: fmtShap(v),
      };
    })
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, topN);

  // Dynamic right margin: enough for the end-of-bar "+0.44" label (~48px)
  const RIGHT_MARGIN = 52;

  return (
    <div
      aria-label="SHAP feature contribution chart"
      role="img"
      className="w-full"
    >
      {/* Legend */}
      <div className="flex gap-4 text-xs text-muted mb-3 justify-end font-medium">
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-sm bg-red-500" />
          Increases prediction (+)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-sm bg-sky-500" />
          Decreases prediction (−)
        </span>
      </div>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart
          data={entries}
          layout="vertical"
          margin={{ top: 4, right: RIGHT_MARGIN, left: 148, bottom: 4 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" />
          <XAxis
            type="number"
            stroke="currentColor"
            className="text-muted text-[11px]"
            tickFormatter={(v: number) => v.toFixed(2)}
          />
          <YAxis
            type="category"
            dataKey="label"
            width={140}
            stroke="currentColor"
            className="text-ink text-xs font-medium"
            tick={{ fontSize: 11 }}
          />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.06)" }}
            content={<CustomTooltip />}
            wrapperStyle={{ pointerEvents: "none", zIndex: 1000 }}
          />
          {/* Zero reference line — bars diverge from 0, no base-value line */}
          <ReferenceLine x={0} stroke="rgba(128,128,128,0.35)" />
          <Bar
            dataKey="value"
            radius={[0, 4, 4, 0]}
            isAnimationActive={true}
            animationDuration={500}
          >
            {entries.map((entry) => (
              <Cell
                key={entry.feature}
                fill={entry.value >= 0 ? POSITIVE_COLOR : NEGATIVE_COLOR}
              />
            ))}
            {/* Static end-of-bar labels — value visible without hover */}
            <LabelList
              dataKey="displayValue"
              position="right"
              style={{ fontSize: 10, fontFamily: "monospace", fill: "currentColor" }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SHAPChart;
