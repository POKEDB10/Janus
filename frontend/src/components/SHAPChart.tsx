/**
 * components/SHAPChart.tsx
 * Waterfall-style bar chart visualising SHAP feature contributions.
 *
 * Positive values (push towards predicted class) → red/coral bars.
 * Negative values (push away from predicted class) → blue/sky bars.
 * Features are sorted by absolute SHAP value descending.
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
  Legend,
} from "recharts";

interface SHAPChartProps {
  shap_values: Record<string, number>;
  base_value?: number;
  /** Max number of features to display (default 10) */
  topN?: number;
}

interface ShapEntry {
  feature: string;
  label: string;
  value: number;
}

const POSITIVE_COLOR = "#ef4444"; // high-contrast vibrant red
const NEGATIVE_COLOR = "#0ea5e9"; // high-contrast vibrant cyan/sky

const FEATURE_PRETTY_NAMES: Record<string, string> = {
  iat_mean: "IAT Mean (s)",
  pkt_len_iqr: "Packet Len IQR (B)",
  burst_len_mean: "Burst Len Mean",
  burst_len_max: "Burst Len Max",
  pkt_len_mean: "Packet Len Mean (B)",
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

export const SHAPChart: React.FC<SHAPChartProps> = ({
  shap_values,
  base_value = 0,
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
    .map(([feature, value]) => ({
      feature,
      label: formatFeatureName(feature),
      value: typeof value === "number" ? value : parseFloat(String(value)) || 0,
    }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, topN);

  return (
    <div
      aria-label="SHAP feature contribution chart"
      role="img"
      className="w-full"
    >
      <ResponsiveContainer width="100%" height={280}>
        <BarChart
          data={entries}
          layout="vertical"
          margin={{ top: 10, right: 30, left: 140, bottom: 5 }}
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
            width={130}
            stroke="currentColor"
            className="text-ink text-xs font-medium"
          />
          <Tooltip
            cursor={false}
            formatter={(value: number) => [
              value > 0 ? `+${value.toFixed(4)} (Increases likelihood)` : `${value.toFixed(4)} (Decreases likelihood)`,
              "SHAP Impact",
            ]}
            contentStyle={{
              backgroundColor: "rgba(15, 23, 42, 0.95)",
              border: "1px solid rgba(255,255,255,0.15)",
              borderRadius: 6,
              color: "#ffffff",
              fontSize: 12,
            }}
          />
          {/* Base value reference line */}
          {base_value !== 0 && (
            <ReferenceLine
              x={base_value}
              stroke="#f59e0b"
              strokeDasharray="4 3"
              strokeWidth={1.5}
              label={{
                value: `Base: ${base_value.toFixed(2)}`,
                position: "insideTopRight",
                fill: "#f59e0b",
                fontSize: 10,
              }}
            />
          )}
          <ReferenceLine x={0} stroke="rgba(128,128,128,0.3)" />
          <Legend
            verticalAlign="top"
            content={() => (
              <div className="flex gap-4 text-xs text-muted mb-2 justify-end font-medium">
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-2.5 h-2.5 rounded-sm bg-red-500" />
                  Pushes Toward Prediction (+)
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-2.5 h-2.5 rounded-sm bg-sky-500" />
                  Pushes Away (-)
                </span>
              </div>
            )}
          />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} isAnimationActive={true} animationDuration={600}>
            {entries.map((entry) => (
              <Cell
                key={entry.feature}
                fill={entry.value >= 0 ? POSITIVE_COLOR : NEGATIVE_COLOR}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SHAPChart;
