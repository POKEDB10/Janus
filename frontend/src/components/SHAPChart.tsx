/**
 * components/SHAPChart.tsx
 * Waterfall-style bar chart visualising SHAP feature contributions.
 *
 * Positive values (push towards predicted class) → red bars.
 * Negative values (push away from predicted class) → blue bars.
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
  base_value: number;
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
};

function formatFeatureName(raw: string): string {
  if (FEATURE_PRETTY_NAMES[raw]) return FEATURE_PRETTY_NAMES[raw];
  return raw
    .replace(/_/g, " ")
    .replace(/\b\w/g, (l) => l.toUpperCase());
}

export const SHAPChart: React.FC<SHAPChartProps> = ({
  shap_values,
  base_value,
  topN = 10,
}) => {
  // Sort features by |shap_value| descending, take topN
  const entries: ShapEntry[] = Object.entries(shap_values)
    .map(([feature, value]) => ({
      feature,
      label: formatFeatureName(feature),
      value,
    }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, topN);

  return (
    <div
      aria-label="SHAP feature contribution chart"
      role="img"
      className="w-full"
    >
      <ResponsiveContainer width="100%" height={320}>
        <BarChart
          data={entries}
          layout="vertical"
          margin={{ top: 15, right: 30, left: 165, bottom: 10 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis
            type="number"
            stroke="#cbd5e1"
            tick={{ fill: "#cbd5e1", fontSize: 11 }}
            tickFormatter={(v: number) => v.toFixed(3)}
          />
          <YAxis
            type="category"
            dataKey="label"
            width={155}
            stroke="#cbd5e1"
            tick={{ fill: "#f1f5f9", fontSize: 11, fontWeight: 500 }}
          />
          <Tooltip
            formatter={(value: number) => [
              value > 0 ? `+${value.toFixed(4)} (Increases)` : `${value.toFixed(4)} (Decreases)`,
              "SHAP Value",
            ]}
            contentStyle={{
              backgroundColor: "#0f172a",
              border: "1px solid rgba(255,255,255,0.2)",
              borderRadius: 8,
              color: "#ffffff",
              fontSize: 12,
              boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)",
            }}
            itemStyle={{ color: "#38bdf8", fontWeight: "bold" }}
            labelStyle={{ color: "#ffffff", fontWeight: "bold" }}
          />
          {/* Base value reference line */}
          <ReferenceLine
            x={base_value}
            stroke="#f59e0b"
            strokeDasharray="4 3"
            strokeWidth={1.5}
            label={{
              value: `Base: ${base_value.toFixed(3)}`,
              position: "insideTopRight",
              fill: "#f59e0b",
              fontSize: 11,
              fontWeight: "bold",
            }}
          />
          <ReferenceLine x={0} stroke="rgba(255,255,255,0.3)" />
          <Legend
            verticalAlign="top"
            content={() => (
              <div className="flex gap-5 text-xs text-gray-300 mb-2 ml-44 font-medium">
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-3 h-3 rounded-sm bg-red-500" />
                  Pushes Toward Prediction (+)
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-3 h-3 rounded-sm bg-sky-500" />
                  Pushes Away from Prediction (-)
                </span>
              </div>
            )}
          />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} isAnimationActive={false}>
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
