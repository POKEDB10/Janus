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
  value: number;
}

const POSITIVE_COLOR = "#cc3333";
const NEGATIVE_COLOR = "#3366cc";

export const SHAPChart: React.FC<SHAPChartProps> = ({
  shap_values,
  base_value,
  topN = 10,
}) => {
  // Sort features by |shap_value| descending, take topN
  const entries: ShapEntry[] = Object.entries(shap_values)
    .map(([feature, value]) => ({ feature, value }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, topN);

  return (
    <div
      aria-label="SHAP feature contribution chart"
      role="img"
      className="w-full"
    >
      <ResponsiveContainer width="100%" height={300}>
        <BarChart
          data={entries}
          layout="vertical"
          margin={{ top: 10, right: 20, left: 120, bottom: 10 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
          <XAxis
            type="number"
            stroke="#9ca3af"
            tick={{ fill: "#9ca3af", fontSize: 11 }}
            tickFormatter={(v: number) => v.toFixed(3)}
          />
          <YAxis
            type="category"
            dataKey="feature"
            width={115}
            stroke="#9ca3af"
            tick={{ fill: "#9ca3af", fontSize: 11 }}
          />
          <Tooltip
            formatter={(value: number) => [value.toFixed(4), "SHAP value"]}
            contentStyle={{
              backgroundColor: "#1a2332",
              border: "1px solid rgba(255,255,255,0.15)",
              borderRadius: 6,
              color: "#f3f4f6",
            }}
          />
          {/* Base value reference line */}
          <ReferenceLine
            x={base_value}
            stroke="#fbbf24"
            strokeDasharray="4 3"
            label={{
              value: `base ${base_value.toFixed(3)}`,
              position: "insideTopRight",
              fill: "#fbbf24",
              fontSize: 10,
            }}
          />
          <ReferenceLine x={0} stroke="rgba(255,255,255,0.2)" />
          <Legend
            verticalAlign="top"
            content={() => (
              <div className="flex gap-4 text-xs text-gray-400 mb-1 ml-32">
                <span className="flex items-center gap-1">
                  <span className="inline-block w-3 h-3 rounded-sm" style={{ background: POSITIVE_COLOR }} />
                  Increases prediction
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block w-3 h-3 rounded-sm" style={{ background: NEGATIVE_COLOR }} />
                  Decreases prediction
                </span>
              </div>
            )}
          />
          <Bar dataKey="value" radius={[0, 3, 3, 0]}>
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
