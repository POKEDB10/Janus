/**
 * components/ScoreGauge.tsx
 * Radial bar chart gauge displaying a 0-100 security score and letter grade.
 */
import React from "react";
import {
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";

interface ScoreGaugeProps {
  score: number;
  grade?: string;
  label?: string;
  /** Diameter of the gauge in pixels (default 180) */
  size?: number;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#10b981"; // emerald
  if (score >= 60) return "#3b82f6"; // blue
  if (score >= 40) return "#f59e0b"; // yellow / amber
  return "#ef4444";                  // red
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  grade,
  label = "Security Score",
  size = 180,
}) => {
  const clamped = Math.min(100, Math.max(0, score));
  const color = scoreColor(clamped);

  const data = [{ value: clamped, fill: color }];

  return (
    <div
      className="flex flex-col items-center justify-center"
      role="img"
      aria-label={`${label}: ${clamped} out of 100`}
    >
      <div style={{ width: size, height: size }} className="relative">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            cx="50%"
            cy="50%"
            innerRadius="70%"
            outerRadius="100%"
            barSize={14}
            data={data}
            startAngle={90}
            endAngle={-270}
          >
            {/* Full-range axis gives the bar a 0-100 scale */}
            <PolarAngleAxis
              type="number"
              domain={[0, 100]}
              angleAxisId={0}
              tick={false}
            />
            {/* Background track */}
            <RadialBar
              background={{ fill: "rgba(255,255,255,0.06)" }}
              dataKey="value"
              angleAxisId={0}
              cornerRadius={8}
            />
          </RadialBarChart>
        </ResponsiveContainer>

        {/* Centred numeric score & grade */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <div className="flex items-baseline gap-1">
            <span
              className="text-3xl font-bold tabular-nums font-mono"
              style={{ color }}
              aria-hidden="true"
            >
              {clamped.toFixed(0)}
            </span>
            {grade && (
              <span
                className="text-lg font-bold font-mono px-1 rounded"
                style={{ color }}
              >
                ({grade})
              </span>
            )}
          </div>
          <span className="text-[10px] text-gray-400" aria-hidden="true">
            / 100
          </span>
        </div>
      </div>
      <p className="mt-2 text-xs text-gray-300 font-medium font-mono uppercase tracking-wider">{label}</p>
    </div>
  );
};

export default ScoreGauge;
