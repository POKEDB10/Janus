import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Section } from "../../components/ui/Primitives";
import type { FlowResult } from "../../types";

const TRAFFIC_COLORS: Record<string, string> = {
  VoIP: "#10b981",       // emerald
  Video: "#3b82f6",      // blue
  Web: "#8b5cf6",        // purple
  Email: "#f59e0b",      // amber
  ICMP: "#06b6d4",       // cyan
  Obfuscated: "#ec4899", // pink
  Unknown: "#64748b",    // slate
};

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name?: string; value?: number }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="border border-rule bg-surface p-2.5 text-xs shadow-md rounded-md">
      <p className="font-mono text-muted">{label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="mt-1 text-ink font-medium flex items-center justify-between gap-3">
          <span>{entry.name}:</span>
          <span className="font-mono font-bold">{entry.value ?? "—"}</span>
        </p>
      ))}
    </div>
  );
}

export function TrafficCharts({ distribution, flows }: { distribution?: Record<string, number>; flows: FlowResult[] }) {
  const distributionData = Object.entries(distribution ?? {})
    .filter(([, count]) => count > 0)
    .map(([name, count]) => ({
      name,
      value: count,
      color: TRAFFIC_COLORS[name] || "#3b82f6",
    }));

  const confidenceData = flows.flatMap((flow, index) => {
    const confidence = flow.classification?.calibrated_confidence ?? flow.classification?.confidence;
    return confidence === undefined
      ? []
      : [{ flow: `Flow ${index + 1}`, confidence: Number((confidence * 100).toFixed(1)) }];
  });

  const totalFlows = distributionData.reduce((acc, d) => acc + d.value, 0);

  if (!distributionData.length && !confidenceData.length) return null;

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* Traffic Distribution Donut / Pie Chart */}
      <Section
        title="Traffic Distribution"
        detail={`${totalFlows} classified ESP flows by statistical application profile.`}
        isEmpty={!distributionData.length}
      >
        <div className="flex flex-col sm:flex-row items-center gap-4 h-64">
          <div className="h-full w-full sm:w-3/5">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Tooltip content={<ChartTooltip />} />
                <Pie
                  data={distributionData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={3}
                  isAnimationActive={true}
                  animationDuration={800}
                >
                  {distributionData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Custom Legend */}
          <div className="flex flex-wrap sm:flex-col gap-2 text-xs font-mono w-full sm:w-2/5">
            {distributionData.map((item) => (
              <div key={item.name} className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5 text-muted">
                  <span className="size-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span>{item.name}</span>
                </span>
                <span className="font-bold text-ink">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* Confidence per flow Line Chart */}
      <Section
        title="Classifier Confidence"
        detail="Confidence percentage returned per flow index."
        isEmpty={!confidenceData.length}
      >
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={confidenceData} margin={{ top: 12, right: 12, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="rgba(128,128,128,0.15)" vertical={false} />
              <XAxis dataKey="flow" tick={{ fill: "currentColor", fontSize: 11 }} className="text-muted" axisLine={{ stroke: "rgba(128,128,128,0.2)" }} tickLine={false} />
              <YAxis domain={[0, 100]} unit="%" tick={{ fill: "currentColor", fontSize: 11 }} className="text-muted" axisLine={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Line
                type="monotone"
                dataKey="confidence"
                name="Confidence"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={{ r: 3, fill: "#3b82f6" }}
                activeDot={{ r: 5 }}
                isAnimationActive={true}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Section>
    </div>
  );
}
