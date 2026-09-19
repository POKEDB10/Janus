import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Section } from "../../components/ui/Primitives";
import type { FlowResult } from "../../types";

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name?: string; value?: number }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return <div className="border border-rule bg-surface px-3 py-2 text-xs shadow-menu"><p className="font-mono text-muted">{label}</p>{payload.map((entry) => <p key={entry.name} className="mt-1 text-ink">{entry.name}: <span className="font-mono">{entry.value ?? "—"}</span></p>)}</div>;
}

export function TrafficCharts({ distribution, flows }: { distribution?: Record<string, number>; flows: FlowResult[] }) {
  const distributionData = Object.entries(distribution ?? {}).filter(([, count]) => count > 0).map(([name, count]) => ({ name, count }));
  const confidenceData = flows.flatMap((flow, index) => {
    const confidence = flow.classification?.calibrated_confidence ?? flow.classification?.confidence;
    return confidence === undefined ? [] : [{ flow: `Flow ${index + 1}`, confidence: Number((confidence * 100).toFixed(1)) }];
  });
  const distributionSummary = distributionData.map(({ name, count }) => `${name}: ${count}`).join(", ");
  const confidenceSummary = confidenceData.map(({ flow, confidence }) => `${flow}: ${confidence}%`).join(", ");

  if (!distributionData.length && !confidenceData.length) return null;

  return (
    <div className="grid gap-8 lg:grid-cols-2">
      <Section title="Traffic distribution" detail="Classified ESP flows by returned traffic type." isEmpty={!distributionData.length}>
        <div className="h-60" role="img" aria-label={`Traffic distribution chart. ${distributionSummary}`}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={distributionData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <CartesianGrid stroke="rgb(var(--color-rule))" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={{ stroke: "rgb(var(--color-rule))" }} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgb(var(--color-sunken))" }} />
              <Bar dataKey="count" name="Flows" fill="rgb(var(--color-accent))" isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Section>
      <Section title="Confidence per flow" detail="Returned classifier confidence, shown by flow order." isEmpty={!confidenceData.length}>
        <div className="h-60" role="img" aria-label={`Confidence per flow chart. ${confidenceSummary}`}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={confidenceData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <CartesianGrid stroke="rgb(var(--color-rule))" vertical={false} />
              <XAxis dataKey="flow" tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={{ stroke: "rgb(var(--color-rule))" }} tickLine={false} />
              <YAxis domain={[0, 100]} unit="%" tick={{ fill: "rgb(var(--color-muted))", fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Line type="linear" dataKey="confidence" name="Confidence" stroke="rgb(var(--color-accent))" strokeWidth={1.5} dot={{ r: 2, fill: "rgb(var(--color-accent))" }} activeDot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Section>
    </div>
  );
}
