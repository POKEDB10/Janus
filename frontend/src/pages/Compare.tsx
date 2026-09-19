import { useState, type FormEvent, type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { getFlowDisposition, type AnalysisResults } from "../types";

function dispositionSummary(data: AnalysisResults): string {
  const counts = data.flows.reduce((summary, flow) => {
    const disposition = getFlowDisposition(flow);
    summary[disposition] += 1;
    return summary;
  }, { ABSTAINED: 0, OBFUSCATED: 0, LOW_CONFIDENCE: 0, VERIFIED: 0 });
  const alerts = [`${counts.ABSTAINED} abstained`, `${counts.LOW_CONFIDENCE} low confidence`, `${counts.OBFUSCATED} obfuscated`];
  return alerts.join(" · ");
}

function verdict(data: AnalysisResults): string {
  const compliance = data.compliance;
  if (!compliance) return "Not returned";
  if (compliance.overall_score === null) return "Not assessable";
  return `Grade ${compliance.grade} · ${compliance.overall_score.toFixed(0)} / 100`;
}

function trafficMix(data: AnalysisResults): string {
  const types = Object.entries(data.traffic_distribution ?? {}).filter(([, count]) => count > 0).map(([type, count]) => `${type} ${count}`);
  return types.length ? types.join(" · ") : "Not returned";
}

function ComparisonCell({ children }: { children: ReactNode }) {
  return <td className="px-3 py-3 align-top text-sm text-ink">{children}</td>;
}

function ComparisonTable({ left, right, leftId, rightId }: { left: AnalysisResults; right: AnalysisResults; leftId: string; rightId: string }) {
  const rows: Array<[string, string, string]> = [
    ["Configuration verdict", verdict(left), verdict(right)],
    ["Observed ESP flows", String(left.total_flows), String(right.total_flows)],
    ["IKE sessions", String(left.ike_sessions.length), String(right.ike_sessions.length)],
    ["Traffic distribution", trafficMix(left), trafficMix(right)],
    ["Flow dispositions", dispositionSummary(left), dispositionSummary(right)],
  ];
  return <div className="overflow-x-auto"><table className="w-full min-w-[700px] border-collapse text-left"><caption className="sr-only">Completed capture comparison</caption><thead className="border-y border-rule font-mono text-xs text-muted"><tr><th scope="col" className="px-3 py-2 font-medium">Evidence</th><th scope="col" className="px-3 py-2 font-medium">{leftId}</th><th scope="col" className="px-3 py-2 font-medium">{rightId}</th></tr></thead><tbody>{rows.map(([label, leftValue, rightValue]) => <tr key={label} className="border-b border-rule/70"><th scope="row" className="w-44 px-3 py-3 text-sm font-medium text-muted">{label}</th><ComparisonCell>{leftValue}</ComparisonCell><ComparisonCell>{rightValue}</ComparisonCell></tr>)}</tbody></table></div>;
}

export default function Compare() {
  const { search } = useLocation();
  const [pendingLeft, setPendingLeft] = useState("");
  const [pendingRight, setPendingRight] = useState("");
  const [leftId, setLeftId] = useState("");
  const [rightId, setRightId] = useState("");
  const left = useCaptureResults(leftId, search);
  const right = useCaptureResults(rightId, search);
  const selected = Boolean(leftId || rightId);
  const completePair = Boolean(leftId && rightId);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLeftId(pendingLeft.trim());
    setRightId(pendingRight.trim());
  }

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Capture comparison" title="Compare two completed analyses." answer="Janus compares only returned evidence. Missing verdicts, traces, and classifications remain visibly unavailable." />
      <form onSubmit={submit} className="grid gap-4 border-b border-rule pb-5 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
        <label className="grid gap-1 text-sm font-medium text-ink">First capture<input required value={pendingLeft} onChange={(event) => setPendingLeft(event.target.value)} placeholder="capture ID" className="min-h-10 border border-rule bg-surface px-3 font-mono text-sm outline-none focus:border-accent" /></label>
        <label className="grid gap-1 text-sm font-medium text-ink">Second capture<input required value={pendingRight} onChange={(event) => setPendingRight(event.target.value)} placeholder="capture ID" className="min-h-10 border border-rule bg-surface px-3 font-mono text-sm outline-none focus:border-accent" /></label>
        <button type="submit" className="min-h-10 bg-accent px-4 text-sm font-medium text-white hover:bg-accent-strong focus-visible:outline-none">Compare</button>
      </form>
      {!selected ? <InlineNotice>Enter two completed capture IDs to compare configuration and traffic evidence.</InlineNotice> : null}
      {selected && !completePair ? <InlineNotice>Enter both capture IDs before Janus can produce a comparison.</InlineNotice> : null}
      {completePair && (left.isPending || right.isPending) ? <LoadingState label="Loading capture evidence…" /> : null}
      {completePair && left.isError ? <ErrorState title={`Couldn’t load ${leftId}`} detail={getApiErrorMessage(left.error)} onRetry={() => void left.refetch()} /> : null}
      {completePair && right.isError ? <ErrorState title={`Couldn’t load ${rightId}`} detail={getApiErrorMessage(right.error)} onRetry={() => void right.refetch()} /> : null}
      {completePair && left.data && right.data ? <Section title="Evidence comparison" detail="Values are shown side-by-side without normalizing or replacing missing API fields."><ComparisonTable left={left.data} right={right.data} leftId={leftId} rightId={rightId} /></Section> : null}
    </div>
  );
}
