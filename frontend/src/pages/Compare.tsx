import { useState, type FormEvent } from "react";
import { useLocation } from "react-router-dom";
import { useCaptureResults } from "../api/queries";
import { ErrorState, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";

function ComparisonResult({ captureId, search }: { captureId: string; search: string }) {
  const result = useCaptureResults(captureId, search);
  if (!captureId) return <p className="text-sm text-muted">Enter a capture ID to compare it.</p>;
  if (result.isPending) return <LoadingState label={`Loading ${captureId}…`} />;
  if (result.isError) return <ErrorState title={`Couldn’t load ${captureId}`} detail={getApiErrorMessage(result.error)} onRetry={() => void result.refetch()} />;
  const compliance = result.data?.compliance;
  return (
    <dl className="grid gap-4 text-sm">
      <div><dt className="text-xs text-muted">Capture</dt><dd className="mt-1 font-mono text-ink">{captureId}</dd></div>
      <div><dt className="text-xs text-muted">Configuration verdict</dt><dd className="mt-1 font-medium text-ink">{compliance?.overall_score === null || compliance?.grade === "N/A" ? "Not assessable" : compliance?.grade ? `Grade ${compliance.grade}` : "Not returned by the API"}</dd></div>
      <div><dt className="text-xs text-muted">Traffic flows</dt><dd className="data-number mt-1 font-mono text-ink">{result.data?.total_flows ?? "—"}</dd></div>
    </dl>
  );
}

export default function Compare() {
  const { search } = useLocation();
  const [pendingLeft, setPendingLeft] = useState("");
  const [pendingRight, setPendingRight] = useState("");
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLeft(pendingLeft.trim());
    setRight(pendingRight.trim());
  }

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Capture comparison" title="Compare two completed analyses." answer="Enter capture IDs returned by the analysis service. Janus does not substitute sample verdicts." />
      <form onSubmit={submit} className="grid gap-4 border-b border-rule pb-5 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
        <label className="grid gap-1 text-sm font-medium text-ink">First capture<input value={pendingLeft} onChange={(event) => setPendingLeft(event.target.value)} className="min-h-10 border border-rule bg-surface px-3 font-mono text-sm outline-none focus:border-accent" /></label>
        <label className="grid gap-1 text-sm font-medium text-ink">Second capture<input value={pendingRight} onChange={(event) => setPendingRight(event.target.value)} className="min-h-10 border border-rule bg-surface px-3 font-mono text-sm outline-none focus:border-accent" /></label>
        <button type="submit" className="min-h-10 bg-accent px-4 text-sm font-medium text-white hover:bg-accent-strong focus-visible:outline-none">Compare</button>
      </form>
      {(left || right) ? <Section title="Results"><div className="grid gap-8 md:grid-cols-2"><ComparisonResult captureId={left} search={search} /><ComparisonResult captureId={right} search={search} /></div></Section> : null}
    </div>
  );
}
