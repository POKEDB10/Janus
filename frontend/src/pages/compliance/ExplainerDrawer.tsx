import { useCallback, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert } from "lucide-react";
import { explainFinding } from "../../api/client";
import { Drawer } from "../../components/ui/Drawer";
import { ErrorState, InlineNotice, LoadingState } from "../../components/ui/Primitives";
import { getApiErrorMessage } from "../../lib/api-error";
import type { Finding } from "../../types";

function groundedness(value: number) {
  return `${(value <= 1 ? value * 100 : value).toFixed(0)}%`;
}

export function useExplainerDrawer() {
  const [finding, setFinding] = useState<Finding | null>(null);
  const explanation = useMutation({ mutationFn: (target: Finding) => explainFinding(target) });

  const open = useCallback((target: Finding) => {
    setFinding(target);
    explanation.mutate(target);
  }, [explanation]);
  const close = useCallback(() => {
    setFinding(null);
    explanation.reset();
  }, [explanation]);

  const drawer = (
    <Drawer open={Boolean(finding)} title={finding ? `${finding.rule_id} source notes` : "Source notes"} onClose={close}>
      {explanation.isPending ? <LoadingState label="Retrieving source clauses…" /> : null}
      {explanation.isError && finding ? <ErrorState title="Sources are unavailable" detail={getApiErrorMessage(explanation.error)} onRetry={() => explanation.mutate(finding)} /> : null}
      {explanation.data ? <ExplainerContent data={explanation.data} /> : null}
    </Drawer>
  );

  return { open, drawer };
}

function ExplainerContent({ data }: { data: Awaited<ReturnType<typeof explainFinding>> }) {
  return (
    <div className="space-y-6">
      <p className="text-sm leading-6 text-ink">{data.explanation}</p>
      {data.warning || data.is_fallback ? <InlineNotice>{data.warning ?? "The explainer returned a fallback response."}</InlineNotice> : null}
      <dl className="grid grid-cols-3 gap-4 border-y border-rule py-4 text-xs">
        <div><dt className="text-muted">Groundedness</dt><dd className="data-number mt-1 font-mono text-ink">{groundedness(data.groundedness_score)}</dd></div>
        <div><dt className="text-muted">Latency</dt><dd className="data-number mt-1 font-mono text-ink">{data.latency_ms} ms</dd></div>
        <div><dt className="text-muted">Model</dt><dd className="mt-1 font-mono text-ink">{data.model_name}</dd></div>
      </dl>
      {data.citations.length ? <section aria-labelledby="citation-heading"><h3 id="citation-heading" className="text-sm font-semibold text-ink">Citations</h3><ul className="mt-3 divide-y divide-rule border-y border-rule">{data.citations.map((citation) => <li key={`${citation.document}-${citation.section}-${citation.raw_citation}`} className="py-3 text-sm"><div className="flex items-start gap-2">{citation.verified ? <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-pass" /> : <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />}<div><p className="font-medium text-ink">{citation.raw_citation}</p><p className="mt-1 text-xs text-muted">{citation.document} · {citation.section} · {citation.verified ? "Verified" : "Not verified"}</p>{citation.clause_title ? <p className="mt-1 text-xs text-muted">{citation.clause_title}</p> : null}</div></div></li>)}</ul></section> : <InlineNotice>Not returned by the API</InlineNotice>}
      {data.retrieved_chunks.length ? <section aria-labelledby="source-heading"><h3 id="source-heading" className="text-sm font-semibold text-ink">Source clauses</h3><div className="mt-3 divide-y divide-rule border-y border-rule">{data.retrieved_chunks.map((chunk) => <article key={chunk.chunk_id} className="py-3"><p className="font-mono text-xs text-muted">{chunk.document} · {chunk.section}</p><h4 className="mt-1 text-sm font-medium text-ink">{chunk.title}</h4><p className="mt-2 text-sm leading-6 text-muted">{chunk.text}</p></article>)}</div></section> : null}
    </div>
  );
}
