import { useCallback, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  BookOpen,
  CheckCircle2,
  CircleAlert,
  FileText,
  Layers,
  Shield,
} from "lucide-react";
import { explainFinding } from "../../api/client";
import { MarkdownView } from "../../components/ui/MarkdownView";
import { Drawer } from "../../components/ui/Drawer";
import RiskBadge from "../../components/RiskBadge";
import { ErrorState, LoadingState } from "../../components/ui/Primitives";
import { getApiErrorMessage } from "../../lib/api-error";
import { cn } from "../../lib/cn";
import type { Finding } from "../../types";

function groundedness(value: number) {
  return `${(value <= 1 ? value * 100 : value).toFixed(0)}%`;
}

function cleanModelName(modelName: string): string {
  if (modelName.includes("Janus-Grounded-Fallback") || modelName.includes("Janus-Standards-Engine")) {
    return "Janus Standards Rule Engine (CoT)";
  }
  return modelName;
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
    <Drawer
      open={Boolean(finding)}
      title={finding ? `${finding.rule_id} Compliance Advisory` : "Compliance Advisory"}
      onClose={close}
    >
      {explanation.isPending ? (
        <LoadingState label="Synthesizing authoritative RFC/NIST standards evaluation…" />
      ) : null}
      {explanation.isError && finding ? (
        <ErrorState
          title="Standards advisory unavailable"
          detail={getApiErrorMessage(explanation.error)}
          onRetry={() => explanation.mutate(finding)}
        />
      ) : null}
      {explanation.data ? (
        <ExplainerContent data={explanation.data} finding={finding} />
      ) : null}
    </Drawer>
  );

  return { open, drawer };
}

function SourceChunkCard({ chunk }: { chunk: { chunk_id: string; document: string; section: string; title: string; text: string } }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const isLong = chunk.text.length > 260 || chunk.text.includes("spi 0x") || chunk.text.includes("seq 0x");

  return (
    <article className="rounded-xl border border-rule bg-surface p-4 space-y-2.5 transition-colors">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule/60 pb-2">
        <span className="font-mono text-[11px] font-bold text-accent">
          {chunk.document} · Section {chunk.section}
        </span>
        <span className="font-mono text-[10px] text-muted uppercase">RFC Corpus</span>
      </div>
      <h4 className="text-xs font-bold text-ink">{chunk.title}</h4>

      {isLong ? (
        <div className="space-y-2">
          <p className="text-xs leading-relaxed text-ink/80">
            {isExpanded ? chunk.text.slice(0, 200) : `${chunk.text.slice(0, 240)}...`}
          </p>
          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="font-mono text-[11px] font-semibold text-accent hover:text-accent-strong select-none"
          >
            {isExpanded ? "Collapse full clause text ▲" : "View full normative text & tables ▼"}
          </button>
          {isExpanded && (
            <pre className="mt-2 p-3 rounded-lg border border-rule bg-canvas font-mono text-[11px] text-ink leading-relaxed overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto">
              {chunk.text}
            </pre>
          )}
        </div>
      ) : (
        <p className="text-xs leading-relaxed text-ink/80">{chunk.text}</p>
      )}
    </article>
  );
}

function ExplainerContent({
  data,
  finding,
}: {
  data: Awaited<ReturnType<typeof explainFinding>>;
  finding: Finding | null;
}) {
  const [activeTab, setActiveTab] = useState<"analysis" | "sources">("analysis");

  return (
    <div className="space-y-6">
      {/* Target Finding Summary Card */}
      {finding && (
        <div className="rounded-xl border border-rule bg-sunken/40 p-4 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <RiskBadge level={(finding.severity as any) || "INFO"} />
              <span className="font-mono text-xs font-bold text-ink">{finding.rule_id}</span>
            </div>
            <span className="rounded bg-surface px-2.5 py-0.5 font-mono text-[11px] font-semibold text-ink border border-rule">
              {finding.parameter}
            </span>
          </div>
          <p className="text-xs text-ink leading-relaxed font-medium">
            {finding.description}
          </p>
          {finding.references && finding.references.length > 0 && (
            <p className="font-mono text-[11px] text-muted">
              Governing Standard: <span className="text-accent font-semibold">{finding.references.join(", ")}</span>
            </p>
          )}
        </div>
      )}

      {/* Clean Segmented Tab Switcher */}
      <div className="flex items-center gap-1 rounded-lg border border-rule bg-sunken/60 p-1">
        <button
          type="button"
          onClick={() => setActiveTab("analysis")}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all",
            activeTab === "analysis"
              ? "bg-surface text-ink shadow-sm border border-rule/80 font-bold"
              : "text-muted hover:text-ink"
          )}
        >
          <Shield size={13} className="text-accent" />
          <span>Standards Advisory</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("sources")}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all",
            activeTab === "sources"
              ? "bg-surface text-ink shadow-sm border border-rule/80 font-bold"
              : "text-muted hover:text-ink"
          )}
        >
          <BookOpen size={13} className="text-accent" />
          <span>Normative Clauses ({data.citations.length})</span>
        </button>
      </div>

      {/* Tab 1: Advisory & Remediation Markdown */}
      {activeTab === "analysis" && (
        <div className="space-y-4 motion-fade">
          <MarkdownView content={data.explanation} />
        </div>
      )}

      {/* Tab 2: Authoritative Citations & Source Clauses */}
      {activeTab === "sources" && (
        <div className="space-y-6 motion-fade">
          {/* Citations Section */}
          <section className="space-y-3">
            <div className="flex items-center gap-2 font-mono text-xs font-bold text-ink uppercase tracking-wider">
              <FileText className="size-3.5 text-accent" />
              <span>Governing Standards Citations</span>
            </div>

            {data.citations.length > 0 ? (
              <div className="space-y-2">
                {data.citations.map((citation, idx) => (
                  <div
                    key={`${citation.document}-${citation.section}-${idx}`}
                    className="flex items-start justify-between gap-3 rounded-xl border border-rule bg-surface p-3.5 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-accent">{citation.raw_citation}</span>
                        {citation.clause_title && (
                          <span className="text-xs text-ink font-medium">— {citation.clause_title}</span>
                        )}
                      </div>
                      <p className="text-[11px] text-muted font-mono">
                        {citation.document} · Section {citation.section}
                      </p>
                    </div>
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase shrink-0",
                        citation.verified
                          ? "bg-pass/10 text-pass border border-pass/30"
                          : "bg-sunken text-muted border border-rule"
                      )}
                    >
                      {citation.verified ? (
                        <CheckCircle2 className="size-3" />
                      ) : (
                        <CircleAlert className="size-3" />
                      )}
                      <span>{citation.verified ? "Verified" : "Unverified"}</span>
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-muted">No citations recorded for this finding.</p>
            )}
          </section>

          {/* Source Clauses Section */}
          {data.retrieved_chunks.length > 0 && (
            <section className="space-y-3 pt-2">
              <div className="flex items-center justify-between border-t border-rule pt-4">
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-ink uppercase tracking-wider">
                  <Layers className="size-3.5 text-accent" />
                  <span>Primary Standards Text ({data.retrieved_chunks.length})</span>
                </div>
                <span className="text-[11px] font-mono text-muted">Authoritative Corpus</span>
              </div>

              <div className="space-y-3">
                {data.retrieved_chunks.map((chunk) => (
                  <SourceChunkCard key={chunk.chunk_id} chunk={chunk} />
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* Technical Audit Footer (Replacing raw debug dl) */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule pt-4 text-xs font-mono text-muted">
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 text-pass font-medium">
            <CheckCircle2 className="size-3.5" />
            <span>Grounded: {groundedness(data.groundedness_score)}</span>
          </span>
          <span>•</span>
          <span className="text-ink">
            {cleanModelName(data.model_name)}
          </span>
        </div>
        <div className="text-[11px] text-muted">
          Latency: <span className="font-semibold text-ink">{data.latency_ms.toFixed(1)} ms</span>
        </div>
      </div>
    </div>
  );
}
