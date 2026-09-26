import { useCallback, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  BookOpen,
  CircleAlert,
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
    return "Janus Standards Rule Engine";
  }
  return modelName
    .replace(/\s*\(CoT\)/gi, "")
    .replace(/-CoT/gi, "")
    .replace(/-Compound/gi, "")
    .trim();
}

/** Map well-known rule/technique IDs to human-readable advisory titles. */
const ADVISORY_TITLE_MAP: Record<string, string> = {
  SIMULATED_VPN_SUITE: "Simulated VPN Suite Advisory",
  T1040: "Strong Cryptographic Protection (T1040)",
  T1557: "Adversary-in-the-Middle Resistance (T1557)",
  T1484: "Domain Policy Modification (T1484)",
  T1556: "Modify Authentication Process (T1556)",
  T1552: "Unsecured Credentials (T1552)",
};

function humanizeAdvisoryTitle(ruleId: string): string {
  if (!ruleId) return "Compliance Advisory";
  if (ADVISORY_TITLE_MAP[ruleId]) return ADVISORY_TITLE_MAP[ruleId];
  // MITRE technique IDs: T1040 style — keep ID as parenthetical
  if (/^T\d{4}(\.\d{3})?$/.test(ruleId)) {
    return `Technique ${ruleId} Advisory`;
  }
  // RFC rule IDs: RFC8221-ENCR_3DES → sentence-case the suffix, keep rule as badge
  const rfcMatch = ruleId.match(/^(RFC\d+)-(.+)$/i);
  if (rfcMatch) {
    const suffix = rfcMatch[2].replace(/_/g, " ").toLowerCase();
    return `${suffix.charAt(0).toUpperCase() + suffix.slice(1)} Advisory`;
  }
  // SCREAMING_SNAKE → Sentence Case Advisory
  if (/^[A-Z][A-Z0-9_]+$/.test(ruleId)) {
    const words = ruleId.replace(/_/g, " ").toLowerCase();
    return `${words.charAt(0).toUpperCase() + words.slice(1)} Advisory`;
  }
  return `${ruleId} Advisory`;
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
      title={finding ? humanizeAdvisoryTitle(finding.rule_id) : "Compliance Advisory"}
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

/** Clean § section symbols from document clauses, IDs, and section strings */
function cleanSectionNumber(sec?: string | null): string {
  if (!sec) return "";
  const s = String(sec).trim();
  // Strip leading §, "Section", "Sec.", and whitespace
  const stripped = s.replace(/^(?:section|sec\.?|§)\s*/i, "").replace(/^[§\s]+/, "");
  return stripped || s;
}

function cleanSectionText(text?: string | null): string {
  if (!text) return "";
  return text
    .replace(/(?:Section|Sec\.?)\s*§\s*/gi, "Section ")
    .replace(/§\s*([0-9])/g, "Section $1")
    .replace(/§/g, "")
    .replace(/Section\s+Section\s+/gi, "Section ")
    .trim();
}

function formatSectionLabel(sec?: string | null): string {
  if (!sec) return "Specification Clause";
  const num = cleanSectionNumber(sec);
  if (/^(table|appendix|clause)/i.test(num)) {
    return num;
  }
  return `Section ${num}`;
}

function SourceChunkCard({ chunk }: { chunk: { chunk_id: string; document: string; section: string; title: string; text: string } }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const isLong = chunk.text.length > 260 || chunk.text.includes("spi 0x") || chunk.text.includes("seq 0x");

  return (
    <article className="rounded-xl border border-rule bg-surface p-4 space-y-2.5 transition-colors">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule/60 pb-2">
        <span className="font-mono text-[11px] font-bold text-accent">
          {chunk.document} · {formatSectionLabel(chunk.section)}
        </span>
        <span className="font-mono text-[10px] text-muted">Standards corpus</span>
      </div>
      <h4 className="text-xs font-bold text-ink">{cleanSectionText(chunk.title)}</h4>

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
            <span className="font-mono text-xs font-semibold text-ink">
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

      {/* Tab 1: Advisory & Remediation */}
      {activeTab === "analysis" && (
        <div className="space-y-4 motion-fade">
          {data.summary ? (
            <div className="space-y-4">
              <div className="space-y-3">
                <p className="text-xs sm:text-[13px] leading-relaxed text-ink/90">
                  {data.summary}
                </p>
                {(data.riskNote || data.risk_note) && (
                  <div className="space-y-1 pt-1">
                    <h4 className="text-xs font-semibold text-ink">What this means</h4>
                    <p className="text-xs sm:text-[13px] leading-relaxed text-ink/90">
                      {data.riskNote ?? data.risk_note}
                    </p>
                  </div>
                )}
                {((data.standardsCited && data.standardsCited.length > 0) ||
                  (data.standards_cited && data.standards_cited.length > 0)) && (
                  <div className="space-y-1.5 pt-1">
                    <h4 className="text-xs font-semibold text-ink">Governing standards</h4>
                    <ul className="space-y-1 text-xs sm:text-[13px] text-ink/80">
                      {(data.standardsCited ?? data.standards_cited ?? []).map((std, idx) => (
                        <li key={idx} className="leading-relaxed">
                          <strong className="font-mono font-semibold text-ink">{cleanSectionText(std.id)}</strong>
                          {std.note ? <span> — {cleanSectionText(std.note)}</span> : null}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {data.remediation && (
                <div className="border-t border-rule/60 pt-3 space-y-2">
                  <h4 className="text-xs font-semibold text-ink">Remediation</h4>
                  <MarkdownView content={data.remediation} />
                </div>
              )}
            </div>
          ) : (
            <MarkdownView content={data.explanation} />
          )}
        </div>
      )}

      {/* Tab 2: Authoritative Citations & Source Clauses */}
      {activeTab === "sources" && (
        <div className="space-y-6 motion-fade">
          {/* Citations Section */}
          <section className="space-y-3">
            <h4 className="text-xs font-semibold text-ink">Governing standards citations</h4>

            {data.citations.length > 0 ? (
              <div className="space-y-2">
                {data.citations.map((citation, idx) => (
                  <div
                    key={`${citation.document}-${citation.section}-${idx}`}
                    className="flex items-start justify-between gap-3 rounded-xl border border-rule bg-surface p-3.5 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-accent">{cleanSectionText(citation.raw_citation)}</span>
                        {citation.clause_title && (
                          <span className="text-xs text-ink font-medium">— {cleanSectionText(citation.clause_title)}</span>
                        )}
                      </div>
                      <p className="text-[11px] text-muted font-mono">
                        {citation.document} · {formatSectionLabel(citation.section)}
                      </p>
                    </div>
                    {/* Only show a badge when the citation could NOT be verified — verified is the expected state */}
                    {!citation.verified && (
                      <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase shrink-0 bg-sunken text-muted border border-rule">
                        <CircleAlert className="size-3" />
                        <span>Unverified</span>
                      </span>
                    )}
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
              <div className="border-t border-rule pt-4">
                <h4 className="text-xs font-semibold text-ink">
                  Normative clauses ({data.retrieved_chunks.length})
                </h4>
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

      {/* Technical Audit Footer (Clean Attribution; Telemetry behind dev toggle) */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule pt-4 text-xs font-mono text-muted">
        <span className="text-ink font-medium">
          {cleanModelName(data.model_name)}
        </span>
        {import.meta.env.DEV && (
          <details className="text-[11px] font-mono text-muted/70 cursor-pointer">
            <summary className="hover:text-ink">Debug telemetry</summary>
            <div className="mt-1 flex items-center gap-3 pl-2">
              <span>Grounded: {groundedness(data.groundedness_score)}</span>
              <span>•</span>
              <span>Latency: {data.latency_ms.toFixed(1)} ms</span>
            </div>
          </details>
        )}
      </div>
    </div>
  );
}
