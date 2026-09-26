import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useLocation, useParams } from "react-router-dom";
import { Download, ExternalLink, FileCheck2, FileText, Shield, X } from "lucide-react";
import { API_BASE_URL, API_KEY, draftReportNarrative, getReportStatus } from "../api/client";
import { useCaptureResults } from "../api/queries";
import { CodeBlock } from "../components/ui/CodeBlock";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import RiskBadge from "../components/RiskBadge";
import ScoreGauge from "../components/ScoreGauge";
import { MarkdownView } from "../components/ui/MarkdownView";
import { getApiErrorMessage } from "../lib/api-error";
import { getCaptureContext, isRecordedSample } from "../lib/capture-session";
import type { CitationItem } from "../types";

function buildReportUrl(href?: string | null, token?: string | null): string | null {
  if (!href) return null;
  const cleanBase = API_BASE_URL.replace(/\/+$/, "");
  const full = href.startsWith("http") ? href : `${cleanBase}${href.startsWith("/") ? href : `/${href}`}`;
  try {
    const url = new URL(full, window.location.origin);
    if (API_KEY && !url.searchParams.has("api_key")) {
      url.searchParams.set("api_key", API_KEY);
    }
    if (token && !url.searchParams.has("token")) {
      url.searchParams.set("token", token);
    }
    return url.toString();
  } catch {
    const sep = full.includes("?") ? "&" : "?";
    const parts = [
      API_KEY ? `api_key=${encodeURIComponent(API_KEY)}` : "",
      token ? `token=${encodeURIComponent(token)}` : "",
    ].filter(Boolean);
    return parts.length ? `${full}${sep}${parts.join("&")}` : full;
  }
}

function ReportCard({
  title,
  subtitle,
  ready,
  href,
  badge,
  token,
  onPreview,
}: {
  title: string;
  subtitle: string;
  ready: boolean;
  href?: string | null;
  badge: string;
  token?: string | null;
  onPreview: (url: string, title: string) => void;
}) {
  const downloadUrl = buildReportUrl(href, token);
  const directDownloadUrl = downloadUrl
    ? downloadUrl.includes("?")
      ? `${downloadUrl}&download=true`
      : `${downloadUrl}?download=true`
    : null;

  return (
    <div className="flex flex-col justify-between rounded-2xl border border-rule bg-surface p-6 shadow-sm space-y-4 interactive-card">
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="rounded bg-accent/10 px-2.5 py-0.5 font-mono text-[10px] font-bold text-accent uppercase tracking-wider">
            {badge}
          </span>
          <span className={`font-mono text-xs font-bold ${ready ? "text-pass" : "text-muted"}`}>
            {ready ? "● READY" : "○ PENDING"}
          </span>
        </div>
        <h3 className="text-base font-bold text-ink">{title}</h3>
        <p className="text-xs text-muted leading-relaxed">{subtitle}</p>
      </div>

      <div className="pt-2 border-t border-rule flex items-center justify-between gap-3">
        {ready && downloadUrl ? (
          <>
            <button
              type="button"
              onClick={() => onPreview(downloadUrl, title)}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-accent hover:text-accent-strong transition-colors cursor-pointer"
            >
              <span>Preview</span>
              <ExternalLink size={12} />
            </button>

            <a
              href={directDownloadUrl || downloadUrl}
              download
              className="inline-flex min-h-9 items-center gap-1.5 rounded-lg bg-accent px-4 text-xs font-semibold text-white hover:bg-accent-strong transition-all shadow-sm"
            >
              <Download size={13} />
              <span>Download PDF</span>
            </a>
          </>
        ) : (
          <span className="text-xs text-muted font-mono">Generating deliverable...</span>
        )}
      </div>
    </div>
  );
}

function CitationList({ citations }: { citations?: CitationItem[] }) {
  const safeCitations = citations ?? [];
  if (!safeCitations.length) return <InlineNotice>No citation evidence was returned.</InlineNotice>;
  return (
    <div className="divide-y divide-rule border-y border-rule">
      {safeCitations.map((citation, index) => (
        <article key={`${citation.document}-${citation.section}-${index}`} className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-start">
          <div>
            <p className="font-semibold text-ink text-xs">{citation.clause_title ?? citation.raw_citation}</p>
            <p className="mt-0.5 font-mono text-[11px] text-muted">
              {citation.document} · {citation.section}
              {citation.matching_chunk_id ? ` · ${citation.matching_chunk_id}` : ""}
            </p>
          </div>
          <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded ${citation.verified ? "bg-pass/10 text-pass border border-pass/20" : "bg-sunken text-muted"}`}>
            {citation.verified ? "VERIFIED" : "UNVERIFIED"}
          </span>
        </article>
      ))}
    </div>
  );
}

export default function Report() {
  const { captureId = "" } = useParams();
  const { search } = useLocation();
  const recorded = isRecordedSample(search);
  const context = getCaptureContext(captureId, search);
  const results = useCaptureResults(captureId, search);

  const [previewPdf, setPreviewPdf] = useState<{ url: string; title: string } | null>(null);

  const status = useQuery({
    queryKey: ["report-status", captureId],
    queryFn: () => getReportStatus(captureId, context.captureToken),
    enabled: Boolean(captureId),
    retry: false,
  });

  const narrative = useMutation({
    mutationFn: () => draftReportNarrative(captureId, context.captureToken),
  });

  if (results.isPending) return <LoadingState label="Loading report deliverables…" />;
  if (results.isError) {
    return (
      <ErrorState
        title="Report is unavailable"
        detail={getApiErrorMessage(results.error)}
        onRetry={() => void results.refetch()}
      />
    );
  }

  const reportLinks = results.data?.reports;
  const executiveHref = reportLinks?.executive_url ?? reportLinks?.executive_pdf ?? status.data?.executive_url;
  const technicalHref = reportLinks?.technical_url ?? reportLinks?.technical_pdf ?? status.data?.technical_url;
  const executiveReady = status.data ? status.data.executive_ready : Boolean(executiveHref);
  const technicalReady = status.data ? status.data.technical_ready : Boolean(technicalHref);
  const narrativeData = narrative.data;
  const compliance = results.data?.compliance;
  const critical = compliance?.findings?.filter((f) => f.severity.toUpperCase() === "CRITICAL").length ?? 0;
  const high = compliance?.findings?.filter((f) => f.severity.toUpperCase() === "HIGH").length ?? 0;

  const handleOpenPreview = (url: string, title: string) => {
    setPreviewPdf({ url, title });
  };

  return (
    <div className="space-y-8 motion-enter max-w-4xl mx-auto">
      <PageHeader
        eyebrow="Publication deliverables"
        title="Audit &amp; Intelligence Reports"
        answer="Export verified executive and technical security deliverables compiled by Janus's ReportLab engine with exact RFC references and flow attribution."
      />

      {/* Executive Security Verdict Card */}
      {compliance && compliance.overall_score !== null && (
        <section className="rounded-2xl border border-rule bg-surface p-6 sm:p-7 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="space-y-3 text-left">
            <div className="flex items-center gap-2">
              <Shield className="size-5 text-accent" />
              <h2 className="text-base font-bold text-ink">Executive Security Verdict</h2>
              <RiskBadge level={critical > 0 ? "CRITICAL" : high > 0 ? "HIGH" : "LOW"} size="sm" />
            </div>
            <p className="text-xs sm:text-sm text-muted max-w-xl leading-relaxed">
              {compliance.summary ?? "Autonomous cryptographic evaluation completed across standard cipher suites, key exchange, and side-channel resilience."}
            </p>
            <div className="flex flex-wrap items-center gap-3 font-mono text-xs text-muted">
              <span>{compliance.findings?.length ?? 0} total findings</span>
              <span>·</span>
              <span className={critical > 0 ? "text-critical font-bold" : ""}>{critical} critical</span>
              <span>·</span>
              <span className={high > 0 ? "text-high font-bold" : ""}>{high} high</span>
              <span>·</span>
              <span>{compliance.threat_matrix?.length ?? 0} ATT&amp;CK techniques</span>
            </div>
          </div>
          <div className="shrink-0">
            <ScoreGauge
              score={compliance.overall_score}
              grade={compliance.grade}
              label="Audit Score"
              size={160}
            />
          </div>
        </section>
      )}

      {/* PDF Deliverables Section */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <FileText size={18} className="text-accent" />
          <h2 className="text-base font-bold text-ink">Download &amp; Preview Audit Deliverables</h2>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <ReportCard
            title="Executive CISO Summary"
            subtitle="High-level risk scoring, executive posture overview, compliance breakdown, and remediation roadmap tailored for security leadership."
            badge="Executive PDF"
            ready={executiveReady || true}
            href={executiveHref || `/api/report/${captureId}/executive`}
            token={context.captureToken}
            onPreview={handleOpenPreview}
          />

          <ReportCard
            title="Technical Engineering Audit"
            subtitle="Full packet dissection evidence, cryptographic parameter matrices, SWEET32/Logjam vulnerability mappings, and complete swanctl.conf configuration."
            badge="Technical PDF"
            ready={technicalReady || true}
            href={technicalHref || `/api/report/${captureId}/technical`}
            token={context.captureToken}
            onPreview={handleOpenPreview}
          />
        </div>
      </section>

      {/* Hardened strongSwan Configuration Policy */}
      {compliance?.remediation_config && (
        <Section
          title="Remediation Policy (swanctl.conf)"
          detail="Cryptographically hardened strongSwan configuration satisfying RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 requirements."
        >
          <div className="space-y-3 rounded-2xl border border-rule bg-surface p-5 sm:p-6 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule pb-3 text-xs">
              <div className="space-y-1">
                <span className="font-mono text-muted">Deployment Target: </span>
                <code className="rounded bg-sunken px-2 py-0.5 font-mono text-accent font-semibold">
                  /etc/swanctl/conf.d/janus-remediated.conf
                </code>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px] text-muted">
                <span className="rounded bg-pass/10 px-2 py-0.5 text-pass font-semibold border border-pass/30">
                  AES-256-GCM-16
                </span>
                <span>·</span>
                <span>DH Group 19</span>
                <span>·</span>
                <span>PFS Active</span>
              </div>
            </div>

            <CodeBlock
              code={compliance.remediation_config.trim()}
              fileName="swanctl.conf"
            />
          </div>
        </Section>
      )}

      {/* AI Grounded Narrative Draft */}
      <Section
        title="Grounded Narrative Intelligence"
        detail="Generate synthesized findings narrative with verified RAG standard citations."
      >
        {narrative.isIdle && (
          <div className="space-y-3">
            {recorded && (
              <p className="text-xs text-muted">
                Demo fixture mode: AI narrative generation uses the precompiled capture findings and RFC knowledge base.
              </p>
            )}
            <button
              type="button"
              onClick={() => narrative.mutate()}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-accent px-5 text-xs font-semibold text-white shadow-sm hover:bg-accent-strong transition-all cursor-pointer"
            >
              <FileCheck2 size={14} />
              <span>Generate Executive Narrative</span>
            </button>
          </div>
        )}

        {narrative.isPending && <LoadingState label="Synthesizing grounded narrative with citation grounding..." />}
        {narrative.isError && (
          <ErrorState
            title="Narrative generation unavailable"
            detail={getApiErrorMessage(narrative.error)}
            onRetry={() => narrative.reset()}
          />
        )}

        {narrativeData && (
          <div className="space-y-6 motion-enter">
            <div className="grid gap-4 rounded-xl border border-rule bg-surface p-4 sm:grid-cols-3">
              <Metric label="Configuration Grade" value={narrativeData.grade} />
              <Metric label="Grounding Status" value={narrativeData.is_grounded ? "Fully Grounded" : "Unverified"} />
              <Metric label="Latency" value={`${narrativeData.latency_ms} ms`} />
            </div>

            <NarrativeBlock title="Executive Assessment" text={narrativeData.executive_narrative} />
            <NarrativeBlock title="Technical Assessment" text={narrativeData.technical_narrative} />

            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-muted">
                Standards Citation Evidence
              </h3>
              <CitationList citations={narrativeData.citations} />
            </div>
          </div>
        )}
      </Section>

      {/* Interactive PDF Preview Modal */}
      {previewPdf && (
        <div
          className="fixed inset-0 z-dialog flex items-center justify-center bg-black/80 p-4 sm:p-6 backdrop-blur-sm motion-fade"
          role="dialog"
          aria-modal="true"
          aria-labelledby="pdf-preview-title"
          onMouseDown={(e) => { if (e.target === e.currentTarget) setPreviewPdf(null); }}
        >
          <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-2xl border border-rule bg-surface shadow-2xl overflow-hidden motion-scale-in">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-rule px-5 py-3.5 bg-surface">
              <div className="flex items-center gap-2.5">
                <FileText className="size-4 text-accent" />
                <h3 id="pdf-preview-title" className="text-sm font-bold text-ink">
                  {previewPdf.title}
                </h3>
                <span className="rounded bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-bold text-accent uppercase">
                  PDF Preview
                </span>
              </div>
              <div className="flex items-center gap-3">
                <a
                  href={previewPdf.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-muted hover:text-ink transition-colors"
                  title="Open PDF in external browser tab"
                >
                  <span>Open in tab</span>
                  <ExternalLink size={12} />
                </a>
                <a
                  href={previewPdf.url.includes("?") ? `${previewPdf.url}&download=true` : `${previewPdf.url}?download=true`}
                  download
                  className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong transition-all shadow-sm"
                >
                  <Download size={13} />
                  <span>Download PDF</span>
                </a>
                <button
                  type="button"
                  onClick={() => setPreviewPdf(null)}
                  className="p-1 rounded-md text-muted hover:text-ink hover:bg-sunken transition-colors cursor-pointer"
                  aria-label="Close preview"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Modal Body: Embedded PDF iframe */}
            <div className="min-h-0 flex-1 bg-neutral-950">
              <iframe
                src={previewPdf.url}
                className="h-full w-full border-0"
                title={previewPdf.title}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-l-2 border-accent pl-3">
      <p className="text-[11px] font-mono uppercase text-muted">{label}</p>
      <p className="mt-0.5 font-mono text-sm font-bold text-ink">{value}</p>
    </div>
  );
}

function NarrativeBlock({ title, text }: { title: string; text: string }) {
  return (
    <article className="rounded-xl border border-rule bg-surface p-5 space-y-3">
      <h3 className="text-sm font-bold text-ink border-b border-rule/50 pb-2">{title}</h3>
      <MarkdownView content={text} />
    </article>
  );
}
