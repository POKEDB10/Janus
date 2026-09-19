import { useMutation, useQuery } from "@tanstack/react-query";
import { useLocation, useParams } from "react-router-dom";
import { draftReportNarrative, getReportStatus } from "../api/client";
import { useCaptureResults } from "../api/queries";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { getCaptureContext, isRecordedSample } from "../lib/capture-session";
import type { CitationItem } from "../types";

function ReportLink({ href, children }: { href: string; children: string }) {
  return <a href={href} className="inline-flex min-h-10 items-center border border-rule px-3 text-sm font-medium text-accent hover:border-accent focus-visible:outline-none">{children}</a>;
}

function ReportAvailability({ label, ready, href }: { label: string; ready: boolean; href?: string | null }) {
  return (
    <article className="border border-rule bg-surface p-4">
      <p className="text-sm font-medium text-ink">{label}</p>
      <p className={`mt-2 font-mono text-xs ${ready ? "text-pass" : "text-muted"}`}>{ready ? "READY" : "NOT READY"}</p>
      {ready && href ? <div className="mt-4"><ReportLink href={href}>Download PDF</ReportLink></div> : null}
      {ready && !href ? <p className="mt-3 text-sm text-muted">Ready, but no download location was returned.</p> : null}
    </article>
  );
}

function CitationList({ citations }: { citations: CitationItem[] }) {
  if (!citations.length) return <InlineNotice>No citation evidence was returned.</InlineNotice>;
  return <div className="divide-y divide-rule border-y border-rule">{citations.map((citation, index) => <article key={`${citation.document}-${citation.section}-${index}`} className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-start"><div><p className="font-medium text-ink">{citation.clause_title ?? citation.raw_citation}</p><p className="mt-1 font-mono text-xs text-muted">{citation.document} · {citation.section}{citation.matching_chunk_id ? ` · ${citation.matching_chunk_id}` : ""}</p></div><p className={`font-mono text-xs ${citation.verified ? "text-pass" : "text-muted"}`}>{citation.verified ? "VERIFIED" : "UNVERIFIED"}</p></article>)}</div>;
}

export default function Report() {
  const { captureId = "" } = useParams();
  const { search } = useLocation();
  const recorded = isRecordedSample(search);
  const context = getCaptureContext(captureId);
  const results = useCaptureResults(captureId, search);
  const status = useQuery({
    queryKey: ["report-status", captureId],
    queryFn: () => getReportStatus(captureId, context.captureToken),
    enabled: Boolean(captureId) && !recorded,
    retry: false,
  });
  const narrative = useMutation({ mutationFn: () => draftReportNarrative(captureId) });

  if (results.isPending) return <LoadingState label="Loading report evidence…" />;
  if (results.isError) return <ErrorState title="Report is unavailable" detail={getApiErrorMessage(results.error)} onRetry={() => void results.refetch()} />;

  const reportLinks = results.data?.reports;
  const executiveHref = reportLinks?.executive_pdf ?? reportLinks?.executive_url ?? status.data?.executive_url;
  const technicalHref = reportLinks?.technical_pdf ?? reportLinks?.technical_url ?? status.data?.technical_url;
  const executiveReady = status.data ? status.data.executive_ready : Boolean(executiveHref);
  const technicalReady = status.data ? status.data.technical_ready : Boolean(technicalHref);
  const narrativeData = narrative.data;

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Analysis report" title="Report evidence." answer="Availability, narrative text, and citations are shown only when returned for this capture." />
      <Section title="Report availability" detail="Readiness comes from the report status response; links are not inferred.">
        {recorded ? <InlineNotice>This recorded fixture does not include report-status evidence.</InlineNotice> : null}
        {status.isFetching ? <LoadingState label="Checking report availability…" /> : null}
        {status.isError ? <InlineNotice>Report status is unavailable: {getApiErrorMessage(status.error)}</InlineNotice> : null}
        {!recorded && status.data ? <div className="grid gap-4 sm:grid-cols-2"><ReportAvailability label="Executive report" ready={executiveReady} href={executiveHref} /><ReportAvailability label="Technical report" ready={technicalReady} href={technicalHref} /></div> : null}
        {recorded && (executiveHref || technicalHref) ? <div className="grid gap-4 sm:grid-cols-2"><ReportAvailability label="Executive report" ready={executiveReady} href={executiveHref} /><ReportAvailability label="Technical report" ready={technicalReady} href={technicalHref} /></div> : null}
      </Section>
      <Section title="Grounded narrative" detail="Narrative generation is requested explicitly and shown with its returned evidence.">
        {recorded ? <InlineNotice>This recorded fixture does not include narrative evidence.</InlineNotice> : null}
        {!recorded && narrative.isIdle ? <button type="button" onClick={() => narrative.mutate()} className="min-h-10 bg-accent px-4 text-sm font-medium text-white hover:bg-accent-strong focus-visible:outline-none">Prepare narrative evidence</button> : null}
        {narrative.isPending ? <LoadingState label="Preparing grounded narrative evidence…" /> : null}
        {narrative.isError ? <ErrorState title="Narrative evidence is unavailable" detail={getApiErrorMessage(narrative.error)} onRetry={() => narrative.reset()} /> : null}
        {narrativeData ? <div className="space-y-6"><div className="grid gap-4 border-y border-rule py-4 sm:grid-cols-3"><Metric label="Configuration grade" value={narrativeData.grade} /><Metric label="Grounding" value={narrativeData.is_grounded ? "Grounded" : "Not grounded"} /><Metric label="Response time" value={`${narrativeData.latency_ms} ms`} /></div><Narrative title="Executive narrative" text={narrativeData.executive_narrative} /><Narrative title="Technical narrative" text={narrativeData.technical_narrative} /><div><h3 className="text-base font-semibold text-ink">Citation evidence</h3><div className="mt-3"><CitationList citations={narrativeData.citations} /></div></div></div> : null}
      </Section>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="border-l border-rule pl-3"><p className="text-xs text-muted">{label}</p><p className="mt-1 font-mono text-sm text-ink">{value}</p></div>;
}

function Narrative({ title, text }: { title: string; text: string }) {
  return <article><h3 className="text-base font-semibold text-ink">{title}</h3><p className="mt-2 max-w-4xl whitespace-pre-wrap text-sm leading-6 text-muted">{text}</p></article>;
}
