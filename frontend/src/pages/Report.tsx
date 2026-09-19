import { useQuery } from "@tanstack/react-query";
import { useLocation, useParams } from "react-router-dom";
import { getReportStatus } from "../api/client";
import { useCaptureResults } from "../api/queries";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { getCaptureContext, isRecordedSample } from "../lib/capture-session";

function ReportLink({ href, children }: { href: string; children: string }) {
  return <a href={href} className="inline-flex min-h-10 items-center border border-rule px-3 text-sm font-medium text-accent hover:border-accent focus-visible:outline-none">{children}</a>;
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

  if (results.isPending) return <LoadingState label="Loading report status…" />;
  if (results.isError) return <ErrorState title="Report is unavailable" detail={getApiErrorMessage(results.error)} onRetry={() => void results.refetch()} />;

  const reportLinks = results.data?.reports;
  const executive = reportLinks?.executive_pdf ?? reportLinks?.executive_url ?? status.data?.executive_url;
  const technical = reportLinks?.technical_pdf ?? reportLinks?.technical_url ?? status.data?.technical_url;

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Analysis report" title="Report files." answer="Download files only when the analysis service reports that they are ready." />
      {status.isError ? <InlineNotice>Report status is unavailable: {getApiErrorMessage(status.error)}</InlineNotice> : null}
      <Section title="Downloads">
        {executive || technical ? (
          <div className="flex flex-wrap gap-3">
            {executive ? <ReportLink href={executive}>Download executive PDF</ReportLink> : null}
            {technical ? <ReportLink href={technical}>Download technical PDF</ReportLink> : null}
          </div>
        ) : (
          <p className="text-sm text-muted">Not returned by the API</p>
        )}
      </Section>
    </div>
  );
}
