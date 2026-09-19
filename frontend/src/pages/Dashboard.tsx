import { Link } from "react-router-dom";
import { InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { recordedAnalysisPath, recordedSampleCaptures, useTestbedSamples } from "../lib/sample-captures";

export default function Dashboard() {
  const testbedSamples = useTestbedSamples();
  const recordedSample = recordedSampleCaptures[0];

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="IPsec protocol analysis"
        title="Start an analysis."
        answer="Upload a network capture to see what protection was negotiated, what traffic was observed, and the evidence behind each result."
        actions={<><Link to="/upload" className="inline-flex min-h-10 items-center bg-accent px-4 text-sm font-medium text-white transition-colors hover:bg-accent-strong focus-visible:outline-none">Upload capture</Link><Link to={recordedAnalysisPath(recordedSample)} className="inline-flex min-h-10 items-center border border-rule px-4 text-sm font-medium text-ink hover:border-accent focus-visible:outline-none">Open recorded walkthrough</Link></>}
      />
      <section className="grid border-y border-rule md:grid-cols-3" aria-label="Analysis workflow">
        <WorkflowStep number="01" title="Capture" detail="Upload a .pcap or .pcapng file. Your browser retains the returned capture identity for this session." />
        <WorkflowStep number="02" title="Evidence" detail="Review the observed IKE negotiation, classified ESP flows, and what the capture cannot establish." />
        <WorkflowStep number="03" title="Decision" detail="Read the configuration verdict, findings, and generated remediation evidence." />
      </section>
      <Section title="Recorded walkthrough" detail="A bundled, fixture-backed result. It is clearly separate from a live testbed capture.">
        <div className="grid gap-4 border border-rule bg-surface p-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
          <div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-muted"><span>{recordedSample.category}</span><span>{recordedSample.rfcStatus}</span><span>{recordedSample.cipher}</span></div>
            <h3 className="mt-2 text-base font-semibold text-ink">{recordedSample.title}</h3>
            <p className="mt-1 max-w-2xl text-sm text-muted">{recordedSample.description}</p>
            <p className="mt-3 font-mono text-xs text-muted">{recordedSample.filename}</p>
          </div>
          <Link to={recordedAnalysisPath(recordedSample)} className="inline-flex min-h-10 items-center justify-center border border-rule px-4 text-sm font-medium text-ink hover:border-accent focus-visible:outline-none">Review evidence</Link>
        </div>
      </Section>
      <Section title="Live testbed captures" detail="Published by the connected Janus service; no sample is substituted if it is unavailable.">
        {testbedSamples.isPending ? <LoadingState label="Checking the live testbed catalogue…" /> : null}
        {testbedSamples.isError ? <InlineNotice>Live testbed catalogue unavailable: {getApiErrorMessage(testbedSamples.error)}</InlineNotice> : null}
        {testbedSamples.data?.length === 0 ? <InlineNotice>The connected service returned no testbed captures.</InlineNotice> : null}
        {testbedSamples.data?.length ? <div className="grid gap-px border border-rule bg-rule sm:grid-cols-2 lg:grid-cols-3">{testbedSamples.data.map((sample) => <article key={sample.id} className="bg-surface p-4"><p className="font-mono text-xs text-muted">{sample.category} · {sample.rfc_status}</p><h3 className="mt-2 font-medium text-ink">{sample.title}</h3><p className="mt-1 text-sm text-muted">{sample.description}</p><p className="mt-3 font-mono text-xs text-muted">{sample.cipher}</p></article>)}</div> : null}
      </Section>
    </div>
  );
}

function WorkflowStep({ number, title, detail }: { number: string; title: string; detail: string }) {
  return <article className="border-rule px-4 py-5 first:border-b md:border-b-0 md:border-l md:first:border-l-0 sm:px-5"><p className="font-mono text-xs text-muted">{number}</p><h2 className="mt-2 text-base font-semibold text-ink">{title}</h2><p className="mt-1 text-sm text-muted">{detail}</p></article>;
}
