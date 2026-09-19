import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { Link } from "react-router-dom";
import { API_BASE_URL, getAnalysisStatus, getSamplePcaps, streamAnalysisProgress, uploadPcap } from "../api/client";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { saveCaptureContext } from "../lib/capture-session";
import { formatBytes } from "../lib/format";
import type { AnalysisStatus, SamplePcap } from "../types";

const statusText: Record<AnalysisStatus["status"], string> = {
  INIT: "Queued", PARSING: "Parsing capture", CLASSIFYING: "Classifying ESP traffic", SCORING: "Auditing configuration", DONE: "Complete", ERROR: "Failed",
};

function downloadUrl(sample: SamplePcap) {
  return `${API_BASE_URL}${sample.download_url}`;
}

export default function Upload() {
  const fileInput = useRef<HTMLInputElement>(null);
  const stream = useRef<EventSource | null>(null);
  const timer = useRef<number | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const samples = useQuery({ queryKey: ["samples"], queryFn: getSamplePcaps, retry: false });

  const clearMonitoring = useCallback(() => {
    stream.current?.close();
    stream.current = null;
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = null;
  }, []);

  const poll = useCallback(async (captureId: string, captureToken: string | undefined, delay: number, failures = 0) => {
    try {
      const next = await getAnalysisStatus(captureId, captureToken);
      setStatus(next);
      if (next.status === "DONE" || next.status === "ERROR") return;
      timer.current = window.setTimeout(() => void poll(captureId, captureToken, Math.min(delay * 1.5, 4_000)), delay);
    } catch (pollError) {
      if (failures >= 3) {
        setError(getApiErrorMessage(pollError));
        return;
      }
      timer.current = window.setTimeout(() => void poll(captureId, captureToken, Math.min(delay * 2, 6_000), failures + 1), delay);
    }
  }, []);

  const monitor = useCallback((captureId: string, captureToken: string | undefined) => {
    clearMonitoring();
    stream.current = streamAnalysisProgress(captureId, captureToken, {
      onProgress: (next) => setStatus((current) => ({ capture_id: captureId, error: null, ...current, ...next })),
      onDone: (next) => setStatus((current) => ({ capture_id: captureId, error: null, ...current, ...next, status: "DONE", progress_pct: 100 })),
      onFailure: () => { void poll(captureId, captureToken, 1_000); },
    });
  }, [clearMonitoring, poll]);

  useEffect(() => () => clearMonitoring(), [clearMonitoring]);

  function chooseFile(next: File) {
    if (!/\.pcapng?$/i.test(next.name)) {
      setError("Choose a .pcap or .pcapng capture.");
      return;
    }
    setFile(next);
    setError(null);
  }

  function drop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const next = event.dataTransfer.files.item(0);
    if (next) chooseFile(next);
  }

  async function submit() {
    if (!file) return;
    setUploading(true);
    setError(null);
    setStatus(null);
    try {
      const response = await uploadPcap(file, setUploadProgress);
      saveCaptureContext(response);
      setStatus({ capture_id: response.capture_id, status: "INIT", progress_pct: 0, message: "Capture accepted", logs: [] });
      monitor(response.capture_id, response.capture_token ?? undefined);
    } catch (uploadError) {
      setError(getApiErrorMessage(uploadError));
    } finally {
      setUploading(false);
    }
  }

  const analysisLink = status?.capture_id ? `/analysis/${encodeURIComponent(status.capture_id)}` : null;

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Capture intake" title="Upload an IPsec capture." answer="Janus parses IKE where present, classifies ESP traffic, and audits the negotiated configuration." />
      <section className="border-y border-rule py-6" aria-labelledby="capture-file">
        <h2 id="capture-file" className="sr-only">Capture file</h2>
        <div onDrop={drop} onDragOver={(event) => event.preventDefault()} className="grid min-h-48 place-items-center border border-dashed border-rule bg-surface p-6 text-center">
          <div>
            <p className="font-medium text-ink">{file ? file.name : "Drop a .pcap or .pcapng file here"}</p>
            <p className="mt-1 text-sm text-muted">{file ? formatBytes(file.size) : "or choose a file from this device"}</p>
            <input ref={fileInput} type="file" accept=".pcap,.pcapng" className="sr-only" onChange={(event) => { const next = event.currentTarget.files?.item(0); if (next) chooseFile(next); }} />
            <div className="mt-4 flex flex-wrap justify-center gap-3">
              <button type="button" onClick={() => fileInput.current?.click()} className="min-h-10 border border-rule px-4 text-sm font-medium text-ink hover:border-accent focus-visible:outline-none">Choose file</button>
              <button type="button" onClick={() => void submit()} disabled={!file || uploading} className="min-h-10 bg-accent px-4 text-sm font-medium text-white disabled:cursor-not-allowed disabled:bg-rule hover:bg-accent-strong focus-visible:outline-none">{uploading ? "Uploading…" : "Analyze capture"}</button>
            </div>
          </div>
        </div>
        {uploading ? <p className="data-number mt-3 font-mono text-xs text-muted">Upload {uploadProgress}%</p> : null}
      </section>
      {error ? <ErrorState title="Upload or analysis failed" detail={error} onRetry={file ? () => void submit() : undefined} /> : null}
      {status ? (
        <Section title="Pipeline" detail="Live status is delivered by the analysis service." action={analysisLink ? <Link className="text-sm font-medium text-accent underline underline-offset-4" to={analysisLink}>Open flows</Link> : null}>
          <div className="grid gap-4 sm:grid-cols-[auto_1fr] sm:items-center"><p className="data-number font-mono text-2xl text-ink">{Math.round(status.progress_pct)}%</p><div><p className="font-medium text-ink">{statusText[status.status]}</p><p className="mt-1 text-sm text-muted">{status.message ?? "Waiting for pipeline status."}</p></div></div>
          {status.logs.length ? <pre className="mt-4 max-h-44 overflow-auto border-t border-rule pt-3 font-mono text-xs leading-5 text-muted" aria-live="polite">{status.logs.join("\n")}</pre> : null}
        </Section>
      ) : null}
      {samples.isPending ? <LoadingState label="Loading testbed captures…" /> : null}
      {samples.isError ? <InlineNotice>Sample captures are unavailable: {getApiErrorMessage(samples.error)}</InlineNotice> : null}
      {samples.data?.length === 0 ? <InlineNotice>No sample captures returned by the API.</InlineNotice> : null}
      {samples.data?.length ? <Section title="Testbed captures" detail="Sample captures from the Janus testbed."><SampleTable samples={samples.data} /></Section> : null}
    </div>
  );
}

function SampleTable({ samples }: { samples: SamplePcap[] }) {
  return <div className="overflow-x-auto"><table className="w-full min-w-[640px] border-collapse text-left text-sm"><caption className="sr-only">Testbed captures</caption><thead className="border-y border-rule font-mono text-xs text-muted"><tr><th className="px-2 py-2 font-medium">Capture</th><th className="px-2 py-2 font-medium">Category</th><th className="px-2 py-2 font-medium">Cipher</th><th className="px-2 py-2 font-medium">File</th></tr></thead><tbody>{samples.map((sample) => <tr key={sample.id} className="border-b border-rule/70"><td className="px-2 py-3 text-ink">{sample.title}</td><td className="px-2 py-3 text-muted">{sample.category}</td><td className="px-2 py-3 font-mono text-xs text-muted">{sample.cipher}</td><td className="px-2 py-3"><a className="text-accent underline underline-offset-4" href={downloadUrl(sample)} download={sample.filename}>Download .pcap</a></td></tr>)}</tbody></table></div>;
}
