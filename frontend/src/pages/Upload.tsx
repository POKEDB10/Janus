import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { FileCheck2, UploadCloud } from "lucide-react";
import { Link } from "react-router-dom";
import { getAnalysisStatus, streamAnalysisProgress, uploadPcap } from "../api/client";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import { saveCaptureContext } from "../lib/capture-session";
import { cn } from "../lib/cn";
import { formatBytes } from "../lib/format";
import { recordedAnalysisPath, recordedSampleCaptures, sampleDownloadHref, useTestbedSamples } from "../lib/sample-captures";
import type { AnalysisStatus, SamplePcap } from "../types";

const statusText: Record<AnalysisStatus["status"], string> = {
  INIT: "Queued", PARSING: "Parsing capture", CLASSIFYING: "Classifying ESP traffic", SCORING: "Auditing configuration", DONE: "Complete", ERROR: "Failed",
};

type MonitoringMode = "idle" | "streaming" | "polling";

function mergeStreamStatus(
  captureId: string,
  current: AnalysisStatus | null,
  next: Partial<AnalysisStatus>,
): AnalysisStatus {
  const initial: AnalysisStatus = { capture_id: captureId, status: "INIT", progress_pct: 0, logs: [], error: null };
  return { ...initial, ...current, ...next, error: null };
}

export default function Upload() {
  const fileInput = useRef<HTMLInputElement>(null);
  const stream = useRef<EventSource | null>(null);
  const timer = useRef<number | null>(null);
  const dragDepth = useRef(0);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [monitoringMode, setMonitoringMode] = useState<MonitoringMode>("idle");
  const [connectionNote, setConnectionNote] = useState<string | null>(null);
  const [isDragActive, setIsDragActive] = useState(false);
  const samples = useTestbedSamples();

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
      if (next.status === "ERROR") {
        setError(next.error ?? next.message ?? "The analysis pipeline reported an error.");
        setMonitoringMode("idle");
        return;
      }
      if (next.status === "DONE") {
        setMonitoringMode("idle");
        return;
      }
      timer.current = window.setTimeout(() => void poll(captureId, captureToken, Math.min(delay * 1.5, 4_000)), delay);
    } catch (pollError) {
      if (failures >= 3) {
        setError(`Unable to retrieve pipeline status after four attempts: ${getApiErrorMessage(pollError)}`);
        setMonitoringMode("idle");
        return;
      }
      timer.current = window.setTimeout(() => void poll(captureId, captureToken, Math.min(delay * 2, 6_000), failures + 1), delay);
    }
  }, []);

  const monitor = useCallback((captureId: string, captureToken: string | undefined) => {
    clearMonitoring();
    setMonitoringMode("streaming");
    setConnectionNote(null);
    stream.current = streamAnalysisProgress(captureId, captureToken, {
      onProgress: (next) => setStatus((current) => mergeStreamStatus(captureId, current, next)),
      onDone: (next) => {
        setStatus((current) => ({ ...mergeStreamStatus(captureId, current, next), status: "DONE", progress_pct: 100 }));
        setMonitoringMode("idle");
      },
      onFailure: (message) => {
        clearMonitoring();
        setMonitoringMode("polling");
        setConnectionNote(`Live progress disconnected (${message}). Continuing with status polling.`);
        void poll(captureId, captureToken, 1_000);
      },
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

  function dragEnter(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    dragDepth.current += 1;
    setIsDragActive(true);
  }

  function dragLeave(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setIsDragActive(false);
  }

  function dragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  }

  function drop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    dragDepth.current = 0;
    setIsDragActive(false);
    const next = event.dataTransfer.files.item(0);
    if (next) chooseFile(next);
  }

  async function submit() {
    if (!file) return;
    clearMonitoring();
    setUploading(true);
    setUploadProgress(0);
    setError(null);
    setStatus(null);
    setConnectionNote(null);
    setMonitoringMode("idle");
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

  const analysisLink = status?.status === "DONE" ? `/analysis/${encodeURIComponent(status.capture_id)}` : null;

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Capture intake" title="Upload an IPsec capture." answer="Drop a capture file to see its observed negotiation, traffic patterns, and configuration evidence. Technical details remain available when you need them." />
      <section className="border-y border-rule py-6" aria-labelledby="capture-file">
        <h2 id="capture-file" className="sr-only">Capture file</h2>
        <div onDrop={drop} onDragEnter={dragEnter} onDragLeave={dragLeave} onDragOver={dragOver} data-drag-active={isDragActive} className={cn("drop-zone grid min-h-52 place-items-center border border-dashed bg-surface p-6 text-center", isDragActive ? "is-drag-active border-accent bg-sunken" : "border-rule")}>
          <div aria-live="polite">
            <div className="mx-auto grid size-10 place-items-center border border-rule bg-sunken text-accent">
              {file ? <FileCheck2 aria-hidden="true" className="size-5" /> : <UploadCloud aria-hidden="true" className="size-5" />}
            </div>
            <p className="mt-3 font-medium text-ink">{file ? file.name : isDragActive ? "Release to add this capture" : "Drag a capture here"}</p>
            <p className="mt-1 text-sm text-muted">{file ? `${formatBytes(file.size)} · ready to analyze` : "or choose a .pcap or .pcapng file from this device"}</p>
            <input ref={fileInput} type="file" accept=".pcap,.pcapng" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(event) => { const next = event.currentTarget.files?.item(0); if (next) chooseFile(next); }} />
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
        <Section title="Pipeline" detail="Live status is delivered by the analysis service." action={analysisLink ? <Link className="text-sm font-medium text-accent underline underline-offset-4" to={analysisLink}>Open workspace</Link> : null}>
          <div className="grid gap-4 sm:grid-cols-[auto_1fr] sm:items-center"><p className="data-number font-mono text-2xl text-ink">{Math.round(status.progress_pct)}%</p><div><p className="font-medium text-ink">{statusText[status.status]}</p><p className="mt-1 text-sm text-muted">{status.message ?? "Waiting for pipeline status."}</p></div></div>
          {monitoringMode === "streaming" ? <p className="mt-3 font-mono text-xs text-muted">Receiving live progress events.</p> : null}
          {monitoringMode === "polling" ? <p className="mt-3 font-mono text-xs text-muted">Polling status while the live stream is unavailable.</p> : null}
          {connectionNote ? <InlineNotice>{connectionNote}</InlineNotice> : null}
          {status.logs.length ? <pre className="mt-4 max-h-44 overflow-auto border-t border-rule pt-3 font-mono text-xs leading-5 text-muted" aria-live="polite">{status.logs.join("\n")}</pre> : null}
        </Section>
      ) : null}
      {samples.isPending ? <LoadingState label="Loading testbed captures…" /> : null}
      {samples.isError ? <InlineNotice>Sample captures are unavailable: {getApiErrorMessage(samples.error)}</InlineNotice> : null}
      {samples.data?.length === 0 ? <InlineNotice>No sample captures returned by the API.</InlineNotice> : null}
      {samples.data?.length ? <Section title="Live testbed captures" detail="Published by the connected Janus service."><SampleTable samples={samples.data} /></Section> : null}
      <Section title="Recorded walkthrough" detail="Fixture-backed evidence for reviewing the workspace without uploading a file.">
        <div className="grid gap-px border border-rule bg-rule md:grid-cols-2">{recordedSampleCaptures.map((sample) => <article key={sample.id} className="bg-surface p-4"><p className="font-mono text-xs text-muted">{sample.category} · {sample.rfcStatus} · {sample.cipher}</p><h3 className="mt-2 font-medium text-ink">{sample.title}</h3><p className="mt-1 text-sm text-muted">{sample.description}</p><Link to={recordedAnalysisPath(sample)} className="mt-3 inline-flex text-sm font-medium text-accent underline underline-offset-4">Open recorded evidence</Link></article>)}</div>
      </Section>
    </div>
  );
}

function SampleTable({ samples }: { samples: SamplePcap[] }) {
  return <div className="overflow-x-auto"><table className="w-full min-w-[720px] border-collapse text-left text-sm"><caption className="sr-only">Live testbed captures</caption><thead className="border-y border-rule font-mono text-xs text-muted"><tr><th className="px-2 py-2 font-medium">Capture</th><th className="px-2 py-2 font-medium">Category</th><th className="px-2 py-2 font-medium">RFC status</th><th className="px-2 py-2 font-medium">Cipher</th><th className="px-2 py-2 font-medium">File</th></tr></thead><tbody>{samples.map((sample) => <tr key={sample.id} className="border-b border-rule/70"><td className="px-2 py-3 text-ink"><p>{sample.title}</p><p className="mt-1 text-xs text-muted">{sample.description}</p></td><td className="px-2 py-3 text-muted">{sample.category}</td><td className="px-2 py-3 text-muted">{sample.rfc_status}</td><td className="px-2 py-3 font-mono text-xs text-muted">{sample.cipher}</td><td className="px-2 py-3"><a className="text-accent underline underline-offset-4" href={sampleDownloadHref(sample)} download={sample.filename}>Download .pcap</a></td></tr>)}</tbody></table></div>;
}
