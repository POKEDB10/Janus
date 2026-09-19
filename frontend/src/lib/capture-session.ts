import type { CaptureContext, UploadResponse } from "../types";

const storageKey = "janus.capture-contexts";

function getContexts(): Record<string, CaptureContext> {
  try {
    const parsed: unknown = JSON.parse(sessionStorage.getItem(storageKey) ?? "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, CaptureContext>
      : {};
  } catch {
    return {};
  }
}

export function saveCaptureContext(upload: UploadResponse): CaptureContext {
  const context: CaptureContext = {
    captureId: upload.capture_id,
    filename: upload.filename,
    sizeBytes: upload.size_bytes,
    captureToken: upload.capture_token ?? undefined,
  };
  const contexts = getContexts();
  contexts[context.captureId] = context;
  sessionStorage.setItem(storageKey, JSON.stringify(contexts));
  return context;
}

export function getCaptureContext(captureId: string): CaptureContext {
  return getContexts()[captureId] ?? { captureId };
}

export function isRecordedSample(search: string): boolean {
  return new URLSearchParams(search).get("demo") === "1";
}

export function isPresentationMode(search: string): boolean {
  return new URLSearchParams(search).get("present") === "1";
}
