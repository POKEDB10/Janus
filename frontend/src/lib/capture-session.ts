import type { CaptureContext, UploadResponse } from "../types";

const storageKey = "janus.capture-contexts";

function getContexts(): Record<string, CaptureContext> {
  try {
    const raw = (typeof localStorage !== "undefined" ? localStorage.getItem(storageKey) : null)
      || (typeof sessionStorage !== "undefined" ? sessionStorage.getItem(storageKey) : null);
    const parsed: unknown = JSON.parse(raw ?? "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, CaptureContext>
      : {};
  } catch {
    return {};
  }
}

function persistContexts(contexts: Record<string, CaptureContext>): void {
  try {
    const serialized = JSON.stringify(contexts);
    if (typeof localStorage !== "undefined") localStorage.setItem(storageKey, serialized);
    if (typeof sessionStorage !== "undefined") sessionStorage.setItem(storageKey, serialized);
  } catch {}
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
  persistContexts(contexts);
  return context;
}

export function saveTokenForCapture(captureId: string, token: string): void {
  if (!captureId || !token) return;
  const contexts = getContexts();
  const existing = contexts[captureId] ?? { captureId };
  existing.captureToken = token;
  contexts[captureId] = existing;
  persistContexts(contexts);
}

export function getCaptureContext(captureId: string, search?: string): CaptureContext {
  const contexts = getContexts();
  const existing = contexts[captureId] ? { ...contexts[captureId] } : { captureId };

  // If a token is in the URL search query, honor and persist it
  if (search) {
    try {
      const urlToken = new URLSearchParams(search).get("token");
      if (urlToken && !existing.captureToken) {
        existing.captureToken = urlToken;
        contexts[captureId] = existing;
        persistContexts(contexts);
      }
    } catch {}
  }

  return existing;
}

export function isRecordedSample(search: string): boolean {
  return new URLSearchParams(search).get("demo") === "1";
}

export function isPresentationMode(search: string): boolean {
  return new URLSearchParams(search).get("present") === "1";
}
