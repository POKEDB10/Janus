import { Download } from "lucide-react";
import type { ComplianceReport } from "../../types";

function exportName(captureId: string): string {
  const safeId = captureId.replace(/[^a-z0-9._-]/gi, "-") || "analysis";
  return `janus-${safeId}-compliance.json`;
}

export function JsonExport({ captureId, compliance }: { captureId: string; compliance: ComplianceReport }) {
  const download = () => {
    const payload = JSON.stringify(compliance, null, 2);
    const url = URL.createObjectURL(new Blob([payload], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = exportName(captureId);
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button type="button" onClick={download} className="inline-flex items-center gap-2 bg-accent px-3 py-2 text-sm font-medium text-white hover:bg-accent-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2">
      <Download aria-hidden="true" className="size-4" />
      Export JSON
    </button>
  );
}
