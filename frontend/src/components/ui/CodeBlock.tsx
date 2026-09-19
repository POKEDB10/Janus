import { useState } from "react";
import { Check, Copy, Download } from "lucide-react";

export function CodeBlock({
  code,
  markedLines = [],
  fileName,
}: {
  code: string;
  markedLines?: number[];
  fileName?: string;
}) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const marked = new Set(markedLines);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
    window.setTimeout(() => setCopyState("idle"), 1600);
  };

  const download = () => {
    const blob = new Blob([code], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName ?? "janus-remediation.conf";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="border border-rule bg-sunken">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule px-3 py-2">
        <p className="font-mono text-xs text-muted">{fileName ?? "configuration"}</p>
        <div className="flex items-center gap-3">
          <button type="button" onClick={copy} className="inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:text-accent-strong">
            {copyState === "copied" ? <Check aria-hidden="true" className="size-3.5" /> : <Copy aria-hidden="true" className="size-3.5" />}
            {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : "Copy"}
          </button>
          <button type="button" onClick={download} className="inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:text-accent-strong"><Download aria-hidden="true" className="size-3.5" />Download</button>
        </div>
      </div>
      <pre className="max-h-96 overflow-auto p-3 text-xs leading-5 text-ink"><code>{code.split("\n").map((line, index) => <span key={`${index}-${line}`} className={`block ${marked.has(index + 1) ? "border-l-2 border-accent bg-accent/10 pl-2" : ""}`}><span className="mr-4 inline-block w-5 select-none text-right text-muted">{index + 1}</span>{line || " "}</span>)}</code></pre>
    </div>
  );
}
