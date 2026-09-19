import type { ReactNode } from "react";
import { AlertCircle, Check, CircleAlert, LoaderCircle, RotateCcw } from "lucide-react";
import type { RiskLevel } from "../../types";

export function PageHeader({
  eyebrow,
  title,
  answer,
  actions,
}: {
  eyebrow?: string;
  title: string;
  answer: string;
  actions?: ReactNode;
}) {
  return (
    <header className="grid gap-4 pb-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
      <div className="min-w-0">
        {eyebrow ? <p className="mb-1 font-mono text-xs text-muted">{eyebrow}</p> : null}
        <h1 className="text-balance text-[28px] font-semibold leading-tight text-ink">{title}</h1>
        <p className="mt-2 max-w-3xl text-pretty text-base text-muted">{answer}</p>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2 md:justify-end">{actions}</div> : null}
    </header>
  );
}

export function Section({
  title,
  detail,
  action,
  children,
  isEmpty = false,
  className = "",
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
  children: ReactNode;
  isEmpty?: boolean;
  className?: string;
}) {
  if (isEmpty) return null;
  return (
    <section className={`border-t border-rule pt-4 ${className}`} aria-labelledby={title.replace(/\s+/g, "-").toLowerCase()}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id={title.replace(/\s+/g, "-").toLowerCase()} className="text-base font-semibold text-ink">{title}</h2>
          {detail ? <p className="mt-1 text-sm text-muted">{detail}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Stat({ label, value, detail }: { label: string; value: ReactNode; detail?: string }) {
  return (
    <div className="border-l border-rule pl-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="data-number mt-1 font-mono text-xl font-medium text-ink">{value}</p>
      {detail ? <p className="mt-1 text-xs text-muted">{detail}</p> : null}
    </div>
  );
}

const severityStyles: Record<RiskLevel, string> = {
  CRITICAL: "border-critical/40 bg-critical/10 text-critical",
  HIGH: "border-high/40 bg-high/10 text-high",
  MEDIUM: "border-medium/40 bg-medium/10 text-medium",
  LOW: "border-low/40 bg-low/10 text-low",
  INFO: "border-info/40 bg-info/10 text-info",
};

export function SeverityBadge({ level }: { level: RiskLevel | string }) {
  const normalised = (level.toUpperCase() in severityStyles ? level.toUpperCase() : "INFO") as RiskLevel;
  return <span className={`inline-flex border px-1.5 py-0.5 font-mono text-xs font-medium ${severityStyles[normalised]}`}>{normalised}</span>;
}

export function GradeMark({ score, grade, label = "Configuration verdict" }: { score: number | null; grade: string; label?: string }) {
  const state = score === null || grade === "N/A" ? "indeterminate" : score >= 80 ? "pass" : score >= 50 ? "medium" : "critical";
  const color = state === "pass" ? "text-pass" : state === "medium" ? "text-medium" : state === "critical" ? "text-critical" : "text-muted";
  const text = state === "indeterminate" ? "Not assessable" : `Grade ${grade}`;
  return (
    <div className="min-w-0">
      <p className="text-xs text-muted">{label}</p>
      <p className={`data-number mt-1 text-[28px] font-semibold leading-none ${color}`}>{text}</p>
      <p className="data-number mt-1 font-mono text-xs text-muted">{score === null ? "No score" : `${score.toFixed(0)} / 100`}</p>
    </div>
  );
}

export function SampleStamp() {
  return <p className="border-b border-rule bg-sunken px-4 py-2 text-center text-xs text-muted">Recorded sample, not a live analysis</p>;
}

export function LoadingState({ label = "Loading analysis…" }: { label?: string }) {
  return (
    <div className="flex min-h-36 items-center gap-3 border-t border-rule py-8 text-sm text-muted" aria-live="polite" aria-busy="true">
      <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <div className="border-t border-rule py-8">
      <h2 className="text-base font-semibold text-ink">{title}</h2>
      <p className="mt-1 max-w-xl text-sm text-muted">{detail}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ title = "Couldn’t load this analysis", detail, onRetry }: { title?: string; detail: string; onRetry?: () => void }) {
  return (
    <div className="border-l-2 border-critical bg-surface px-4 py-4" role="alert">
      <div className="flex gap-3">
        <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-critical" />
        <div>
          <h2 className="font-medium text-ink">{title}</h2>
          <p className="mt-1 text-sm text-muted">{detail}</p>
          {onRetry ? <button type="button" onClick={onRetry} className="mt-3 inline-flex items-center gap-2 text-sm font-medium text-accent hover:text-accent-strong"><RotateCcw aria-hidden="true" className="size-4" />Retry</button> : null}
        </div>
      </div>
    </div>
  );
}

export function InlineNotice({ children }: { children: ReactNode }) {
  return <p className="flex items-start gap-2 text-sm text-muted"><AlertCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />{children}</p>;
}

export function CopyResult({ copied }: { copied: boolean }) {
  return copied ? <Check aria-hidden="true" className="size-4 text-pass" /> : null;
}
