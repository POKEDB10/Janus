import Markdown from "react-markdown";
import { AlertTriangle, BookOpen, CheckCircle2, ShieldAlert } from "lucide-react";
import { CodeBlock } from "./CodeBlock";
import { cn } from "../../lib/cn";

interface MarkdownViewProps {
  content: string;
  className?: string;
}

export function MarkdownView({ content, className = "" }: MarkdownViewProps) {
  if (!content) return null;

  return (
    <div className={`prose-sm text-xs leading-relaxed ${className}`}>
      <Markdown
        components={{
          h1: ({ children }) => (
            <h1 className="text-base font-bold text-ink mt-4 mb-2 first:mt-0 pb-1.5 border-b border-rule/60">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-sm font-bold text-ink mt-4 mb-2 first:mt-0">
              {children}
            </h2>
          ),
          h3: ({ children }) => {
            const rawText = Array.isArray(children) ? children.join("") : String(children ?? "");
            const text = rawText.toLowerCase();
            const isThreat = text.includes("threat") || text.includes("cryptanalytic") || text.includes("mathematical");
            const isStandards = text.includes("standard") || text.includes("grounding") || text.includes("primary");
            const isImpact = text.includes("impact") || text.includes("blast");
            const isRemediation = text.includes("remediation") || text.includes("actionable") || text.includes("verified");

            const Icon = isThreat
              ? AlertTriangle
              : isStandards
              ? BookOpen
              : isImpact
              ? ShieldAlert
              : isRemediation
              ? CheckCircle2
              : null;

            return (
              <div
                className={cn(
                  "mt-5 mb-2.5 flex items-center gap-2.5 rounded-lg border px-3 py-2 text-xs font-mono font-bold tracking-wider uppercase",
                  isThreat
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-500 dark:text-amber-400"
                    : isStandards
                    ? "border-accent/30 bg-accent/10 text-accent dark:text-accent-strong"
                    : isImpact
                    ? "border-critical/30 bg-critical/10 text-critical"
                    : isRemediation
                    ? "border-pass/30 bg-pass/10 text-pass"
                    : "border-rule bg-sunken text-ink"
                )}
              >
                {Icon && <Icon className="size-4 shrink-0" />}
                <span>{children}</span>
              </div>
            );
          },
          h4: ({ children }) => (
            <h4 className="text-xs font-semibold text-ink mt-3 mb-1">
              {children}
            </h4>
          ),
          p: ({ children }) => (
            <p className="text-xs sm:text-[13px] leading-relaxed text-ink/90 mb-3 last:mb-0">
              {children}
            </p>
          ),
          strong: ({ children }) => (
            <strong className="font-semibold text-ink">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="italic text-ink/90">{children}</em>
          ),
          ul: ({ children }) => (
            <ul className="list-disc list-inside space-y-1.5 text-xs sm:text-[13px] text-ink/80 mb-3 pl-1">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal list-inside space-y-1.5 text-xs sm:text-[13px] text-ink/80 mb-3 pl-1">
              {children}
            </ol>
          ),
          li: ({ children }) => <li className="leading-relaxed">{children}</li>,
          code: ({ children, className }) => {
            const isInline = !className;
            if (isInline) {
              return (
                <code className="rounded bg-sunken px-1.5 py-0.5 font-mono text-[11px] text-accent border border-rule/60 font-medium">
                  {children}
                </code>
              );
            }
            const codeString = String(children).replace(/\n$/, "");
            const lang = className?.replace("language-", "") || "swanctl.conf";
            return (
              <div className="my-3 overflow-hidden rounded-xl border border-rule shadow-sm">
                <CodeBlock code={codeString} fileName={lang === "text" ? "swanctl.conf" : lang} />
              </div>
            );
          },
          blockquote: ({ children }) => (
            <blockquote className="border-l-4 border-accent bg-accent/5 rounded-r-lg px-4 py-2.5 text-xs text-ink/80 italic my-3">
              {children}
            </blockquote>
          ),
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent underline hover:text-accent-strong transition-colors"
            >
              {children}
            </a>
          ),
        }}
      >
        {content}
      </Markdown>
    </div>
  );
}

export default MarkdownView;
