import Markdown from "react-markdown";
import { CodeBlock } from "./CodeBlock";

interface MarkdownViewProps {
  content: string;
  className?: string;
}

function sanitizeClientProse(raw: string): string {
  if (!raw) return "";
  let text = raw;

  // Strip LaTeX math: e.g. $2^{64}$ -> 2^64, $\approx$ -> ~, $\times$ -> x
  text = text.replace(/\$([^\$]+)\$/g, (_m, g1) => {
    return g1
      .replace(/\^\{?(\d+)\}?/g, "^$1")
      .replace(/\\times/g, "x")
      .replace(/\\approx/g, "~")
      .replace(/\\le/g, "<=")
      .replace(/\\ge/g, ">=")
      .replace(/\\cdot/g, "·");
  });

  // Protect SCREAMING_SNAKE_CASE technical identifiers (cipher names, transform IDs,
  // algorithm constants like ENCR_AES_GCM_16, AUTH_NONE, ENCR_3DES) from being parsed
  // as markdown emphasis. Wrap them in backtick code spans before the parser sees them.
  // Pattern: 2+ uppercase words joined by underscores (no lowercase in between).
  text = text.replace(/\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,})\b/g, (match) => {
    // Already inside a backtick span → don't double-wrap
    return `\`${match}\``;
  });

  // Reframe blast radius / system impact headers and strip ALL-CAPS banners
  text = text.replace(/###\s+THREAT ANALYSIS/gi, "### Threat analysis");
  text = text.replace(/###\s+STANDARDS GROUNDING/gi, "### Governing standards");
  text = text.replace(/###\s+(?:SYSTEM IMPACT & BLAST RADIUS|BLAST RADIUS|System Impact & Blast Radius)/gi, "### What this means");
  text = text.replace(/###\s+(?:ACTIONABLE REMEDIATION|REMEDIATION)/gi, "### Remediation");

  // Reframe any remaining [RFC xxxx §y] bracket citations to RFC xxxx §y
  text = text.replace(/\[((?:RFC|NIST|CNSA|FIPS)[^\]]+)\]/g, "$1");

  // Remove (CoT) if present in prose
  text = text.replace(/\s*\(CoT\)/g, "");

  return text;
}

export function MarkdownView({ content, className = "" }: MarkdownViewProps) {
  if (!content) return null;
  const cleanContent = sanitizeClientProse(content);

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
            let text = rawText
              .replace(/System Impact & Blast Radius/gi, "What this means")
              .replace(/Blast Radius/gi, "What this means")
              .trim();
            if (text.length > 3 && text === text.toUpperCase() && /[A-Z]/.test(text)) {
              text = text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
            }
            return (
              <h3 className="text-xs font-semibold text-ink mt-4 mb-2 first:mt-0">
                {text || children}
              </h3>
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
                <strong className="font-mono text-xs font-semibold text-ink">
                  {children}
                </strong>
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
        {cleanContent}
      </Markdown>
    </div>
  );
}

export default MarkdownView;
