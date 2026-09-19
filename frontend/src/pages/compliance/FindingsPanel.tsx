import { ExternalLink } from "lucide-react";
import { Section, SeverityBadge } from "../../components/ui/Primitives";
import type { Finding } from "../../types";

function AdvisoryDetails({ finding }: { finding: Finding }) {
  const hasAdvisory = finding.cve_id || finding.cwe_id || finding.cvss_score !== null && finding.cvss_score !== undefined || finding.nvd_url;
  if (!hasAdvisory) return null;
  return (
    <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs">
      {finding.cve_id ? <div><dt className="inline text-muted">CVE </dt><dd className="inline font-mono text-ink">{finding.cve_id}</dd></div> : null}
      {finding.cwe_id ? <div><dt className="inline text-muted">CWE </dt><dd className="inline font-mono text-ink">{finding.cwe_id}</dd></div> : null}
      {finding.cvss_score !== null && finding.cvss_score !== undefined ? <div><dt className="inline text-muted">CVSS </dt><dd className="data-number inline font-mono text-ink">{finding.cvss_score.toFixed(1)}</dd></div> : null}
      {finding.nvd_url ? <div><a className="inline-flex items-center gap-1 font-medium text-accent underline underline-offset-4" href={finding.nvd_url} target="_blank" rel="noreferrer">NVD advisory<ExternalLink aria-hidden="true" className="size-3" /></a></div> : null}
    </dl>
  );
}

export function FindingsPanel({ findings, onExplain }: { findings: Finding[]; onExplain?: (finding: Finding) => void }) {
  if (!findings.length) return null;
  return (
    <Section title="Findings" detail="Configuration evidence returned with this analysis.">
      <div>
        {findings.map((finding) => (
          <article key={`${finding.rule_id}-${finding.parameter}`} className="border-t border-rule py-5 first:border-t-0 first:pt-0">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2"><SeverityBadge level={finding.severity} /><span className="font-mono text-xs text-muted">{finding.rule_id}</span></div>
                <h3 className="mt-3 text-base font-semibold text-ink">{finding.parameter}</h3>
              </div>
              {onExplain ? <button type="button" onClick={() => onExplain(finding)} className="text-sm font-medium text-accent underline underline-offset-4">Explain with sources</button> : null}
            </div>
            <p className="mt-2 max-w-3xl text-sm text-muted">{finding.description}</p>
            {finding.value ? <p className="mt-3 font-mono text-xs text-ink"><span className="text-muted">Detected </span>{finding.value}</p> : null}
            {finding.remediation ?? finding.recommendation ? <p className="mt-3 max-w-3xl text-sm text-ink"><span className="font-medium">Remediation: </span>{finding.remediation ?? finding.recommendation}</p> : null}
            {finding.references?.length ? <p className="mt-3 text-xs text-muted"><span className="font-medium text-ink">Standards: </span>{finding.references.join(" · ")}</p> : null}
            <AdvisoryDetails finding={finding} />
          </article>
        ))}
      </div>
    </Section>
  );
}
