import { CodeBlock } from "../../components/ui/CodeBlock";
import { Section, SeverityBadge } from "../../components/ui/Primitives";
import type { ComplianceReport } from "../../types";
import { buildAlgorithmComparisons, markedRemediationLines } from "./audit-data";

export function RemediationPanel({ compliance }: { compliance: ComplianceReport }) {
  const comparisons = buildAlgorithmComparisons(compliance);
  const config = compliance.remediation_config?.trim();
  if (!comparisons.length && !config) return null;

  return (
    <Section title="Detected vs required" detail="Observed values are paired only when the analysis returned a matching parameter and remediation.">
      <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        {comparisons.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[540px] border-collapse text-left text-sm">
              <caption className="sr-only">Detected cryptographic parameters and required remediation</caption>
              <thead className="border-y border-rule font-mono text-xs text-muted">
                <tr><th className="px-2 py-2 font-medium">Parameter</th><th className="px-2 py-2 font-medium">Detected</th><th className="px-2 py-2 font-medium">Required</th></tr>
              </thead>
              <tbody>
                {comparisons.map((comparison) => (
                  <tr key={`${comparison.finding.rule_id}-${comparison.parameter}`} className="border-b border-rule/70 align-top">
                    <td className="px-2 py-3"><div className="flex items-center gap-2"><SeverityBadge level={comparison.finding.severity} /><span className="font-mono text-xs text-ink">{comparison.parameter}</span></div></td>
                    <td className="px-2 py-3 font-mono text-xs text-ink">{comparison.detected}</td>
                    <td className="px-2 py-3 text-muted">{comparison.required}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {config ? <CodeBlock code={config} fileName="swanctl.conf" markedLines={markedRemediationLines(config, comparisons)} /> : null}
      </div>
    </Section>
  );
}
