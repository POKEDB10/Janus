import { CodeBlock } from "../../components/ui/CodeBlock";
import { Section, SeverityBadge } from "../../components/ui/Primitives";
import type { ComplianceReport } from "../../types";
import { buildAlgorithmComparisons, markedRemediationLines } from "./audit-data";

export function RemediationPanel({ compliance }: { compliance: ComplianceReport }) {
  const comparisons = buildAlgorithmComparisons(compliance);
  const config = compliance.remediation_config?.trim();
  if (!comparisons.length && !config) return null;

  return (
    <Section
      title="Detected vs required"
      detail="Observed cryptographic parameters evaluated against RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 requirements."
    >
      <div className="grid gap-8 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        {comparisons.length ? (
          <div className="overflow-x-auto rounded-xl border border-rule bg-surface p-4 shadow-sm">
            <table className="w-full min-w-[540px] border-collapse text-left text-sm">
              <caption className="sr-only">Detected cryptographic parameters and required remediation</caption>
              <thead className="border-b border-rule font-mono text-xs text-muted">
                <tr>
                  <th scope="col" className="px-2 py-2 font-medium">Status &amp; Parameter</th>
                  <th scope="col" className="px-2 py-2 font-medium">Detected</th>
                  <th scope="col" className="px-2 py-2 font-medium">Required Specification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule/60">
                {comparisons.map((comparison, idx) => (
                  <tr key={`${comparison.parameter}-${idx}`} className="align-top hover:bg-sunken/40 transition-colors">
                    <td className="px-2 py-3">
                      <div className="flex items-center gap-2">
                        <SeverityBadge level={comparison.status} />
                        <span className="font-mono text-xs font-semibold text-ink">{comparison.parameter}</span>
                      </div>
                    </td>
                    <td className="px-2 py-3 font-mono text-xs text-ink">{comparison.detected}</td>
                    <td className="px-2 py-3 text-xs text-muted leading-relaxed">{comparison.required}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded-xl border border-rule bg-surface p-5 text-xs text-muted">
            Cryptographic parameters could not be evaluated directly from packet headers (pre-handshake or mid-stream traffic).
          </div>
        )}
        {config ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-muted">
                Remediation Policy
              </h3>
              <span className="font-mono text-[10px] text-muted">
                /etc/swanctl/conf.d/janus-remediated.conf
              </span>
            </div>
            <CodeBlock code={config} fileName="swanctl.conf" markedLines={markedRemediationLines(config, comparisons)} />
          </div>
        ) : null}
      </div>
    </Section>
  );
}
