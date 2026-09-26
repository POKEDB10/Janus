import { useState } from "react";
import { Check, Copy, ShieldAlert, ShieldCheck } from "lucide-react";
import { Section, SeverityBadge } from "../../components/ui/Primitives";
import type { ComplianceReport } from "../../types";
import { buildAlgorithmComparisons } from "./audit-data";

export function DetectedParametersPanel({ compliance }: { compliance: ComplianceReport }) {
  const [copiedPqc, setCopiedPqc] = useState(false);
  const comparisons = buildAlgorithmComparisons(compliance);
  
  // Filter out the PQC entry from standard table rows since it has its own dedicated technical summary below
  const tableRows = comparisons.filter((c) => !c.parameter.toLowerCase().includes("post-quantum"));
  
  const isVulnerable = compliance.pqc_status === "CRQC_VULNERABLE";
  const isHybrid = compliance.pqc_status === "TRANSITIONAL_HYBRID";
  
  const evaluatedDh = compliance.evaluated_parameters?.dh_group
    ? `Group ${compliance.evaluated_parameters.dh_group} (Classical)`
    : "Classical DH / ECDH";

  const pqcProposal = "proposals = aes256gcm16-prfsha384-curve25519-mlkem768";

  const copyPqc = async () => {
    try {
      await navigator.clipboard.writeText(pqcProposal);
      setCopiedPqc(true);
      setTimeout(() => setCopiedPqc(false), 2000);
    } catch {
      // Fallback
    }
  };

  if (!comparisons.length) {
    return (
      <Section
        title="Detected cryptographic configuration"
        detail="Observed session parameters evaluated against RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 requirements."
      >
        <div className="rounded-xl border border-rule bg-surface p-5 text-xs text-muted">
          Cryptographic parameters could not be asserted directly from packet headers alone (capture began mid-stream without initial IKE exchange).
        </div>
      </Section>
    );
  }

  return (
    <Section
      title="Detected cryptographic configuration"
      detail="Observed session parameters evaluated against RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 requirements."
    >
      <div className="space-y-4">
        {/* Full-width High-Density Parameters Table */}
        <div className="overflow-x-auto rounded-xl border border-rule bg-surface shadow-sm">
          <table className="w-full min-w-[700px] border-collapse text-left text-sm">
            <caption className="sr-only">Detected cryptographic configuration parameters</caption>
            <thead className="border-b border-rule font-mono text-xs text-muted bg-sunken/40">
              <tr>
                <th scope="col" className="px-4 py-3 font-semibold">Parameter</th>
                <th scope="col" className="px-4 py-3 font-semibold">Detected Value</th>
                <th scope="col" className="px-4 py-3 font-semibold">RFC / NIST Baseline Requirement</th>
                <th scope="col" className="px-4 py-3 font-semibold text-right">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-rule/60">
              {tableRows.map((item, idx) => (
                <tr key={`${item.parameter}-${idx}`} className="align-middle hover:bg-sunken/30 transition-colors">
                  <td className="px-4 py-3 font-medium text-ink text-xs sm:text-sm">
                    {item.parameter}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-ink font-semibold">
                    {item.detected}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted leading-relaxed">
                    {item.required}
                  </td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    <SeverityBadge level={item.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Compact, Sober Technical Post-Quantum Assessment */}
        {compliance.pqc_status && (
          <div className="rounded-xl border border-rule bg-surface p-4 text-xs space-y-2.5 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-rule/60 pb-2">
              <div className="flex items-center gap-2">
                <span className="font-mono font-semibold text-ink text-[11px]">
                  Post-quantum cryptographic posture
                </span>
                <span className={`inline-flex items-center gap-1 font-mono text-xs font-semibold ${
                  isVulnerable
                    ? "text-amber-500"
                    : "text-emerald-500"
                }`}>
                  {isVulnerable ? (
                    <>
                      <ShieldAlert className="size-3.5" />
                      CRQC vulnerable (HNDL exposure)
                    </>
                  ) : isHybrid ? (
                    <>
                      <ShieldCheck className="size-3.5" />
                      RFC 9370 hybrid (Protected)
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="size-3.5" />
                      Quantum resistant
                    </>
                  )}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] text-muted">strongSwan Proposal:</span>
                <button
                  type="button"
                  onClick={copyPqc}
                  className="inline-flex items-center gap-1 font-mono text-[11px] text-accent hover:underline rounded bg-sunken px-2 py-0.5 border border-rule"
                  title="Copy strongSwan RFC 9370 proposal line"
                >
                  {copiedPqc ? (
                    <>
                      <Check className="size-3 text-pass" />
                      <span className="text-pass">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="size-3" />
                      <span>{pqcProposal}</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-[11px] text-muted pt-1">
              <div>
                <span className="text-ink font-semibold">Primitive: </span>
                {evaluatedDh} (Shor's factorable)
              </div>
              <div>
                <span className="text-ink font-semibold">Threat Model: </span>
                Harvest Now, Decrypt Later (HNDL)
              </div>
              <div>
                <span className="text-ink font-semibold">Target Standard: </span>
                RFC 9370 &amp; FIPS 203 (ML-KEM-768)
              </div>
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}
