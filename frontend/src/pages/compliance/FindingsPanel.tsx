import { BookOpen, ExternalLink, Lightbulb } from "lucide-react";
import { Section } from "../../components/ui/Primitives";
import RiskBadge from "../../components/RiskBadge";
import type { Finding } from "../../types";

const FIX_SUGGESTIONS: Record<string, string> = {
  "RFC8221-ENCR_3DES":
    "Change ESP cipher from 3DES → AES-256-GCM-16 in swanctl.conf. Resolves CVE-2016-2183 Sweet32 collision risks. Estimated effort: 2 minutes.",
  "RFC8221-ENCR_BLOWFISH":
    "Replace Blowfish with AES-256-GCM-16. Blowfish is MUST NOT per RFC 8221 §5.",
  "RFC8247-DH_GROUP_2":
    "Upgrade DH Group 2 (MODP-1024) → Group 19 (ECP-256) in your IKEv2 proposal. Mitigates Logjam discrete log attacks. Estimated effort: 5 minutes.",
  "RFC8247-DH_GROUP_1":
    "Upgrade DH Group 1 (MODP-768) → Group 19 (ECP-256). Group 1 is cryptographically broken.",
  "RFC8221-AUTH_HMAC_MD5_96":
    "Replace HMAC-MD5-96 with AEAD cipher (drop separate auth) or HMAC-SHA2-256-128. Estimated effort: 2 minutes.",
  "RFC8221-AUTH_HMAC_SHA1_96":
    "Migrate from HMAC-SHA1-96 to HMAC-SHA2-256-128 or switch to an AEAD cipher.",
  "NIST-SA_LIFETIME":
    "Reduce SA lifetime to ≤ 4h (14400 s) per NIST SP 800-77 Rev. 1 §7.2.3. One config line change.",
  "NIST-PFS":
    "Enable Perfect Forward Secrecy (PFS) by configuring a Child SA DH group. Estimated effort: 1 minute.",
};

function getFixSuggestion(ruleId?: string): string | null {
  if (!ruleId) return null;
  for (const [key, val] of Object.entries(FIX_SUGGESTIONS)) {
    if (ruleId.toUpperCase().includes(key.toUpperCase())) return val;
  }
  return null;
}

function AdvisoryDetails({ finding }: { finding: Finding }) {
  const hasAdvisory = finding.cve_id || finding.cwe_id || (finding.cvss_score !== null && finding.cvss_score !== undefined) || finding.nvd_url;
  if (!hasAdvisory) return null;
  return (
    <dl className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
      {finding.cve_id ? (
        <div className="rounded bg-red-500/10 border border-red-500/20 px-2 py-0.5">
          <dt className="inline text-muted font-mono">CVE: </dt>
          <dd className="inline font-mono font-semibold text-critical">{finding.cve_id}</dd>
        </div>
      ) : null}
      {finding.cwe_id ? (
        <div className="rounded bg-sunken px-2 py-0.5">
          <dt className="inline text-muted font-mono">CWE: </dt>
          <dd className="inline font-mono text-ink">{finding.cwe_id}</dd>
        </div>
      ) : null}
      {finding.cvss_score !== null && finding.cvss_score !== undefined ? (
        <div className="rounded bg-sunken px-2 py-0.5">
          <dt className="inline text-muted font-mono">CVSS: </dt>
          <dd className="data-number inline font-mono font-bold text-ink">{finding.cvss_score.toFixed(1)}</dd>
        </div>
      ) : null}
      {finding.nvd_url ? (
        <div>
          <a
            className="inline-flex items-center gap-1 font-medium text-accent hover:underline"
            href={finding.nvd_url}
            target="_blank"
            rel="noreferrer"
          >
            <span>NVD Advisory</span>
            <ExternalLink aria-hidden="true" className="size-3" />
          </a>
        </div>
      ) : null}
    </dl>
  );
}

export function FindingsPanel({ findings, onExplain }: { findings: Finding[]; onExplain?: (finding: Finding) => void }) {
  if (!findings.length) return null;

  return (
    <Section title="Compliance Findings" detail="Cryptographic vulnerabilities and RFC deviations identified in this capture.">
      <div className="space-y-4">
        {findings.map((finding) => {
          const fix = getFixSuggestion(finding.rule_id);
          const severityUpper = (finding.severity || "INFO").toUpperCase();

          return (
            <article
              key={`${finding.rule_id}-${finding.parameter}`}
              className="rounded-xl border border-rule bg-surface p-5 space-y-3 interactive-card"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <RiskBadge level={severityUpper as any} size="sm" />
                    <span className="font-mono text-xs text-muted">{finding.rule_id}</span>
                  </div>
                  <h3 className="text-base font-bold text-ink">{finding.parameter}</h3>
                </div>

                {onExplain ? (
                  <button
                    type="button"
                    onClick={() => onExplain(finding)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-rule bg-sunken/60 px-3 py-1.5 text-xs font-semibold text-accent hover:border-accent transition-colors"
                  >
                    <BookOpen size={13} />
                    <span>Standards Advisory</span>
                  </button>
                ) : null}
              </div>

              <p className="text-sm text-muted leading-relaxed">{finding.description}</p>

              {finding.value && (
                <p className="font-mono text-xs">
                  <span className="text-muted">Observed Value: </span>
                  <span className="font-semibold text-critical">{finding.value}</span>
                </p>
              )}

              {/* Actionable Fix Recommendation */}
              {fix && (
                <div className="rounded-lg border border-accent/30 bg-accent/5 p-3 flex items-start gap-2.5">
                  <Lightbulb size={16} className="text-accent shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-bold text-accent uppercase tracking-wider">Actionable Remediation</p>
                    <p className="text-xs text-ink mt-0.5">{fix}</p>
                  </div>
                </div>
              )}

              {finding.references?.length ? (
                <p className="text-xs text-muted">
                  <span className="font-medium text-ink">Standards Cited: </span>
                  {finding.references.join(" · ")}
                </p>
              ) : null}

              <AdvisoryDetails finding={finding} />
            </article>
          );
        })}
      </div>
    </Section>
  );
}
