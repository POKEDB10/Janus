import { useState } from "react";
import { ChevronDown, ChevronUp, HelpCircle, ShieldCheck } from "lucide-react";
import { CodeBlock } from "../../components/ui/CodeBlock";
import { Section } from "../../components/ui/Primitives";
import type { ComplianceReport } from "../../types";
import { buildAlgorithmComparisons, markedRemediationLines } from "./audit-data";

export function RemediationConfigPanel({ compliance }: { compliance: ComplianceReport }) {
  const [showExplanation, setShowExplanation] = useState(false);
  const comparisons = buildAlgorithmComparisons(compliance);
  const config = compliance.remediation_config?.trim();

  if (!config) return null;

  return (
    <Section
      title="Recommended strongSwan remediation policy"
      detail="Authoritative swanctl.conf configuration generated to enforce RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 compliance."
    >
      <div className="space-y-4">
        {/* Full-width Container */}
        <div className="rounded-xl border border-rule bg-surface p-5 space-y-4 shadow-sm">
          {/* Header Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-rule/60 pb-3">
            <div className="space-y-0.5">
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-ink">
                Hardened strongSwan 5.7+ Policy
              </span>
              <p className="font-mono text-[11px] text-muted">
                /etc/swanctl/conf.d/janus-remediated.conf
              </p>
            </div>

            {/* Explain Why This Config Is Better Button */}
            <button
              type="button"
              onClick={() => setShowExplanation(!showExplanation)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/20 transition-colors"
            >
              <HelpCircle className="size-3.5" />
              <span>{showExplanation ? "Hide Configuration Rationale" : "Explain Why This Config Is Better"}</span>
              {showExplanation ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
            </button>
          </div>

          {/* Expandable Technical Explanation Drawer */}
          {showExplanation && (
            <div className="rounded-lg border border-accent/30 bg-accent/5 p-4 space-y-3 motion-enter">
              <div className="flex items-center gap-2 text-xs font-bold font-mono uppercase tracking-wider text-accent">
                <ShieldCheck className="size-4" />
                <span>Authoritative Technical Rationale for Proposed Configuration</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs leading-relaxed text-ink/90">
                <div className="rounded bg-surface/80 p-3 border border-rule/80 space-y-1">
                  <p className="font-bold text-ink">1. Modern AEAD Cipher (AES-256-GCM-16)</p>
                  <p className="text-muted">
                    Replaces legacy CBC mode to permanently eliminate padding oracle vulnerabilities (e.g. POODLE, Lucky13, Sweet32). Galois Counter Mode authenticates payload integrity in a single pass with a 128-bit ICV, removing separate HMAC computational overhead.
                  </p>
                </div>

                <div className="rounded bg-surface/80 p-3 border border-rule/80 space-y-1">
                  <p className="font-bold text-ink">2. Diffie-Hellman Group 19 (256-bit ECP)</p>
                  <p className="text-muted">
                    Standardizes on NIST P-256 elliptic curve key exchange per RFC 8247 §2.4. Resists discrete-log precomputation attacks (Logjam) that compromise legacy MODP groups (Group 1, Group 2).
                  </p>
                </div>

                <div className="rounded bg-surface/80 p-3 border border-rule/80 space-y-1">
                  <p className="font-bold text-ink">3. Enforced Perfect Forward Secrecy (PFS)</p>
                  <p className="text-muted">
                    Mandates independent ephemeral DH key derivation for every Child SA rekey. Prevents retroactive decryption of archived traffic if gateway long-term private keys are compromised.
                  </p>
                </div>

                <div className="rounded bg-surface/80 p-3 border border-rule/80 space-y-1">
                  <p className="font-bold text-ink">4. 4-Hour SA Rotation Window</p>
                  <p className="text-muted">
                    Complies with NIST SP 800-77 Rev. 1 recommendation (1h–8h window). Mitigates replay sequence number wrap-around and restricts adversary cryptanalytic exposure while avoiding DPD rekeying storms.
                  </p>
                </div>
              </div>

              <p className="text-[11px] font-mono text-muted pt-1">
                Standard Citations: RFC 8221 (ESP Cryptographic Suites), RFC 8247 (IKEv2 Cryptographic Algorithms), NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs).
              </p>
            </div>
          )}

          {/* Full-width Syntax-Highlighted Code Block */}
          <CodeBlock
            code={config}
            fileName="swanctl.conf"
            markedLines={markedRemediationLines(config, comparisons)}
          />
        </div>
      </div>
    </Section>
  );
}
