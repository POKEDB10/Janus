import { useState } from "react";
import {
  Atom,
  Check,
  Copy,
  KeyRound,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  BookOpen,
} from "lucide-react";
import { Section } from "../../components/ui/Primitives";
import type { ComplianceReport } from "../../types";

export function PqcPanel({ compliance }: { compliance: ComplianceReport }) {
  const [copied, setCopied] = useState(false);
  if (!compliance.pqc_status) return null;

  const status = compliance.pqc_status;
  const isVulnerable = status === "CRQC_VULNERABLE";
  const isHybrid = status === "TRANSITIONAL_HYBRID";
  const isPure = status === "POST_QUANTUM_RESISTANT";

  // Derive evaluated DH group or fallback
  const evaluatedDh = compliance.evaluated_parameters?.dh_group
    ? `DH Group ${compliance.evaluated_parameters.dh_group} (Classical)`
    : "Classical DH / ECDH";

  const hybridConfig = `# /etc/swanctl/conf.d/pqc-hybrid.conf
# RFC 9370 Hybrid Key Exchange (Classical + NIST FIPS 203 ML-KEM-768)
connections {
    pqc-hybrid-tunnel {
        version = 2
        proposals = aes256gcm16-prfsha384-curve25519-mlkem768
        children {
            pqc-esp {
                esp_proposals = aes256gcm16-mlkem768
                dpd_action = restart
                rekey_time = 4h
            }
        }
    }
}`;

  const copyConfig = async () => {
    try {
      await navigator.clipboard.writeText(hybridConfig);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <Section
      title="Post-quantum cryptographic readiness"
      detail="RFC 9370 / NIST FIPS 203 quantum resistance evaluation and Harvest Now, Decrypt Later (HNDL) exposure analysis."
    >
      <div className="space-y-6">
        {/* Main Posture Card */}
        <div
          className={`rounded-2xl border p-6 transition-all duration-300 shadow-sm ${
            isVulnerable
              ? "border-amber-500/30 bg-amber-500/[0.03] dark:bg-amber-500/[0.04]"
              : "border-emerald-500/30 bg-emerald-500/[0.03] dark:bg-emerald-500/[0.04]"
          }`}
        >
          {/* Header Row */}
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between pb-5 border-b border-rule/60">
            <div className="flex items-start sm:items-center gap-3.5">
              <div
                className={`flex size-12 shrink-0 items-center justify-center rounded-xl border ${
                  isVulnerable
                    ? "border-amber-500/40 bg-amber-500/15 text-amber-500"
                    : "border-emerald-500/40 bg-emerald-500/15 text-emerald-500"
                }`}
              >
                <Atom className="size-6 animate-[spin_12s_linear_infinite]" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2.5">
                  <h3 className="text-base sm:text-lg font-bold text-ink">
                    {isVulnerable
                      ? "Cryptographically Relevant Quantum Computer (CRQC) Vulnerability"
                      : isHybrid
                      ? "RFC 9370 Hybrid Key Exchange Active"
                      : "Post-Quantum Pure Lattice KEM Active"}
                  </h3>
                  <span
                    className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-xs font-semibold ${
                      isVulnerable
                        ? "border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                        : "border border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    }`}
                  >
                    {isVulnerable ? (
                      <>
                        <ShieldAlert className="size-3.5" />
                        CRQC_VULNERABLE · HNDL Risk
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="size-3.5" />
                        QUANTUM_RESISTANT
                      </>
                    )}
                  </span>
                </div>
                <p className="mt-1 text-xs sm:text-sm text-muted">
                  {isVulnerable
                    ? "Session key exchange relies exclusively on classical asymmetric mathematics (DH/ECDH/RSA), susceptible to polynomial-time factoring via Shor's algorithm."
                    : "Session key exchange incorporates post-quantum key encapsulation mechanisms immune to Shor's algorithm."}
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={copyConfig}
              className="inline-flex items-center justify-center gap-2 self-start sm:self-auto rounded-lg border border-rule bg-surface px-3 py-1.5 text-xs font-medium text-ink hover:bg-sunken hover:border-accent transition-colors shadow-sm"
              title="Copy swanctl.conf RFC 9370 proposal"
            >
              {copied ? (
                <>
                  <Check className="size-3.5 text-pass" />
                  <span className="text-pass font-semibold">Proposal Copied</span>
                </>
              ) : (
                <>
                  <Copy className="size-3.5 text-muted" />
                  <span>Copy RFC 9370 Proposal</span>
                </>
              )}
            </button>
          </div>

          {/* 4-Card Analytical Metrics Breakdown */}
          <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Dimension 1: Key Exchange */}
            <div className="rounded-xl border border-rule/80 bg-surface/80 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted">Observed Primitive</span>
                <KeyRound className="size-4 text-accent" />
              </div>
              <p className="font-mono text-sm font-bold text-ink">{evaluatedDh}</p>
              <div className="inline-flex items-center gap-1 rounded bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 text-[11px] font-mono text-amber-600 dark:text-amber-400">
                Shor's Algorithm Susceptible
              </div>
              <p className="text-[11px] text-muted leading-tight pt-1">
                Discrete log factorization solvable in polynomial time <span className="font-mono font-medium text-ink">O(log³ N)</span>.
              </p>
            </div>

            {/* Dimension 2: Threat Vector */}
            <div className="rounded-xl border border-rule/80 bg-surface/80 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted">Adversary Threat Vector</span>
                <Radio className="size-4 text-critical" />
              </div>
              <p className="font-mono text-sm font-bold text-ink">HNDL Attack</p>
              <div className="inline-flex items-center gap-1 rounded bg-rose-500/10 border border-rose-500/20 px-2 py-0.5 text-[11px] font-mono text-critical">
                Harvest Now, Decrypt Later
              </div>
              <p className="text-[11px] text-muted leading-tight pt-1">
                Adversaries intercept &amp; store ciphertext today to decrypt once CRQC matures.
              </p>
            </div>

            {/* Dimension 3: Target Standard */}
            <div className="rounded-xl border border-rule/80 bg-surface/80 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted">Target Standard</span>
                <BookOpen className="size-4 text-pass" />
              </div>
              <p className="font-mono text-sm font-bold text-ink">RFC 9370 &amp; FIPS 203</p>
              <div className="inline-flex items-center gap-1 rounded bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 text-[11px] font-mono text-indigo-500">
                ML-KEM-768 (Kyber)
              </div>
              <p className="text-[11px] text-muted leading-tight pt-1">
                Module-Lattice Key Encapsulation combined with classical ECDH.
              </p>
            </div>

            {/* Dimension 4: Migration Suite */}
            <div className="rounded-xl border border-rule/80 bg-surface/80 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted">Recommended Suite</span>
                <Cpu className="size-4 text-cyan-500" />
              </div>
              <p className="font-mono text-sm font-bold text-ink">curve25519-mlkem768</p>
              <div className="inline-flex items-center gap-1 rounded bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-[11px] font-mono text-emerald-600 dark:text-emerald-400">
                Dual Hybrid KEX
              </div>
              <p className="text-[11px] text-muted leading-tight pt-1">
                Protects payload against quantum adversary without breaking legacy clients.
              </p>
            </div>
          </div>

          {/* 3-Step Industry Migration Roadmap */}
          <div className="mt-6 pt-5 border-t border-rule/60">
            <h4 className="text-xs font-mono uppercase tracking-wider font-semibold text-muted mb-3">
              Cryptographic Migration Roadmap (Classical &rarr; Hybrid &rarr; Full PQC)
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Step 1 */}
              <div
                className={`rounded-xl border p-3.5 space-y-1.5 ${
                  isVulnerable
                    ? "border-amber-500/50 bg-amber-500/10 shadow-sm"
                    : "border-rule bg-surface/50 opacity-70"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] font-semibold text-muted">PHASE 1 · CURRENT</span>
                  {isVulnerable && (
                    <span className="rounded bg-amber-500/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-amber-600 dark:text-amber-400">
                      OBSERVED
                    </span>
                  )}
                </div>
                <p className="text-sm font-bold text-ink">Classical Asymmetric (RFC 7296)</p>
                <p className="text-xs text-muted leading-relaxed">
                  Diffie-Hellman Groups 14/19/20 or RSA-3072. Secure against classical supercomputers, but completely factorable on CRQC.
                </p>
              </div>

              {/* Step 2 */}
              <div
                className={`rounded-xl border p-3.5 space-y-1.5 ${
                  isHybrid
                    ? "border-emerald-500/50 bg-emerald-500/10 shadow-sm"
                    : "border-accent/40 bg-accent/5"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] font-semibold text-accent">PHASE 2 · RECOMMENDED</span>
                  <span className="rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-accent">
                    ACTIONABLE NOW
                  </span>
                </div>
                <p className="text-sm font-bold text-ink">RFC 9370 Hybrid Exchange</p>
                <p className="text-xs text-muted leading-relaxed">
                  Dual negotiation: Classical ECDH + NIST ML-KEM-768. Immediate immunity against HNDL harvest while maintaining existing FIPS certification.
                </p>
              </div>

              {/* Step 3 */}
              <div
                className={`rounded-xl border p-3.5 space-y-1.5 ${
                  isPure
                    ? "border-cyan-500/50 bg-cyan-500/10 shadow-sm"
                    : "border-rule bg-surface/50 opacity-80"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] font-semibold text-muted">PHASE 3 · FUTURE</span>
                  <span className="rounded bg-sunken px-1.5 py-0.5 font-mono text-[10px] text-muted">
                    {isPure ? "ACTIVE" : "STANDARDIZING"}
                  </span>
                </div>
                <p className="text-sm font-bold text-ink">Pure Post-Quantum (FIPS 203/204)</p>
                <p className="text-xs text-muted leading-relaxed">
                  Native lattice encapsulation (ML-KEM) and signatures (ML-DSA / SLH-DSA). Classical DH fully deprecated once ecosystem completes rollout.
                </p>
              </div>
            </div>
          </div>

          {/* Copyable Configuration Drawer */}
          <div className="mt-5 rounded-xl border border-rule/80 bg-sunken/60 p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="size-2 rounded-full bg-accent animate-pulse" />
                <span className="font-mono text-xs font-semibold text-ink">
                  Authoritative strongSwan 5.7+ Hybrid Drop-in (swanctl.conf)
                </span>
              </div>
              <button
                type="button"
                onClick={copyConfig}
                className="font-mono text-[11px] text-accent hover:underline flex items-center gap-1"
              >
                {copied ? "Copied!" : "Copy Snippet"}
              </button>
            </div>
            <pre className="overflow-x-auto font-mono text-xs text-muted p-2 rounded bg-surface/80 border border-rule">
              <code>{hybridConfig}</code>
            </pre>
          </div>
        </div>
      </div>
    </Section>
  );
}
