import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { runAdHocEvaluation } from "../../api/client";
import { ErrorState, GradeMark, InlineNotice, Section } from "../../components/ui/Primitives";
import RiskBadge from "../../components/RiskBadge";
import { getApiErrorMessage } from "../../lib/api-error";
import type { Finding, RiskLevel } from "../../types";
import { SimulationModal } from "./SimulationModal";

const aeadCiphers = new Set(["ENCR_AES_GCM_16", "ENCR_AES_GCM_12", "ENCR_AES_GCM_8", "ENCR_CHACHA20_POLY1305", "ENCR_AES_CCM_8", "ENCR_AES_CCM_12", "ENCR_AES_CCM_16"]);

function validateCipherAuth(cipher: string, auth: string): string | null {
  if (auth === "AUTH_NONE" && !aeadCiphers.has(cipher)) {
    return "AUTH_NONE is valid only with an AEAD cipher. Choose an HMAC authentication algorithm or an AEAD cipher.";
  }
  if (aeadCiphers.has(cipher) && auth !== "AUTH_NONE") {
    return "AEAD ciphers include authentication. Select AUTH_NONE to avoid an incompatible separate authentication setting.";
  }
  return null;
}

export function ParameterSandbox({ onExplain }: { onExplain?: (finding: Finding) => void }) {
  const [cipher, setCipher] = useState("ENCR_AES_GCM_16");
  const [auth, setAuth] = useState("AUTH_NONE");
  const [dhGroup, setDhGroup] = useState(19);
  const [pfsEnabled, setPfsEnabled] = useState(true);
  const [lifetime, setLifetime] = useState(3600);
  const [showSimulation, setShowSimulation] = useState(false);
  const validation = validateCipherAuth(cipher, auth);
  const evaluation = useMutation({ mutationFn: runAdHocEvaluation });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (validation) return;
    evaluation.mutate({ esp_encryption: cipher, esp_auth: auth, dh_group: dhGroup, pfs_enabled: pfsEnabled, sa_lifetime_seconds: lifetime, rsa_key_bits: 3072, ike_version: "IKEv2" });
    setShowSimulation(true);
  }

  return (
    <div id="parameter-sandbox" className="scroll-mt-16">
      <Section title="Parameter sandbox" detail="Evaluate a hypothetical IPsec suite without changing this capture.">
        <form onSubmit={submit} className="grid gap-4 lg:grid-cols-5">
        <label className="grid gap-1 text-sm font-medium text-ink">ESP cipher
          <select value={cipher} onChange={(event) => setCipher(event.target.value)} className="min-h-10 border border-rule bg-surface px-2 font-mono text-xs text-ink focus:border-accent focus:outline-none">
            <option value="ENCR_AES_GCM_16" className="bg-surface text-ink">ENCR_AES_GCM_16</option>
            <option value="ENCR_CHACHA20_POLY1305" className="bg-surface text-ink">ENCR_CHACHA20_POLY1305</option>
            <option value="ENCR_AES_CBC" className="bg-surface text-ink">ENCR_AES_CBC</option>
            <option value="ENCR_3DES" className="bg-surface text-ink">ENCR_3DES</option>
            <option value="ENCR_BLOWFISH" className="bg-surface text-ink">ENCR_BLOWFISH</option>
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium text-ink">ESP authentication
          <select value={auth} onChange={(event) => setAuth(event.target.value)} aria-invalid={Boolean(validation)} className="min-h-10 border border-rule bg-surface px-2 font-mono text-xs text-ink focus:border-accent focus:outline-none">
            <option value="AUTH_NONE" className="bg-surface text-ink">AUTH_NONE</option>
            <option value="AUTH_HMAC_SHA2_256_128" className="bg-surface text-ink">AUTH_HMAC_SHA2_256_128</option>
            <option value="AUTH_HMAC_SHA1_96" className="bg-surface text-ink">AUTH_HMAC_SHA1_96</option>
            <option value="AUTH_HMAC_MD5_96" className="bg-surface text-ink">AUTH_HMAC_MD5_96</option>
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium text-ink">DH group
          <select value={dhGroup} onChange={(event) => setDhGroup(Number(event.target.value))} className="min-h-10 border border-rule bg-surface px-2 font-mono text-xs text-ink focus:border-accent focus:outline-none">
            <option value={19} className="bg-surface text-ink">19 (ECP-256)</option>
            <option value={20} className="bg-surface text-ink">20 (ECP-384)</option>
            <option value={14} className="bg-surface text-ink">14 (MODP-2048)</option>
            <option value={2} className="bg-surface text-ink">2 (MODP-1024)</option>
            <option value={1} className="bg-surface text-ink">1 (MODP-768)</option>
          </select>
        </label>
        <div className="grid gap-1 text-sm font-medium text-ink">
          <span>PFS and lifetime</span>
          <div className="flex min-h-10 items-center gap-2 border border-rule bg-surface px-2.5">
            <label className="inline-flex items-center gap-1.5 font-mono text-xs text-ink cursor-pointer shrink-0">
              <input checked={pfsEnabled} onChange={(event) => setPfsEnabled(event.target.checked)} type="checkbox" className="rounded border-rule text-accent focus:ring-accent" />
              PFS
            </label>
            <span className="text-rule/80">|</span>
            <select
              value={lifetime}
              onChange={(event) => setLifetime(Number(event.target.value))}
              aria-label="Simulated SA lifetime"
              className="min-w-0 flex-1 bg-surface font-mono text-xs text-ink focus:outline-none"
            >
              <option value={3600} className="bg-surface text-ink">1h (3,600s)</option>
              <option value={14400} className="bg-surface text-ink">4h (14,400s)</option>
              <option value={28800} className="bg-surface text-ink">8h (28,800s)</option>
              <option value={86400} className="bg-surface text-ink">24h (86,400s)</option>
            </select>
          </div>
        </div>
        <div className="flex items-end">
          <button
            type="submit"
            disabled={Boolean(validation) || evaluation.isPending}
            className="inline-flex min-h-10 w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 text-xs font-semibold text-white hover:bg-accent-strong disabled:cursor-not-allowed disabled:bg-rule focus-visible:outline-none transition-all shadow-sm"
          >
            <Play className="size-3.5 fill-current" />
            <span>{evaluation.isPending ? "Simulating…" : `Simulate ${Math.max(1, Math.round(lifetime / 3600))}h VPN Traffic`}</span>
          </button>
        </div>
      </form>
      {validation ? <p className="mt-4 text-sm text-critical" role="alert">{validation}</p> : null}
      {evaluation.isError ? <div className="mt-4"><ErrorState title="Suite evaluation failed" detail={getApiErrorMessage(evaluation.error)} onRetry={() => evaluation.mutate({ esp_encryption: cipher, esp_auth: auth, dh_group: dhGroup, pfs_enabled: pfsEnabled, sa_lifetime_seconds: lifetime, rsa_key_bits: 3072, ike_version: "IKEv2" })} /></div> : null}
      {evaluation.data ? (
        <div className="mt-5 rounded-xl border border-rule bg-surface p-5 space-y-4 shadow-sm" aria-live="polite">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-rule pb-3">
            <GradeMark score={evaluation.data.overall_score} grade={evaluation.data.grade} label="Sandbox Suite Verdict" />
            <div className="flex items-center gap-2">
              <RiskBadge
                level={
                  (evaluation.data.grade === "A" || evaluation.data.grade === "B"
                    ? "LOW"
                    : evaluation.data.grade === "C"
                    ? "MEDIUM"
                    : evaluation.data.grade === "D"
                    ? "HIGH"
                    : "CRITICAL") as RiskLevel
                }
                size="sm"
              />
              <span className="font-mono text-xs text-muted">
                {evaluation.data.findings.length} finding(s)
              </span>
            </div>
          </div>
          {evaluation.data.summary ? (
            <p className="text-xs sm:text-sm text-muted leading-relaxed">
              {evaluation.data.summary}
            </p>
          ) : null}
          {(evaluation.data.findings ?? []).length > 0 && (
            <div className="space-y-2 pt-1">
              <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-muted">
                Identified Cryptographic Weaknesses:
              </h4>
              <div className="grid gap-2">
                {(evaluation.data.findings ?? []).map((f, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-2.5 rounded-lg border border-rule/60 bg-sunken/40 p-2.5 text-xs"
                  >
                    <RiskBadge level={(f.severity?.toUpperCase() || "INFO") as RiskLevel} size="sm" />
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <div className="font-mono font-semibold text-ink">{f.rule_id}</div>
                      <div className="text-muted leading-relaxed">{f.description}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : null}
      {!validation && !evaluation.data && !evaluation.isError ? (
        <div className="mt-4">
          <InlineNotice>
            {`Results and ${Math.max(1, Math.round(lifetime / 3600))}-hour traffic simulation will launch in a focused pop-up window.`}
          </InlineNotice>
        </div>
      ) : null}

      {/* 1-Hour Accelerated Traffic & Exploit Simulation Modal */}
      <SimulationModal
        open={showSimulation}
        onClose={() => setShowSimulation(false)}
        cipher={cipher}
        auth={auth}
        dhGroup={dhGroup}
        pfsEnabled={pfsEnabled}
        lifetime={lifetime}
        isPending={evaluation.isPending}
        isError={evaluation.isError}
        error={evaluation.error}
        onRetry={() => evaluation.mutate({
          esp_encryption: cipher,
          esp_auth: auth,
          dh_group: dhGroup,
          pfs_enabled: pfsEnabled,
          sa_lifetime_seconds: lifetime,
          rsa_key_bits: 3072,
          ike_version: "IKEv2",
        })}
        overallScore={evaluation.data?.overall_score ?? undefined}
        grade={evaluation.data?.grade}
        summary={evaluation.data?.summary}
        backendFindings={evaluation.data?.findings}
        onExplain={onExplain}
      />
    </Section>
    </div>
  );
}
