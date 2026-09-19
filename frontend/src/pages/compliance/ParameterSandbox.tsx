import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { runAdHocEvaluation } from "../../api/client";
import { ErrorState, GradeMark, InlineNotice, Section } from "../../components/ui/Primitives";
import { getApiErrorMessage } from "../../lib/api-error";

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

export function ParameterSandbox() {
  const [cipher, setCipher] = useState("ENCR_AES_GCM_16");
  const [auth, setAuth] = useState("AUTH_NONE");
  const [dhGroup, setDhGroup] = useState(19);
  const [pfsEnabled, setPfsEnabled] = useState(true);
  const [lifetime, setLifetime] = useState(3600);
  const validation = validateCipherAuth(cipher, auth);
  const evaluation = useMutation({ mutationFn: runAdHocEvaluation });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (validation) return;
    evaluation.mutate({ esp_encryption: cipher, esp_auth: auth, dh_group: dhGroup, pfs_enabled: pfsEnabled, sa_lifetime_seconds: lifetime, rsa_key_bits: 3072, ike_version: "IKEv2" });
  }

  return (
    <Section title="Parameter sandbox" detail="Evaluate a hypothetical IPsec suite without changing this capture.">
      <form onSubmit={submit} className="grid gap-4 lg:grid-cols-5">
        <label className="grid gap-1 text-sm font-medium text-ink">ESP cipher
          <select value={cipher} onChange={(event) => setCipher(event.target.value)} className="min-h-10 border border-rule bg-surface px-2 font-mono text-xs text-ink focus:border-accent focus:outline-none">
            <option value="ENCR_AES_GCM_16">ENCR_AES_GCM_16</option>
            <option value="ENCR_CHACHA20_POLY1305">ENCR_CHACHA20_POLY1305</option>
            <option value="ENCR_AES_CBC">ENCR_AES_CBC</option>
            <option value="ENCR_3DES">ENCR_3DES</option>
            <option value="ENCR_BLOWFISH">ENCR_BLOWFISH</option>
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium text-ink">ESP authentication
          <select value={auth} onChange={(event) => setAuth(event.target.value)} aria-invalid={Boolean(validation)} className="min-h-10 border border-rule bg-surface px-2 font-mono text-xs text-ink focus:border-accent focus:outline-none">
            <option value="AUTH_NONE">AUTH_NONE</option>
            <option value="AUTH_HMAC_SHA2_256_128">AUTH_HMAC_SHA2_256_128</option>
            <option value="AUTH_HMAC_SHA1_96">AUTH_HMAC_SHA1_96</option>
            <option value="AUTH_HMAC_MD5_96">AUTH_HMAC_MD5_96</option>
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium text-ink">DH group
          <select value={dhGroup} onChange={(event) => setDhGroup(Number(event.target.value))} className="min-h-10 border border-rule bg-surface px-2 font-mono text-xs text-ink focus:border-accent focus:outline-none">
            <option value={19}>19</option><option value={20}>20</option><option value={14}>14</option><option value={2}>2</option><option value={1}>1</option>
          </select>
        </label>
        <div className="grid gap-1 text-sm font-medium text-ink"><span>PFS and lifetime</span><div className="flex min-h-10 items-center gap-3 border border-rule px-2"><label className="inline-flex items-center gap-1.5 font-mono text-xs"><input checked={pfsEnabled} onChange={(event) => setPfsEnabled(event.target.checked)} type="checkbox" />PFS</label><select value={lifetime} onChange={(event) => setLifetime(Number(event.target.value))} className="min-w-0 flex-1 bg-transparent font-mono text-xs text-ink focus:outline-none"><option value={3600}>1h</option><option value={14400}>4h</option><option value={28800}>8h</option><option value={86400}>24h</option></select></div></div>
        <div className="flex items-end"><button type="submit" disabled={Boolean(validation) || evaluation.isPending} className="min-h-10 w-full bg-accent px-4 text-sm font-medium text-white hover:bg-accent-strong disabled:cursor-not-allowed disabled:bg-rule focus-visible:outline-none">{evaluation.isPending ? "Evaluating…" : "Evaluate suite"}</button></div>
      </form>
      {validation ? <p className="mt-4 text-sm text-critical" role="alert">{validation}</p> : null}
      {evaluation.isError ? <div className="mt-4"><ErrorState title="Suite evaluation failed" detail={getApiErrorMessage(evaluation.error)} onRetry={() => evaluation.mutate({ esp_encryption: cipher, esp_auth: auth, dh_group: dhGroup, pfs_enabled: pfsEnabled, sa_lifetime_seconds: lifetime, rsa_key_bits: 3072, ike_version: "IKEv2" })} /></div> : null}
      {evaluation.data ? <div className="mt-5 border-t border-rule pt-4" aria-live="polite"><div className="flex flex-wrap items-end justify-between gap-4"><GradeMark score={evaluation.data.overall_score} grade={evaluation.data.grade} label="Suite evaluation" />{evaluation.data.summary ? <p className="max-w-2xl text-sm text-muted">{evaluation.data.summary}</p> : null}</div></div> : null}
      {!validation && !evaluation.data && !evaluation.isError ? <div className="mt-4"><InlineNotice>Results are returned by the compliance API after evaluation.</InlineNotice></div> : null}
    </Section>
  );
}
