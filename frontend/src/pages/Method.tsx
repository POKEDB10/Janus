import { useBackendStatus, useModelStatus } from "../api/queries";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section, Stat } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import type { ModelInfo } from "../types";

function ModelCard({ model }: { model: ModelInfo }) {
  const evaluation = Object.keys(model.evaluation).length ? JSON.stringify(model.evaluation, null, 2) : null;
  return <>
    <Section title="Model card" detail="Metadata returned by the model information endpoint.">
      <div className="grid gap-5 border-y border-rule py-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Model" value={model.model_name} />
        <Stat label="Architecture" value={model.architecture} />
        <Stat label="Input features" value={model.features} detail={model.feature_type} />
        <Stat label="Classes" value={model.classes.length} />
      </div>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <div><h3 className="text-sm font-medium text-ink">Traffic classes</h3><p className="mt-2 text-sm text-muted">{model.classes.length ? model.classes.join(" · ") : "Not returned by the API"}</p></div>
        <div><h3 className="text-sm font-medium text-ink">Explainability</h3><p className="mt-2 text-sm text-muted">{model.explainability || "Not returned by the API"}</p></div>
      </div>
    </Section>
    <Section title="Training and evaluation" detail="The model service supplies the metadata; Janus does not infer unreturned metrics.">
      <div className="grid gap-5 lg:grid-cols-2">
        <dl className="grid gap-3 text-sm">
          <div><dt className="text-xs text-muted">Source</dt><dd className="mt-1 text-ink">{model.training_data.source}</dd></div>
          <div><dt className="text-xs text-muted">Training flows</dt><dd className="data-number mt-1 font-mono text-ink">{model.training_data.total_flows}</dd></div>
          <div><dt className="text-xs text-muted">Scenarios</dt><dd className="data-number mt-1 font-mono text-ink">{model.training_data.scenarios}</dd></div>
          <div><dt className="text-xs text-muted">Notes</dt><dd className="mt-1 text-muted">{model.training_data.note}</dd></div>
        </dl>
        <div><h3 className="text-sm font-medium text-ink">Evaluation metadata</h3>{evaluation ? <pre className="mt-2 max-h-72 overflow-auto border border-rule bg-sunken p-3 font-mono text-xs leading-5 text-ink">{evaluation}</pre> : <InlineNotice>No evaluation metadata was returned.</InlineNotice>}</div>
      </div>
    </Section>
    <Section title="Standards context" detail="Configuration evidence is assessed against the following reference material.">
      <div className="grid gap-px border border-rule bg-rule sm:grid-cols-3">
        <article className="bg-surface p-4"><p className="font-mono text-xs text-muted">RFC 8221</p><p className="mt-2 text-sm text-ink">Cryptographic algorithm requirements for ESP and AH.</p></article>
        <article className="bg-surface p-4"><p className="font-mono text-xs text-muted">RFC 8247</p><p className="mt-2 text-sm text-ink">Cryptographic algorithm requirements for IKEv2.</p></article>
        <article className="bg-surface p-4"><p className="font-mono text-xs text-muted">NIST SP 800-77</p><p className="mt-2 text-sm text-ink">Guide to IPsec VPN security and configuration context.</p></article>
      </div>
    </Section>
    <Section title="Known evidence limits" detail="These are scope boundaries, not negative model claims.">
      <ul className="grid gap-3 text-sm text-muted sm:grid-cols-2">
        <li className="border-l border-rule pl-3">Model metadata describes the model; it does not confirm runtime loading state.</li>
        <li className="border-l border-rule pl-3">A capture without observed IKE negotiation cannot establish the negotiated cipher suite.</li>
        <li className="border-l border-rule pl-3">Flow views show normalized trace samples, not complete packet-size or inter-arrival-time series.</li>
        <li className="border-l border-rule pl-3">Configuration reports identify compliance findings; unavailable dimensions remain unscored.</li>
      </ul>
    </Section>
  </>;
}

export default function Method() {
  const service = useBackendStatus();
  const model = useModelStatus(service.isSuccess);

  if (service.isPending) return <LoadingState label="Checking model information service…" />;
  if (service.isError) return <div className="space-y-8"><PageHeader eyebrow="Method and model card" title="Model metadata unavailable." answer="Janus has not requested model information because the service health check did not succeed." /><ErrorState title="Model card is unavailable" detail={getApiErrorMessage(service.error)} onRetry={() => void service.refetch()} /></div>;
  if (model.isPending) return <LoadingState label="Loading model card…" />;
  if (model.isError) return <div className="space-y-8"><PageHeader eyebrow="Method and model card" title="Model metadata unavailable." answer="The service is reachable, but it did not return model information." /><ErrorState title="Model card is unavailable" detail={getApiErrorMessage(model.error)} onRetry={() => void model.refetch()} /></div>;
  if (!model.data) return <div className="space-y-8"><PageHeader eyebrow="Method and model card" title="No model metadata returned." answer="The service response did not include a model card." /><InlineNotice>Not returned by the API</InlineNotice></div>;

  return <div className="space-y-8"><PageHeader eyebrow="Method and model card" title={model.data.model_name} answer="Model metadata and evaluation evidence are shown exactly as returned by the running service." /><ModelCard model={model.data} /></div>;
}
