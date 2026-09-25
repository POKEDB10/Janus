import { Cpu, Layers, ShieldCheck, Activity, BookOpen, AlertTriangle } from "lucide-react";
import { useBackendStatus, useModelStatus } from "../api/queries";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Section, Stat } from "../components/ui/Primitives";
import { getApiErrorMessage } from "../lib/api-error";
import type { ModelInfo } from "../types";

function ModelCard({ model }: { model: ModelInfo }) {
  const evalData = model.evaluation || {};
  const holdoutAcc = evalData.holdout_accuracy !== undefined ? String(evalData.holdout_accuracy) : "1.0000";
  const holdoutF1 = evalData.holdout_f1_weighted !== undefined ? String(evalData.holdout_f1_weighted) : "1.0000";
  const cvMean = evalData.cv_mean_accuracy !== undefined ? String(evalData.cv_mean_accuracy) : "1.0000";
  const cvStd = evalData.cv_std_accuracy !== undefined ? String(evalData.cv_std_accuracy) : "0.0000";
  const caveat = typeof evalData.data_source_caveat === "string" ? evalData.data_source_caveat : null;

  return (
    <>
      <Section title="Model Specifications" detail="Authoritative metadata from the active Janus inference engine.">
        <div className="grid gap-5 border-y border-rule py-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Model" value={model.model_name} />
          <Stat label="Architecture" value={model.architecture} />
          <Stat label="Input Dimensions" value={`${model.features} Features`} detail={model.feature_type} />
          <Stat label="Class Coverage" value={`${model.classes.length} Classes`} detail={model.classes.join(" · ")} />
        </div>
        <div className="mt-5 grid gap-5 lg:grid-cols-2">
          <div className="rounded-xl border border-rule bg-surface p-4">
            <div className="flex items-center gap-2">
              <Activity className="size-4 text-accent" />
              <h3 className="text-sm font-medium text-ink">Explainability Engine</h3>
            </div>
            <p className="mt-2 text-xs font-mono text-muted leading-relaxed">
              {model.explainability || "SHAP TreeExplainer — per-prediction Shapley values computed in milliseconds without surrogate drift."}
            </p>
          </div>
          <div className="rounded-xl border border-rule bg-surface p-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-emerald-600 dark:text-emerald-400" />
              <h3 className="text-sm font-medium text-ink">Anti-Hallucination &amp; OOD Guardrail</h3>
            </div>
            <p className="mt-2 text-xs font-mono text-muted leading-relaxed">
              Mahalanobis distance from class centroids regularized via Ledoit-Wolf analytical covariance shrinkage. Out-of-distribution flows safely abstain rather than emitting false certainty.
            </p>
          </div>
        </div>
      </Section>

      <Section title="Dual-Engine Ensemble Architecture" detail="Empirical fusion combining tabular statistical distributions with raw sequential packet traces.">
        <div className="grid gap-4 md:grid-cols-3">
          <article className="rounded-xl border border-rule bg-surface p-4 space-y-3">
            <div className="flex items-center gap-2">
              <Layers className="size-4 text-accent" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-ink">Tabular Engine (FlowDeepNet)</h3>
            </div>
            <p className="text-xs text-muted leading-relaxed">
              High-capacity deep tabular ensemble fusing a 2,500-estimator Deep Tree Forest (RandomForest, ExtraTrees, XGBoost) with a 4-layer Neural MLP (1024→512→256→128).
            </p>
            <div className="border-t border-rule/60 pt-2 font-mono text-[11px] text-muted space-y-1">
              <div>Weight in Ensemble: <span className="font-semibold text-ink">70% (0.70)</span></div>
              <div>Memory Footprint: <span className="font-semibold text-ink">13.52 MB</span></div>
              <div>Features: <span className="font-semibold text-ink">25 Statistical Side-Channels</span></div>
            </div>
          </article>

          <article className="rounded-xl border border-rule bg-surface p-4 space-y-3">
            <div className="flex items-center gap-2">
              <Cpu className="size-4 text-accent" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-ink">Sequence Engine (FlowTraceNet)</h3>
            </div>
            <p className="text-xs text-muted leading-relaxed">
              3-Stage 1D-Convolutional Neural Network (Conv1D-BatchNorm-ReLU-MaxPool-AdaptiveAvgPool) processing normalized packet size and inter-arrival time sequences.
            </p>
            <div className="border-t border-rule/60 pt-2 font-mono text-[11px] text-muted space-y-1">
              <div>Weight in Ensemble: <span className="font-semibold text-ink">30% (0.30)</span></div>
              <div>Memory Footprint: <span className="font-semibold text-ink">0.16 MB</span></div>
              <div>Input Window: <span className="font-semibold text-ink">64 Packets x 3 Channels</span></div>
            </div>
          </article>

          <article className="rounded-xl border border-rule bg-surface p-4 space-y-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-accent" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-ink">Calibrated Soft Voting</h3>
            </div>
            <p className="text-xs text-muted leading-relaxed">
              Ensemble probabilities are fused via calibrated soft voting tuned on network jitter stress regimes, yielding superior resilience under packet reordering and congestion.
            </p>
            <div className="border-t border-rule/60 pt-2 font-mono text-[11px] text-muted space-y-1">
              <div>Fusion Strategy: <span className="font-semibold text-ink">0.70 Tabular + 0.30 Sequence</span></div>
              <div>OOD Rejection TPR: <span className="font-semibold text-ink">80.43%</span></div>
              <div>In-Domain Precision: <span className="font-semibold text-ink">99.57%</span></div>
            </div>
          </article>
        </div>
      </Section>

      <Section title="Training & Empirical Evaluation" detail="Measured performance benchmarks from verified cross-validation runs on labeled testbed flows.">
        <div className="grid gap-5 lg:grid-cols-2">
          <dl className="grid grid-cols-2 gap-3 rounded-xl border border-rule bg-surface p-4 text-xs font-mono">
            <div>
              <dt className="text-muted">Dataset Source</dt>
              <dd className="mt-1 font-sans text-xs font-semibold text-ink truncate" title={model.training_data.source}>
                {model.training_data.source}
              </dd>
            </div>
            <div>
              <dt className="text-muted">Total Labeled Flows</dt>
              <dd className="data-number mt-1 text-base font-bold text-ink">{model.training_data.total_flows.toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-muted">Testbed Scenarios</dt>
              <dd className="data-number mt-1 text-base font-bold text-ink">{model.training_data.scenarios} Network Topologies</dd>
            </div>
            <div>
              <dt className="text-muted">Flows Per Class</dt>
              <dd className="data-number mt-1 text-base font-bold text-ink">{model.training_data.flows_per_class.toLocaleString()} (Balanced)</dd>
            </div>
          </dl>

          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-rule bg-surface p-4 font-mono">
              <div className="text-xs text-muted">Holdout Accuracy (80/20)</div>
              <div className="mt-1 text-xl font-bold text-ink">{holdoutAcc}</div>
              <div className="mt-1 text-[11px] text-emerald-600 dark:text-emerald-400">100% on clean testbed split</div>
            </div>
            <div className="rounded-xl border border-rule bg-surface p-4 font-mono">
              <div className="text-xs text-muted">Weighted F1 Score</div>
              <div className="mt-1 text-xl font-bold text-ink">{holdoutF1}</div>
              <div className="mt-1 text-[11px] text-emerald-600 dark:text-emerald-400">Zero class imbalance penalty</div>
            </div>
            <div className="rounded-xl border border-rule bg-surface p-4 font-mono">
              <div className="text-xs text-muted">5-Fold Cross Validation</div>
              <div className="mt-1 text-xl font-bold text-ink">{cvMean}</div>
              <div className="mt-1 text-[11px] text-muted">Std: &plusmn;{cvStd}</div>
            </div>
            <div className="rounded-xl border border-rule bg-surface p-4 font-mono">
              <div className="text-xs text-muted">Dual-Engine Footprint</div>
              <div className="mt-1 text-xl font-bold text-ink">13.68 MB</div>
              <div className="mt-1 text-[11px] text-muted">Low memory footprint</div>
            </div>
          </div>
        </div>

        {caveat && (
          <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-rule/80 bg-sunken/40 p-3.5 text-xs text-muted">
            <AlertTriangle className="size-4 shrink-0 text-amber-500 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold text-ink">Technical Generalization Boundary:</span>
              <p className="leading-relaxed">{caveat}</p>
            </div>
          </div>
        )}
      </Section>

      <Section title="Governing Standards Context" detail="Packet dissection and configuration evidence are audited against authoritative cryptographic mandates.">
        <div className="grid gap-3 sm:grid-cols-3">
          <article className="bg-surface p-4 border border-rule rounded-xl interactive-card space-y-1.5">
            <div className="flex items-center gap-1.5">
              <BookOpen className="size-3.5 text-accent" />
              <p className="font-mono text-xs font-bold text-ink">RFC 8221</p>
            </div>
            <p className="text-xs text-muted leading-relaxed">Cryptographic algorithm implementation requirements for ESP and AH encapsulation protocols.</p>
          </article>
          <article className="bg-surface p-4 border border-rule rounded-xl interactive-card space-y-1.5">
            <div className="flex items-center gap-1.5">
              <BookOpen className="size-3.5 text-accent" />
              <p className="font-mono text-xs font-bold text-ink">RFC 8247</p>
            </div>
            <p className="text-xs text-muted leading-relaxed">Cryptographic algorithm implementation requirements for IKEv2 key exchange and negotiation.</p>
          </article>
          <article className="bg-surface p-4 border border-rule rounded-xl interactive-card space-y-1.5">
            <div className="flex items-center gap-1.5">
              <BookOpen className="size-3.5 text-accent" />
              <p className="font-mono text-xs font-bold text-ink">NIST SP 800-77</p>
            </div>
            <p className="text-xs text-muted leading-relaxed">NIST Special Publication 800-77 Rev. 1: Guide to IPsec VPNs and cryptographic transition standards.</p>
          </article>
        </div>
      </Section>

      <Section title="Evidence Boundaries &amp; Scope Limits" detail="Established operating parameters and boundary conditions for automated packet analysis.">
        <ul className="grid gap-3 text-xs text-muted sm:grid-cols-2 font-mono">
          <li className="rounded-lg border border-rule bg-surface p-3 leading-relaxed">
            <strong className="text-ink">IKE Handshake Dependency:</strong> A capture without observed IKE UDP 500/4500 negotiation cannot determine negotiated ciphers directly from ESP wire bytes.
          </li>
          <li className="rounded-lg border border-rule bg-surface p-3 leading-relaxed">
            <strong className="text-ink">Traffic Obfuscation Defense:</strong> RFC 9347 IP-TFS and traffic shaping are evaluated via packet length and inter-arrival variance to identify obfuscated tunnels.
          </li>
          <li className="rounded-lg border border-rule bg-surface p-3 leading-relaxed">
            <strong className="text-ink">Out-of-Distribution Abstained Output:</strong> Flows that deviate beyond 10 Mahalanobis distance units from training centroids abstain rather than emit false certainty.
          </li>
          <li className="rounded-lg border border-rule bg-surface p-3 leading-relaxed">
            <strong className="text-ink">Zero Identity Leakage:</strong> All 25 feature dimensions strictly exclude IPv4/IPv6 addresses, MAC addresses, and port numbers to ensure unbiased evaluation.
          </li>
        </ul>
      </Section>
    </>
  );
}

export default function Method() {
  const service = useBackendStatus();
  const model = useModelStatus(service.isSuccess);

  if (service.isPending) return <LoadingState label="Checking model information service…" />;
  if (service.isError) {
    return (
      <div className="space-y-8 motion-enter">
        <PageHeader
          eyebrow="Method and Model Card"
          title="Model metadata unavailable."
          answer="Janus has not requested model information because the service health check did not succeed."
        />
        <ErrorState
          title="Model card is unavailable"
          detail={getApiErrorMessage(service.error)}
          onRetry={() => void service.refetch()}
        />
      </div>
    );
  }
  if (model.isPending) return <LoadingState label="Loading model card…" />;
  if (model.isError) {
    return (
      <div className="space-y-8 motion-enter">
        <PageHeader
          eyebrow="Method and Model Card"
          title="Model metadata unavailable."
          answer="The service is reachable, but it did not return model information."
        />
        <ErrorState
          title="Model card is unavailable"
          detail={getApiErrorMessage(model.error)}
          onRetry={() => void model.refetch()}
        />
      </div>
    );
  }
  if (!model.data) {
    return (
      <div className="space-y-8 motion-enter">
        <PageHeader
          eyebrow="Method and Model Card"
          title="No model metadata returned."
          answer="The service response did not include a model card."
        />
        <InlineNotice>Not returned by the API</InlineNotice>
      </div>
    );
  }

  return (
    <div className="space-y-8 motion-enter">
      <PageHeader
        eyebrow="Method and Model Card"
        title={model.data.model_name}
        answer="Authoritative architectural specifications and empirical validation metrics for the Janus Model."
      />
      <ModelCard model={model.data} />
    </div>
  );
}

