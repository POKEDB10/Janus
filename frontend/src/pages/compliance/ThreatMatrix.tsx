import { useState, useMemo } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  LayoutGrid,
  List,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Section } from "../../components/ui/Primitives";
import type { Finding, ThreatMatrixItem } from "../../types";

export function ThreatMatrix({
  items,
  onExplain,
}: {
  items: ThreatMatrixItem[];
  onExplain?: (finding: Finding) => void;
}) {
  const [filter, setFilter] = useState<"ALL" | "AT_RISK" | "WARNING" | "SECURE">("ALL");
  const [viewMode, setViewMode] = useState<"CARDS" | "TABLE">("TABLE");

  const safeItems = items ?? [];

  const handleExplain = (item: ThreatMatrixItem) => {
    if (!onExplain) return;
    const statusUpper = (item.status || "").toUpperCase();
    const isSecure = statusUpper === "SECURE" || statusUpper === "MITIGATED";
    onExplain({
      rule_id: item.technique_id,
      parameter: item.affected_parameter || "ipsec_suite",
      severity: isSecure ? "INFO" : item.severity || "HIGH",
      description: `${item.technique_name} (${item.technique_id}): ${item.details}. Current posture status: ${item.status || "UNKNOWN"}.`,
      remediation: isSecure
        ? `Current configuration for ${item.affected_parameter ?? "suite"} successfully mitigates adversary technique ${item.technique_name}.`
        : `Remediate ${item.affected_parameter ?? "parameters"} according to RFC 8221 and RFC 8247 requirements to defeat ${item.technique_name}.`,
    });
  };

  const secureCount = useMemo(
    () => safeItems.filter((i) => {
      const s = (i.status || "").toUpperCase();
      return s === "SECURE" || s === "MITIGATED";
    }).length,
    [safeItems]
  );
  const vulnerableCount = useMemo(
    () => safeItems.filter((i) => {
      const s = (i.status || "").toUpperCase();
      return s === "VULNERABLE" || s === "EXPOSED";
    }).length,
    [safeItems]
  );
  const warningCount = useMemo(
    () => safeItems.filter((i) => {
      const s = (i.status || "").toUpperCase();
      return s === "WARNING" || s === "SUBOPTIMAL";
    }).length,
    [safeItems]
  );

  const filteredItems = useMemo(() => {
    if (filter === "ALL") return safeItems;
    if (filter === "AT_RISK") {
      return safeItems.filter((i) => {
        const s = (i.status || "").toUpperCase();
        return s === "VULNERABLE" || s === "EXPOSED";
      });
    }
    if (filter === "WARNING") {
      return safeItems.filter((i) => {
        const s = (i.status || "").toUpperCase();
        return s === "WARNING" || s === "SUBOPTIMAL";
      });
    }
    if (filter === "SECURE") {
      return safeItems.filter((i) => {
        const s = (i.status || "").toUpperCase();
        return s === "SECURE" || s === "MITIGATED";
      });
    }
    return safeItems;
  }, [safeItems, filter]);

  if (!safeItems.length) return null;

  const renderStatusBadge = (item: ThreatMatrixItem) => {
    const statusUpper = (item.status || "").toUpperCase();
    if (statusUpper === "SECURE" || statusUpper === "MITIGATED") {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
          <CheckCircle2 className="size-3.5 shrink-0" />
          <span>Defense Active</span>
        </span>
      );
    }
    if (statusUpper === "VULNERABLE" || statusUpper === "EXPOSED") {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-xs font-semibold text-rose-600 dark:text-rose-400">
          <ShieldAlert className="size-3.5 shrink-0" />
          <span>Exposed ({item.severity})</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-xs font-semibold text-amber-600 dark:text-amber-400">
        <AlertTriangle className="size-3.5 shrink-0" />
        <span>Suboptimal ({item.severity})</span>
      </span>
    );
  };

  const getMitreLink = (techniqueId: string) => {
    const cleanId = techniqueId.trim().toUpperCase();
    return cleanId.startsWith("T")
      ? `https://attack.mitre.org/techniques/${cleanId}/`
      : `https://attack.mitre.org/techniques/T${cleanId}/`;
  };

  return (
    <Section
      title="MITRE ATT&CK enterprise threat mapping"
      detail="Adversary techniques and defense mitigations mapped to evaluated IPsec cryptographic parameters."
    >
      <div className="space-y-4">
        {/* Posture Bar & Filter Controls */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-xl border border-rule bg-surface shadow-sm">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => setFilter("ALL")}
              className={`rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors ${
                filter === "ALL"
                  ? "bg-accent text-white font-semibold"
                  : "bg-sunken text-muted hover:text-ink"
              }`}
            >
              All ({items.length})
            </button>
            {vulnerableCount > 0 && (
              <button
                type="button"
                onClick={() => setFilter("AT_RISK")}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors ${
                  filter === "AT_RISK"
                    ? "bg-rose-500 text-white font-semibold"
                    : "bg-rose-500/10 text-rose-500 hover:bg-rose-500/20"
                }`}
              >
                <ShieldAlert className="size-3.5" />
                At Risk ({vulnerableCount})
              </button>
            )}
            {warningCount > 0 && (
              <button
                type="button"
                onClick={() => setFilter("WARNING")}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors ${
                  filter === "WARNING"
                    ? "bg-amber-500 text-white font-semibold"
                    : "bg-amber-500/10 text-amber-500 hover:bg-amber-500/20"
                }`}
              >
                <AlertTriangle className="size-3.5" />
                Suboptimal ({warningCount})
              </button>
            )}
            <button
              type="button"
              onClick={() => setFilter("SECURE")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors ${
                filter === "SECURE"
                  ? "bg-emerald-600 text-white font-semibold"
                  : "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20"
              }`}
            >
              <ShieldCheck className="size-3.5" />
              Active Defenses ({secureCount})
            </button>
          </div>

          {/* View Mode Toggle */}
          <div className="flex items-center gap-1 self-end sm:self-auto border border-rule rounded-lg p-0.5 bg-sunken">
            <button
              type="button"
              onClick={() => setViewMode("CARDS")}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                viewMode === "CARDS"
                  ? "bg-surface text-ink shadow-sm"
                  : "text-muted hover:text-ink"
              }`}
              title="Cards View"
            >
              <LayoutGrid className="size-3.5" />
              <span>Cards</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode("TABLE")}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                viewMode === "TABLE"
                  ? "bg-surface text-ink shadow-sm"
                  : "text-muted hover:text-ink"
              }`}
              title="Table View"
            >
              <List className="size-3.5" />
              <span>Table</span>
            </button>
          </div>
        </div>

        {/* View Mode: Cards (Default) */}
        {viewMode === "CARDS" ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredItems.map((item) => {
              const statusUpper = item.status.toUpperCase();
              const isSecure = statusUpper === "SECURE" || statusUpper === "MITIGATED";
              const isVulnerable = statusUpper === "VULNERABLE" || statusUpper === "EXPOSED";

              return (
                <article
                  key={`${item.technique_id}-${item.affected_parameter ?? item.technique_name}`}
                  className={`rounded-2xl border p-5 transition-all shadow-sm flex flex-col justify-between space-y-4 ${
                    isSecure
                      ? "border-emerald-500/20 bg-surface hover:border-emerald-500/40"
                      : isVulnerable
                      ? "border-rose-500/30 bg-rose-500/[0.03] hover:border-rose-500/50"
                      : "border-amber-500/30 bg-amber-500/[0.03] hover:border-amber-500/50"
                  }`}
                >
                  <div className="space-y-3">
                    {/* Header: MITRE ID + Tactic + Status */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <a
                          href={getMitreLink(item.technique_id)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 rounded bg-sunken px-2 py-0.5 font-mono text-xs font-bold text-accent hover:underline hover:bg-sunken/80 transition-colors"
                          title="Open MITRE ATT&CK technique details"
                        >
                          <span>{item.technique_id}</span>
                          <ExternalLink className="size-3" />
                        </a>
                        <span className="font-mono text-[11px] text-muted tracking-tight">
                          {item.tactic}
                        </span>
                      </div>
                      {renderStatusBadge(item)}
                    </div>

                    {/* Technique Name */}
                    <h3 className="text-base font-bold text-ink leading-snug">
                      {item.technique_name}
                    </h3>

                    {/* Affected Parameter Pill */}
                    {item.affected_parameter && (
                      <div className="inline-flex items-center gap-1.5 rounded-md bg-sunken/70 border border-rule px-2.5 py-1 font-mono text-xs text-ink/90">
                        <span className="text-muted">Target Parameter:</span>
                        <span className="font-semibold text-accent">{item.affected_parameter}</span>
                      </div>
                    )}

                    {/* Details Analysis */}
                    <p className="text-xs sm:text-sm text-muted leading-relaxed">
                      {item.details}
                    </p>
                  </div>

                  {/* Footer Posture Hint & RAG Explain */}
                  <div className="pt-3 border-t border-rule/50 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-muted">
                    <span className="flex items-center gap-1">
                      <Shield className="size-3" />
                      MITRE ATT&amp;CK Enterprise v14
                    </span>
                    <div className="flex items-center gap-2">
                      <span>{isSecure ? "Hardened Policy" : "Remediation Required"}</span>
                      {onExplain && (
                        <button
                          type="button"
                          onClick={() => handleExplain(item)}
                          className="inline-flex items-center gap-1 text-accent hover:underline font-semibold cursor-pointer"
                        >
                          <span>Explain Why {isSecure ? "Good" : "Bad"}</span>
                          <ExternalLink className="size-2.5" />
                        </button>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          /* View Mode: Modern Responsive Table */
          <div className="overflow-x-auto rounded-xl border border-rule bg-surface shadow-sm">
            <table className="w-full min-w-[760px] border-collapse text-left text-sm">
              <caption className="sr-only">MITRE ATT&CK threat matrix</caption>
              <thead className="border-b border-rule font-mono text-xs text-muted bg-sunken/40">
                <tr>
                  <th scope="col" className="px-4 py-3 font-semibold">Tactic</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Technique</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Affected Parameter</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Defense Status</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Evaluation Detail</th>
                  <th scope="col" className="px-4 py-3 font-semibold text-right">RAG Explainer</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule/60">
                {filteredItems.map((item) => {
                  const isSecure = item.status.toUpperCase() === "SECURE" || item.status.toUpperCase() === "MITIGATED";
                  return (
                    <tr
                      key={`${item.technique_id}-${item.affected_parameter ?? item.technique_name}`}
                      className="align-top hover:bg-sunken/30 transition-colors"
                    >
                      <td className="px-4 py-3 text-xs text-muted font-medium">{item.tactic}</td>
                      <td className="px-4 py-3">
                        <a
                          href={getMitreLink(item.technique_id)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-xs font-bold text-accent hover:underline"
                        >
                          <span>{item.technique_id}</span>
                          <ExternalLink className="size-3" />
                        </a>
                        <span className="block mt-1 font-semibold text-ink text-xs sm:text-sm">
                          {item.technique_name}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-ink font-semibold">
                        {item.affected_parameter ? (
                          <span className="rounded bg-sunken px-2 py-0.5 border border-rule">
                            {item.affected_parameter}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {renderStatusBadge(item)}
                      </td>
                      <td className="px-4 py-3 text-xs sm:text-sm text-muted leading-relaxed max-w-md">
                        {item.details}
                      </td>
                      <td className="px-4 py-3 text-right whitespace-nowrap">
                        {onExplain ? (
                          <button
                            type="button"
                            onClick={() => handleExplain(item)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-rule bg-sunken px-2.5 py-1 font-mono text-[11px] font-semibold text-accent hover:border-accent hover:text-accent-strong transition-colors cursor-pointer"
                            title={`Explain why this configuration is ${isSecure ? 'good' : 'bad'} with RAG`}
                          >
                            <span>Why {isSecure ? "Good" : "Bad"}?</span>
                            <ExternalLink className="size-3" />
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Section>
  );
}
