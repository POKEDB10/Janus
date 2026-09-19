import { Section, SeverityBadge } from "../../components/ui/Primitives";
import type { ThreatMatrixItem } from "../../types";

export function ThreatMatrix({ items }: { items: ThreatMatrixItem[] }) {
  if (!items.length) return null;
  return (
    <Section title="MITRE ATT&CK mapping" detail="Technique mappings returned by the configuration audit.">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-sm">
          <caption className="sr-only">MITRE ATT&CK threat matrix</caption>
          <thead className="border-y border-rule font-mono text-xs text-muted">
            <tr><th scope="col" className="px-2 py-2 font-medium">Tactic</th><th scope="col" className="px-2 py-2 font-medium">Technique</th><th scope="col" className="px-2 py-2 font-medium">Affected parameter</th><th scope="col" className="px-2 py-2 font-medium">Status</th><th scope="col" className="px-2 py-2 font-medium">Detail</th></tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.technique_id}-${item.affected_parameter ?? item.technique_name}`} className="border-b border-rule/70 align-top">
                <td className="px-2 py-3 text-muted">{item.tactic}</td>
                <td className="px-2 py-3"><span className="font-mono text-xs text-ink">{item.technique_id}</span><span className="block mt-1 text-muted">{item.technique_name}</span></td>
                <td className="px-2 py-3 font-mono text-xs text-ink">{item.affected_parameter ?? "—"}</td>
                <td className="px-2 py-3"><div className="flex flex-wrap items-center gap-2"><SeverityBadge level={item.severity} /><span className="font-mono text-xs text-muted">{item.status}</span></div></td>
                <td className="px-2 py-3 text-muted">{item.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
