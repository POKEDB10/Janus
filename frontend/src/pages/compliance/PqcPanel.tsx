import { Section } from "../../components/ui/Primitives";
import type { ComplianceReport } from "../../types";

export function PqcPanel({ compliance }: { compliance: ComplianceReport }) {
  if (!compliance.pqc_status) return null;
  return (
    <Section title="Post-quantum readiness" detail="RFC 9370 hybrid key exchange status returned by the audit.">
      <p className="font-mono text-sm font-medium text-ink">{compliance.pqc_status}</p>
      {compliance.pqc_advisory ? <p className="mt-2 max-w-3xl text-sm text-muted">{compliance.pqc_advisory}</p> : null}
    </Section>
  );
}
