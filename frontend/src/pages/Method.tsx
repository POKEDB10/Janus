import { PageHeader, Section } from "../components/ui/Primitives";

export default function Method() {
  return (
    <div className="space-y-8">
      <PageHeader title="Method" answer="Janus presents configuration evidence and traffic evidence separately. The complete method reference arrives in Phase 5." />
      <Section title="Method reference" detail="Standards coverage, the model card, and known limits will be populated from the running API.">
        <p className="text-sm text-muted">No method claims are shown until their supporting data is available.</p>
      </Section>
    </div>
  );
}
