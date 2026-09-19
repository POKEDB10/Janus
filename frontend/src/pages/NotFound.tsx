import { Link } from "react-router-dom";
import { PageHeader } from "../components/ui/Primitives";

export default function NotFound() {
  return (
    <div className="space-y-8">
      <PageHeader eyebrow="404" title="Page not found." answer="The requested address does not match a Janus workspace page." />
      <Link to="/" className="text-sm font-medium text-accent underline underline-offset-4">Return to start</Link>
    </div>
  );
}
