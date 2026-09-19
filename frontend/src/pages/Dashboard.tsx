import { Link } from "react-router-dom";
import { EmptyState, PageHeader } from "../components/ui/Primitives";

export default function Dashboard() {
  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="IPsec protocol analysis"
        title="Start an analysis."
        answer="Upload an IPsec capture to inspect its negotiated configuration and ESP traffic."
        actions={<Link to="/upload" className="inline-flex min-h-10 items-center bg-accent px-4 text-sm font-medium text-white transition-colors hover:bg-accent-strong focus-visible:outline-none">Upload capture</Link>}
      />
      <EmptyState
        title="No analysis selected"
        detail="Grades and findings appear only after Janus has processed a capture."
        action={<Link to="/upload" className="text-sm font-medium text-accent underline underline-offset-4">Choose a capture</Link>}
      />
    </div>
  );
}
