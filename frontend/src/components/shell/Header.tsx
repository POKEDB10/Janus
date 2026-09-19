import { Menu } from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import { useBackendStatus, useModelStatus } from "../../api/queries";
import { isRecordedSample } from "../../lib/capture-session";

const navItems = [
  { to: "/upload", label: "Analyze" },
  { to: "/compare", label: "Compare" },
  { to: "/method", label: "Method" },
];

function StatusCluster() {
  const { search } = useLocation();
  const backend = useBackendStatus();
  const model = useModelStatus(backend.isSuccess);
  const recorded = isRecordedSample(search);
  const backendLabel = backend.isPending ? "Backend checking" : backend.isSuccess ? "Backend reachable" : "Backend unavailable";
  const modelLabel = backend.isSuccess ? model.isPending ? "Model checking" : model.isSuccess ? "Model metadata loaded" : "Model unavailable" : "Model unknown";
  const dotColor = backend.isSuccess ? "bg-pass" : backend.isError ? "bg-critical" : "bg-muted";
  return (
    <div className="hidden items-center gap-3 font-mono text-xs font-medium text-muted lg:flex" role="status" aria-live="polite" aria-label="System status">
      <span className="inline-flex items-center gap-1.5"><span aria-hidden="true" className={`size-1.5 rounded-full ${dotColor}`} />{backendLabel}</span>
      <span className="h-3 border-l border-rule" />
      <span>{modelLabel}</span>
      <span className="h-3 border-l border-rule" />
      <span>{recorded ? "Recorded" : "Live"}</span>
    </div>
  );
}

const linkClass = ({ isActive }: { isActive: boolean }) => `border-b-2 px-1 py-4 text-sm font-medium transition-colors duration-150 ${isActive ? "border-accent text-ink" : "border-transparent text-muted hover:border-rule hover:text-ink"}`;

export function Header() {
  return (
    <header className="sticky top-0 z-header border-b border-rule bg-surface">
      <nav className="mx-auto flex min-h-14 max-w-content items-center justify-between gap-5 px-4 sm:px-6" aria-label="Primary navigation">
        <NavLink to="/" className="flex shrink-0 items-center gap-2.5 text-ink" aria-label="Janus home">
          <img src="/janus.svg" className="size-5" alt="" />
          <span className="text-base font-semibold">Janus</span>
          <span className="hidden border-l border-rule pl-2.5 text-xs text-muted sm:inline">IPsec capture analysis</span>
        </NavLink>
        <div className="hidden items-center gap-5 md:flex">
          <div className="flex items-center gap-4">{navItems.map((item) => <NavLink key={item.to} to={item.to} className={linkClass}>{item.label}</NavLink>)}</div>
          <StatusCluster />
        </div>
        <details className="relative md:hidden">
          <summary className="list-none p-2 text-muted marker:hidden"><Menu aria-hidden="true" className="size-5" /><span className="sr-only">Open navigation</span></summary>
          <div className="absolute right-0 top-full mt-2 min-w-40 border border-rule bg-surface p-2 shadow-menu">
            {navItems.map((item) => <NavLink key={item.to} to={item.to} className={({ isActive }) => `block px-3 py-2 text-sm ${isActive ? "bg-sunken text-ink" : "text-muted hover:bg-sunken hover:text-ink"}`}>{item.label}</NavLink>)}
          </div>
        </details>
      </nav>
    </header>
  );
}
