import { Menu } from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import { useBackendStatus } from "../../api/queries";
import { isRecordedSample } from "../../lib/capture-session";
import { cn } from "../../lib/cn";
import { ThemeToggle } from "../ui/ThemeToggle";

const navItems = [
  { to: "/", label: "Dashboard" },
  { to: "/upload", label: "Analyze" },
  { to: "/compare", label: "Compare" },
  { to: "/method", label: "Method" },
];

function StatusCluster() {
  const { search } = useLocation();
  const backend = useBackendStatus();
  const recorded = isRecordedSample(search);

  if (recorded) {
    return (
      <div className="hidden items-center gap-2 font-mono text-xs text-muted lg:flex" role="status" aria-label="Playback state: Recorded sample">
        <span className="size-2 rounded-full bg-muted/60" aria-hidden="true" />
        <span>Recorded session</span>
      </div>
    );
  }

  if (backend.isPending) {
    return (
      <div className="hidden items-center gap-2 font-mono text-xs text-muted lg:flex" role="status" aria-label="Engine status: Connecting">
        <span className="size-2 rounded-full bg-amber-500 animate-pulse" aria-hidden="true" />
        <span>Connecting…</span>
      </div>
    );
  }

  if (backend.isError) {
    return (
      <div className="hidden items-center gap-2 font-mono text-xs text-critical lg:flex" role="status" aria-label="Engine status: Offline">
        <span className="size-2 rounded-full bg-critical" aria-hidden="true" />
        <span>Offline</span>
      </div>
    );
  }

  return (
    <div className="hidden items-center gap-2 font-mono text-xs text-muted lg:flex" role="status" aria-label="Engine status: Connected">
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-pass opacity-75" />
        <span className="relative inline-flex size-2 rounded-full bg-pass" />
      </span>
      <span className="text-ink font-medium">Connected</span>
    </div>
  );
}

const linkClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    "relative border-b-2 px-1 py-4 text-sm font-medium transition-all duration-200 cursor-pointer",
    isActive
      ? "border-accent text-ink font-semibold"
      : "border-transparent text-muted hover:border-rule hover:text-ink"
  );

export function Header() {
  return (
    <header className="sticky top-0 z-header border-b border-rule bg-surface/90 backdrop-blur-md transition-colors">
      <nav className="mx-auto flex min-h-14 max-w-content items-center justify-between gap-5 px-4 sm:px-6" aria-label="Primary navigation">
        <NavLink to="/" className="flex shrink-0 items-center gap-2.5 text-ink" aria-label="Janus home">
          <img src="/janus.svg" className="size-5" alt="" />
          <span className="text-base font-semibold">Janus</span>
          <span className="hidden border-l border-rule pl-2.5 text-xs text-muted sm:inline">IPsec capture analysis</span>
        </NavLink>
        <div className="flex items-center gap-2 md:gap-5">
          <div className="hidden items-center gap-5 md:flex">
            <div className="flex items-center gap-4">{navItems.map((item) => <NavLink key={item.to} to={item.to} className={linkClass}>{item.label}</NavLink>)}</div>
            <StatusCluster />
          </div>
          <ThemeToggle />
          <details className="relative md:hidden">
            <summary className="list-none p-2 text-muted marker:hidden"><Menu aria-hidden="true" className="size-5" /><span className="sr-only">Open navigation</span></summary>
            <div className="absolute right-0 top-full mt-2 min-w-40 border border-rule bg-surface p-2 shadow-menu">
              {navItems.map((item) => <NavLink key={item.to} to={item.to} className={({ isActive }) => cn("block px-3 py-2 text-sm", isActive ? "bg-sunken text-ink" : "text-muted hover:bg-sunken hover:text-ink")}>{item.label}</NavLink>)}
            </div>
          </details>
        </div>
      </nav>
    </header>
  );
}
