/**
 * App.tsx — Root application shell with Navbar, routing, and branded footer.
 */
import React from "react";
import { Routes, Route, NavLink, useNavigate } from "react-router-dom";
import {
  Shield,
  Upload,
  BarChart2,
  CheckSquare,
  FileText,
  GitCompare,
  Menu,
  X,
} from "lucide-react";
import { clsx } from "clsx";
import Dashboard from "./pages/Dashboard";
import UploadPage from "./pages/Upload";
import Analysis from "./pages/Analysis";
import Compliance from "./pages/Compliance";
import Report from "./pages/Report";
import Compare from "./pages/Compare";
import NotFound from "./pages/NotFound";
import ScrollToTop from "./components/ScrollToTop";

// ─── Nav items ───────────────────────────────────────────────────────────────

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const staticNavItems: NavItem[] = [
  { to: "/", label: "Dashboard", icon: <BarChart2 size={16} /> },
  { to: "/upload", label: "Analyze PCAP", icon: <Upload size={16} /> },
  { to: "/compare", label: "Compare", icon: <GitCompare size={16} /> },
];

// ─── Navbar ───────────────────────────────────────────────────────────────────

function Navbar() {
  const [menuOpen, setMenuOpen] = React.useState(false);
  const navigate = useNavigate();

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    clsx(
      "flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-medium transition-colors duration-150",
      isActive
        ? "bg-janus-blue text-white"
        : "text-gray-300 hover:bg-white/10 hover:text-white"
    );

  return (
    <header className="sticky top-0 z-50 bg-janus-navy border-b border-white/10 shadow-md">
      <nav
        className="max-w-screen-xl mx-auto flex items-center justify-between h-14 px-4"
        aria-label="Primary navigation"
      >
        {/* Brand */}
        <button
          onClick={() => navigate("/")}
          className="flex items-center gap-2 text-white font-bold text-lg tracking-tight cursor-pointer"
          aria-label="Janus home"
        >
          <Shield className="text-janus-blue" size={22} aria-hidden="true" />
          <span>Janus</span>
          <span className="hidden sm:inline text-xs text-gray-400 font-normal ml-1 mt-0.5">
            IPsec Analyzer
          </span>
        </button>

        {/* Desktop links */}
        <ul className="hidden md:flex items-center gap-1" role="list">
          {staticNavItems.map((item) => (
            <li key={item.to}>
              <NavLink to={item.to} end className={linkClass}>
                {item.icon}
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>

        {/* Mobile hamburger */}
        <button
          className="md:hidden p-2 rounded text-gray-300 hover:text-white cursor-pointer transition-colors"
          aria-label={menuOpen ? "Close menu" : "Open menu"}
          aria-expanded={menuOpen}
          aria-controls="mobile-menu"
          onClick={() => setMenuOpen((o) => !o)}
        >
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </nav>

      {/* Mobile drawer */}
      {menuOpen && (
        <div
          id="mobile-menu"
          className="md:hidden bg-janus-navy border-t border-white/10 px-4 pb-3"
        >
          <ul className="flex flex-col gap-1 pt-2" role="list">
            {staticNavItems.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end
                  className={linkClass}
                  onClick={() => setMenuOpen(false)}
                >
                  {item.icon}
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      )}
    </header>
  );
}

// ─── Contextual sub-nav (shown on capture detail pages) ──────────────────────

interface CaptureNavProps {
  captureId: string;
}

function CaptureNav({ captureId }: CaptureNavProps) {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    clsx(
      "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border transition-colors duration-150",
      isActive
        ? "border-janus-blue bg-janus-blue/20 text-white"
        : "border-white/10 text-gray-400 hover:border-janus-blue/50 hover:text-white"
    );

  const captureLinks: Array<{ to: string; label: string; icon: React.ReactNode }> = [
    { to: `/analysis/${captureId}`, label: "Analysis", icon: <BarChart2 size={13} /> },
    { to: `/compliance/${captureId}`, label: "Compliance", icon: <CheckSquare size={13} /> },
    { to: `/report/${captureId}`, label: "Report", icon: <FileText size={13} /> },
  ];

  return (
    <div className="bg-janus-navy/80 border-b border-white/10 px-4 py-2">
      <div className="max-w-screen-xl mx-auto flex items-center gap-2 flex-wrap">
        <span className="text-xs text-gray-500 mr-2 font-mono">
          Capture: <span className="text-gray-300">{captureId}</span>
        </span>
        {captureLinks.map((link) => (
          <NavLink key={link.to} to={link.to} end className={linkClass}>
            {link.icon}
            {link.label}
          </NavLink>
        ))}
      </div>
    </div>
  );
}

// ─── Branded Footer ──────────────────────────────────────────────────────────

function Footer() {
  return (
    <footer className="border-t border-white/10 py-4 px-4">
      <div className="max-w-screen-xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-gray-500">
        <div className="flex items-center gap-2">
          <Shield size={13} className="text-janus-blue" />
          <span className="text-gray-400 font-semibold">Janus</span>
          <span>IPsec VPN Analyzer &copy; {new Date().getFullYear()}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="px-2 py-0.5 rounded bg-blue-500/15 border border-blue-500/30 text-blue-400 font-mono font-semibold text-[10px]">
            SIH 2026 · SIH26160
          </span>
          <span className="text-gray-600">·</span>
          <span className="text-gray-400 font-medium">Team: Cipher Ops</span>
        </div>
      </div>
    </footer>
  );
}

// ─── Layout wrapper ──────────────────────────────────────────────────────────

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main id="main-content" className="flex-1 max-w-screen-xl mx-auto w-full px-4 py-6">
        {children}
      </main>
      <Footer />
    </div>
  );
}

// ─── Capture-scoped layout (includes contextual sub-nav) ─────────────────────

function CaptureLayout({
  captureId,
  children,
}: {
  captureId: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <CaptureNav captureId={captureId} />
      <main id="main-content" className="flex-1 max-w-screen-xl mx-auto w-full px-4 py-6">
        {children}
      </main>
      <Footer />
    </div>
  );
}

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  return (
    <>
      <ScrollToTop />
      <Routes>
      <Route
        path="/"
        element={
          <Layout>
            <Dashboard />
          </Layout>
        }
      />
      <Route
        path="/upload"
        element={
          <Layout>
            <UploadPage />
          </Layout>
        }
      />
      <Route
        path="/compare"
        element={
          <Layout>
            <Compare />
          </Layout>
        }
      />
      <Route
        path="/analysis/:captureId"
        element={
          <CaptureLayoutRoute>
            <Analysis />
          </CaptureLayoutRoute>
        }
      />
      <Route
        path="/compliance/:captureId"
        element={
          <CaptureLayoutRoute>
            <Compliance />
          </CaptureLayoutRoute>
        }
      />
      <Route
        path="/report/:captureId"
        element={
          <CaptureLayoutRoute>
            <Report />
          </CaptureLayoutRoute>
        }
      />
      {/* Catch-all 404 — prevents blank white page on any mistyped URL */}
      <Route
        path="*"
        element={
          <Layout>
            <NotFound />
          </Layout>
        }
      />
    </Routes>
  </>
);
}

/**
 * Thin wrapper that reads :captureId from the URL params and passes it
 * to CaptureLayout without reaching into each page component.
 */
function CaptureLayoutRoute({ children }: { children: React.ReactNode }) {
  const { captureId } = useParams();
  if (!captureId) return null;
  return <CaptureLayout captureId={captureId}>{children}</CaptureLayout>;
}

// Must import useParams after the JSX functions that reference it at call-time
import { useParams } from "react-router-dom";
