import { lazy, Suspense, useEffect, type ReactNode } from "react";
import { Route, Routes, useLocation, useParams } from "react-router-dom";
import { CaptureHeader } from "./components/shell/CaptureHeader";
import { Header } from "./components/shell/Header";
import ScrollToTop from "./components/ScrollToTop";
import { LoadingState } from "./components/ui/Primitives";
import { isPresentationMode } from "./lib/capture-session";

import Dashboard from "./pages/Dashboard";
const Upload = lazy(() => import("./pages/Upload"));
const Analysis = lazy(() => import("./pages/Analysis"));
const Compliance = lazy(() => import("./pages/Compliance"));
const Report = lazy(() => import("./pages/Report"));
const Compare = lazy(() => import("./pages/Compare"));
const Method = lazy(() => import("./pages/Method"));
const NotFound = lazy(() => import("./pages/NotFound"));

function Footer() {
  return <footer data-secondary-chrome="true" className="border-t border-rule"><p className="mx-auto max-w-content px-4 py-4 text-xs text-muted sm:px-6">SIH26160 · Cipher Ops</p></footer>;
}

function AppFrame({ children, captureId }: { children: ReactNode; captureId?: string }) {
  const { pathname, search } = useLocation();
  useEffect(() => { document.documentElement.dataset.present = String(isPresentationMode(search)); }, [search]);
  return (
    <div className="flex min-h-dvh flex-col">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header />
      {captureId ? <CaptureHeader captureId={captureId} /> : null}
      <main id="main-content" className="mx-auto w-full max-w-content flex-1 px-4 py-6 sm:px-6 sm:py-8">
        <div key={pathname} className="page-enter">
          <Suspense fallback={<LoadingState label="Loading page…" />}>{children}</Suspense>
        </div>
      </main>
      <Footer />
    </div>
  );
}

function CaptureRoute({ children }: { children: ReactNode }) {
  const { captureId } = useParams<{ captureId: string }>();
  return captureId ? <AppFrame captureId={captureId}>{children}</AppFrame> : null;
}

export default function App() {
  return (
    <>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<AppFrame><Dashboard /></AppFrame>} />
        <Route path="/upload" element={<AppFrame><Upload /></AppFrame>} />
        <Route path="/compare" element={<AppFrame><Compare /></AppFrame>} />
        <Route path="/method" element={<AppFrame><Method /></AppFrame>} />
        <Route path="/analysis/:captureId" element={<CaptureRoute><Analysis /></CaptureRoute>} />
        <Route path="/compliance/:captureId" element={<CaptureRoute><Compliance /></CaptureRoute>} />
        <Route path="/report/:captureId" element={<CaptureRoute><Report /></CaptureRoute>} />
        <Route path="*" element={<AppFrame><NotFound /></AppFrame>} />
      </Routes>
    </>
  );
}
