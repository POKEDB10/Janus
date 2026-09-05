/**
 * components/ScrollToTop.tsx
 *
 * Automatically and instantly resets the window scroll position to (0, 0)
 * whenever the route pathname changes. Prevents the common SPA glitch where
 * navigating to a new page preserves previous scroll offset and drops the
 * user into the middle of the page.
 */
import { useEffect } from "react";
import { useLocation } from "react-router-dom";

export default function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  }, [pathname]);

  return null;
}
