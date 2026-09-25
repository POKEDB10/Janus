export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "janus.theme";

/**
 * Retrieves the theme state persisted across re-launches, with fallback
 * to the DOM attribute and OS media preference.
 */
export function getInitialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "dark" || saved === "light") {
      return saved;
    }
  } catch {
    // Local storage might be blocked in sandboxed/private browsing
  }
  const stored = document.documentElement.dataset.theme;
  if (stored === "dark" || stored === "light") {
    return stored;
  }
  if (typeof window !== "undefined" && window.matchMedia) {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return "dark";
}

let themeTransitionTimer: number | null = null;

/**
 * Applies the given theme to the document and updates persistent storage.
 */
export function applyTheme(theme: Theme, addTransitionClass = true): void {
  if (addTransitionClass) {
    document.documentElement.classList.add("theme-transition");
  } else {
    document.documentElement.classList.remove("theme-transition");
  }

  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute(
    "content",
    theme === "dark" ? "#0B0F19" : "#F3F5F7"
  );

  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Theme selection remains active for this session even if storage is unavailable.
  }

  if (addTransitionClass) {
    if (themeTransitionTimer !== null) window.clearTimeout(themeTransitionTimer);
    themeTransitionTimer = window.setTimeout(() => {
      document.documentElement.classList.remove("theme-transition");
      themeTransitionTimer = null;
    }, 280);
  }
}

/**
 * Triggers a radial wave animation where the incoming theme originates at the
 * toggle button coordinates and washes over the screen.
 *
 * Uses native View Transitions API with Web Animations API clipPath when available,
 * and seamlessly falls back to a hardware-accelerated radial ripple.
 */
export async function toggleThemeWithWave(
  nextTheme: Theme,
  origin?: { x: number; y: number },
  onUpdate?: () => void
): Promise<void> {
  const x = origin?.x ?? window.innerWidth - 40;
  const y = origin?.y ?? 28;

  // Calculate maximum distance to the furthest screen corner
  const endRadius = Math.hypot(
    Math.max(x, window.innerWidth - x),
    Math.max(y, window.innerHeight - y)
  );

  const doc = typeof document !== "undefined" ? (document as any) : null;

  // 1. Native View Transitions API (Chrome 111+, Edge 111+, Safari 18+)
  if (doc && typeof doc.startViewTransition === "function") {
    try {
      const transition = doc.startViewTransition(() => {
        applyTheme(nextTheme, false);
        if (onUpdate) onUpdate();
      });

      await transition.ready;

      // Animate the incoming theme expanding as a circular wave from (x, y)
      const animation = document.documentElement.animate(
        {
          clipPath: [
            `circle(0px at ${x}px ${y}px)`,
            `circle(${Math.ceil(endRadius)}px at ${x}px ${y}px)`,
          ],
        },
        {
          duration: 750,
          easing: "cubic-bezier(0.4, 0, 0.2, 1)",
          pseudoElement: "::view-transition-new(root)",
        }
      );

      await animation.finished;
      return;
    } catch {
      // Fall through to fallback on any error
    }
  }

  // 2. Hardware-accelerated radial wave fallback (Firefox and other engines)
  await runFallbackWave(nextTheme, x, y, endRadius, () => {
    applyTheme(nextTheme, false);
    if (onUpdate) onUpdate();
  });
}

function runFallbackWave(
  nextTheme: Theme,
  x: number,
  y: number,
  endRadius: number,
  onPeak?: () => void
): Promise<void> {
  return new Promise((resolve) => {
    const wave = document.createElement("div");
    wave.className = "janus-wave-fallback";
    wave.style.position = "fixed";
    wave.style.left = `${x}px`;
    wave.style.top = `${y}px`;
    wave.style.width = "10px";
    wave.style.height = "10px";
    wave.style.borderRadius = "50%";
    wave.style.pointerEvents = "none";
    wave.style.zIndex = "99999";
    wave.style.transform = "translate(-50%, -50%) scale(1)";
    wave.style.backgroundColor = nextTheme === "dark" ? "#0b0f19" : "#f3f5f7";
    wave.style.boxShadow =
      nextTheme === "dark"
        ? "0 0 60px 25px rgba(59, 130, 246, 0.8), inset 0 0 40px rgba(108, 179, 225, 0.6)"
        : "0 0 60px 25px rgba(245, 158, 11, 0.8), inset 0 0 40px rgba(251, 191, 36, 0.6)";
    wave.style.opacity = "1";
    wave.style.transition =
      "transform 750ms cubic-bezier(0.4, 0, 0.2, 1), opacity 200ms ease 550ms";

    document.body.appendChild(wave);

    const scale = (endRadius * 2) / 10;

    requestAnimationFrame(() => {
      wave.style.transform = `translate(-50%, -50%) scale(${Math.ceil(scale)})`;
      setTimeout(() => {
        if (onPeak) onPeak();
        wave.style.opacity = "0";
      }, 450);
    });

    setTimeout(() => {
      wave.remove();
      resolve();
    }, 800);
  });
}
