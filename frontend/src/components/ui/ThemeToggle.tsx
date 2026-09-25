import { Moon, Sun } from "lucide-react";
import { useEffect, useState, type MouseEvent } from "react";
import { flushSync } from "react-dom";
import { cn } from "../../lib/cn";
import {
  getInitialTheme,
  THEME_STORAGE_KEY,
  toggleThemeWithWave,
  type Theme,
} from "../../lib/theme";

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const [isAnimating, setIsAnimating] = useState(false);
  const dark = theme === "dark";

  // Multi-tab persistence & sync
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (
        event.key === THEME_STORAGE_KEY &&
        (event.newValue === "dark" || event.newValue === "light")
      ) {
        setTheme(event.newValue);
        document.documentElement.dataset.theme = event.newValue;
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  async function handleToggle(event: MouseEvent<HTMLButtonElement>) {
    if (isAnimating) return;
    const nextTheme: Theme = dark ? "light" : "dark";

    const rect = event.currentTarget.getBoundingClientRect();
    const x = event.clientX || rect.left + rect.width / 2;
    const y = event.clientY || rect.top + rect.height / 2;

    setIsAnimating(true);

    try {
      await toggleThemeWithWave(nextTheme, { x, y }, () => {
        flushSync(() => {
          setTheme(nextTheme);
        });
      });
    } catch {
      setTheme(nextTheme);
    } finally {
      setIsAnimating(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleToggle}
      aria-label={`Switch to ${dark ? "light" : "dark"} mode`}
      aria-pressed={dark}
      title={dark ? "Switch to light mode" : "Switch to dark mode"}
      className={cn(
        "theme-toggle relative inline-flex size-9 shrink-0 items-center justify-center rounded-lg border border-rule bg-surface text-muted transition-all duration-200",
        "hover:border-accent hover:text-ink hover:shadow-sm active:scale-95 focus-visible:outline-none cursor-pointer",
        isAnimating && "pointer-events-none"
      )}
    >
      <Sun
        aria-hidden="true"
        className={cn(
          "absolute size-4 transition-all duration-300 ease-out",
          dark
            ? "rotate-90 scale-0 opacity-0 pointer-events-none"
            : "rotate-0 scale-100 opacity-100 text-amber-500"
        )}
      />
      <Moon
        aria-hidden="true"
        className={cn(
          "absolute size-4 transition-all duration-300 ease-out",
          dark
            ? "rotate-0 scale-100 opacity-100 text-accent"
            : "-rotate-90 scale-0 opacity-0 pointer-events-none"
        )}
      />
    </button>
  );
}
