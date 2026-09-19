import { Moon, Sun } from "lucide-react";
import { useState } from "react";
import { cn } from "../../lib/cn";
import { applyTheme, getInitialTheme, type Theme } from "../../lib/theme";

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const dark = theme === "dark";

  function toggleTheme() {
    const nextTheme: Theme = dark ? "light" : "dark";
    applyTheme(nextTheme);
    setTheme(nextTheme);
  }

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${dark ? "light" : "dark"} mode`}
      aria-pressed={dark}
      className="theme-toggle relative inline-flex size-9 shrink-0 items-center justify-center border border-rule bg-surface text-muted hover:border-accent hover:text-ink focus-visible:outline-none"
    >
      <Sun aria-hidden="true" className={cn("absolute size-4 transition-[transform,opacity] duration-150 ease-out", dark ? "rotate-45 scale-75 opacity-0" : "rotate-0 scale-100 opacity-100")} />
      <Moon aria-hidden="true" className={cn("absolute size-4 transition-[transform,opacity] duration-150 ease-out", dark ? "rotate-0 scale-100 opacity-100" : "-rotate-45 scale-75 opacity-0")} />
    </button>
  );
}
