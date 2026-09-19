export type Theme = "light" | "dark";

const storageKey = "janus.theme";

export function getInitialTheme(): Theme {
  const stored = document.documentElement.dataset.theme;
  return stored === "dark" ? "dark" : "light";
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0F1319" : "#F3F5F7");
  try {
    window.localStorage.setItem(storageKey, theme);
  } catch {
    // Theme selection remains active for this page even if storage is unavailable.
  }
}
