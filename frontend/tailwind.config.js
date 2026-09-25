/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "rgb(var(--color-canvas) / <alpha-value>)",
        surface: "rgb(var(--color-surface) / <alpha-value>)",
        sunken: "rgb(var(--color-sunken) / <alpha-value>)",
        rule: "rgb(var(--color-rule) / <alpha-value>)",
        ink: "rgb(var(--color-ink) / <alpha-value>)",
        muted: "rgb(var(--color-muted) / <alpha-value>)",
        accent: "rgb(var(--color-accent) / <alpha-value>)",
        "accent-strong": "rgb(var(--color-accent-strong) / <alpha-value>)",
        pass: "rgb(var(--color-pass) / <alpha-value>)",
        critical: "rgb(var(--color-critical) / <alpha-value>)",
        high: "rgb(var(--color-high) / <alpha-value>)",
        medium: "rgb(var(--color-medium) / <alpha-value>)",
        low: "rgb(var(--color-low) / <alpha-value>)",
        info: "rgb(var(--color-info) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "ui-sans-serif", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      borderRadius: { instrument: "4px", detail: "2px" },
      maxWidth: { content: "1200px" },
      boxShadow: { menu: "0 8px 24px rgb(16 20 26 / 12%)" },
      zIndex: { header: "80", drawer: "70", dialog: "60" },
    },
  },
  plugins: [],
};
