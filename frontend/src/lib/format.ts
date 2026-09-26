export function formatBytes(value?: number): string {
  if (value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 ** 2)).toFixed(1)} MB`;
}

export function formatPercent(value?: number | null, digits = 0): string {
  return value === undefined || value === null ? "—" : `${(value * 100).toFixed(digits)}%`;
}

export function formatScoreDecimal(value?: unknown, digits = 4): string {
  if (value === undefined || value === null) return "—";
  const num = typeof value === "number" ? value : parseFloat(String(value));
  if (Number.isNaN(num)) return String(value);
  return num.toFixed(digits);
}

export function formatAccuracyPercent(value?: unknown, digits = 2): string {
  if (value === undefined || value === null) return "—";
  const num = typeof value === "number" ? value : parseFloat(String(value));
  if (Number.isNaN(num)) return String(value);
  // If value is a ratio <= 1.0 (e.g. 1.0 or 0.995), convert to percentage
  const pct = num <= 1.0 ? num * 100 : num;
  return `${pct.toFixed(digits)}%`;
}

export function formatCvStd(value?: unknown, digits = 4): string {
  if (value === undefined || value === null) return "—";
  const num = typeof value === "number" ? value : parseFloat(String(value));
  if (Number.isNaN(num)) return String(value);
  return `±${num.toFixed(digits)}`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

