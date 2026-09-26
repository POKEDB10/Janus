/**
 * components/ScoreGauge.tsx
 * High-precision SVG circular progress gauge displaying 0-100 security score and letter grade.
 * Features smooth spring-eased mount sweep and numerical count-up animation.
 */
import React from "react";
import { cn } from "../lib/cn";

interface ScoreGaugeProps {
  score: number;
  grade?: string;
  label?: string;
  /** Diameter of the gauge in pixels (default 170) */
  size?: number;
  className?: string;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#10b981"; // emerald
  if (score >= 60) return "#3b82f6"; // blue
  if (score >= 40) return "#f59e0b"; // yellow / amber
  return "#ef4444";                  // red
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  grade,
  label = "Security Score",
  size = 170,
  className,
}) => {
  const clamped = Math.min(100, Math.max(0, score));
  const color = scoreColor(clamped);

  // SVG coordinate system: 160x160 viewBox
  const center = 80;
  const radius = 66; // Leaves 14px outer margin in 160x160 viewBox
  const strokeWidth = Math.max(8, Math.round(size * 0.065));
  const circumference = 2 * Math.PI * radius; // ~414.69

  // Deterministic arc offset: instantly reflects actual score prop
  const arcTarget = clamped === 0 ? 2.5 : clamped;
  const strokeDashoffset = circumference - (arcTarget / 100) * circumference;
  const isCompact = size < 150;

  return (
    <div
      className={cn("flex flex-col items-center justify-center select-none motion-scale-in", className)}
      role="img"
      aria-label={`${label}: ${clamped} out of 100, Grade ${grade ?? "N/A"}`}
    >
      <div
        style={{ width: size, height: size, minWidth: size, minHeight: size }}
        className="relative shrink-0 flex items-center justify-center"
      >
        <svg
          className="size-full -rotate-90"
          viewBox="0 0 160 160"
          aria-hidden="true"
        >
          {/* Background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            className="stroke-rule/30 fill-none"
            strokeWidth={strokeWidth}
          />
          {/* Animated progress arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{
              filter: clamped < 40 ? "drop-shadow(0 0 8px rgba(239,68,68,0.45))" : undefined,
            }}
          />
        </svg>

        {/* Centered content with generous breathing room */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center px-3">
          <div className="flex items-baseline justify-center">
            <span
              className={cn(
                "font-black font-mono tracking-tight tabular-nums leading-none transition-colors duration-300",
                isCompact ? "text-2xl" : "text-3xl sm:text-4xl"
              )}
              style={{
                color,
                textShadow: clamped < 40 ? "0 0 14px rgba(239,68,68,0.3)" : undefined,
              }}
            >
              {Math.round(clamped)}
            </span>
            <span className="ml-1 font-mono text-[11px] font-semibold text-muted leading-none">
              /100
            </span>
          </div>

          {grade && (
            <span
              className={cn(
                "mt-1.5 inline-flex items-center justify-center rounded-full font-mono font-bold uppercase tracking-wider shadow-sm transition-all duration-300",
                isCompact ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-0.5 text-xs"
              )}
              style={{
                color,
                backgroundColor: `${color}18`,
                border: `1px solid ${color}45`,
              }}
            >
              Grade {grade}
            </span>
          )}
        </div>
      </div>

      {label ? (
        <p className="mt-2 text-xs text-muted font-medium text-center">
          {label}
        </p>
      ) : null}
    </div>
  );
};

export default ScoreGauge;
