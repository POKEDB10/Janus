/**
 * components/RiskBadge.tsx
 * Reusable coloured badge for IPsec risk severity levels.
 */
import React from "react";
import { clsx } from "clsx";
import type { RiskLevel } from "../types";

interface RiskBadgeProps {
  level: RiskLevel;
  size?: "sm" | "md" | "lg";
}

const levelConfig: Record<RiskLevel, { label: string; classes: string }> = {
  CRITICAL: {
    label: "CRITICAL",
    classes: "bg-red-500/20 text-red-400 border border-red-500/40 shadow-sm shadow-red-500/10",
  },
  HIGH: {
    label: "HIGH",
    classes: "bg-orange-500/20 text-orange-400 border border-orange-500/40 shadow-sm shadow-orange-500/10",
  },
  MEDIUM: {
    label: "MEDIUM",
    classes: "bg-amber-500/20 text-amber-400 border border-amber-500/40 shadow-sm shadow-amber-500/10",
  },
  LOW: {
    label: "LOW",
    classes: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm shadow-emerald-500/10",
  },
  INFO: {
    label: "INFO",
    classes: "bg-blue-500/20 text-blue-300 border border-blue-500/40 shadow-sm shadow-blue-500/10",
  },
};

const sizeClasses: Record<NonNullable<RiskBadgeProps["size"]>, string> = {
  sm: "text-[10px] px-1.5 py-0.5 rounded",
  md: "text-xs px-2 py-0.5 rounded-md",
  lg: "text-sm px-3 py-1 rounded-lg font-semibold",
};

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = "md" }) => {
  const config = levelConfig[level] || levelConfig.INFO;
  return (
    <span
      role="status"
      aria-label={`Risk level: ${config.label}`}
      className={clsx("inline-flex items-center font-mono font-semibold tracking-wide uppercase", config.classes, sizeClasses[size])}
    >
      {config.label}
    </span>
  );
};

export default RiskBadge;
