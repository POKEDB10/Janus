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
    classes: "bg-risk-critical/20 text-risk-critical border border-risk-critical/50",
  },
  HIGH: {
    label: "HIGH",
    classes: "bg-risk-high/20 text-risk-high border border-risk-high/50",
  },
  MEDIUM: {
    label: "MEDIUM",
    classes: "bg-risk-medium/20 text-risk-medium border border-risk-medium/50",
  },
  LOW: {
    label: "LOW",
    classes: "bg-risk-low/20 text-risk-low border border-risk-low/50",
  },
  INFO: {
    label: "INFO",
    classes: "bg-blue-900/40 text-blue-300 border border-blue-500/40",
  },
};

const sizeClasses: Record<NonNullable<RiskBadgeProps["size"]>, string> = {
  sm: "text-xs px-1.5 py-0.5 rounded",
  md: "text-xs px-2 py-1 rounded-md",
  lg: "text-sm px-3 py-1.5 rounded-lg font-semibold",
};

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = "md" }) => {
  const { label, classes } = levelConfig[level];
  return (
    <span
      role="status"
      aria-label={`Risk level: ${label}`}
      className={clsx("inline-flex items-center font-mono font-semibold tracking-wide", classes, sizeClasses[size])}
    >
      {label}
    </span>
  );
};

export default RiskBadge;
